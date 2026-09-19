package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	headerKeyID     = "X-Hydra-Key-Id"
	headerTimestamp = "X-Hydra-Timestamp"
	headerNonce     = "X-Hydra-Nonce"
	headerSignature = "X-Hydra-Signature"
	headerRequestID = "X-Request-Id"
)

type contextKey string

const (
	principalContextKey contextKey = "agent-principal"
	bodyHashContextKey  contextKey = "agent-body-hash"
	requestIDContextKey contextKey = "agent-request-id"
)

// Principal is the authenticated Agent API caller.
type Principal struct {
	KeyID string
}

func principalFromContext(ctx context.Context) Principal {
	principal, _ := ctx.Value(principalContextKey).(Principal)
	return principal
}

func bodyHashFromContext(ctx context.Context) string {
	hash, _ := ctx.Value(bodyHashContextKey).(string)
	return hash
}

func requestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey).(string)
	return requestID
}

// Authenticator validates HMAC-signed requests and rejects nonce reuse.
type Authenticator struct {
	keys        *KeyStore
	window      time.Duration
	maxBody     int64
	mu          sync.Mutex
	seenNonces  map[string]time.Time
	lastCleanup time.Time
}

func NewAuthenticator(keys *KeyStore, window time.Duration, maxBody int64) *Authenticator {
	if window <= 0 {
		window = 5 * time.Minute
	}
	if maxBody <= 0 {
		maxBody = 2 << 20
	}
	return &Authenticator{
		keys:       keys,
		window:     window,
		maxBody:    maxBody,
		seenNonces: make(map[string]time.Time),
	}
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(headerRequestID)
		if !validOpaqueToken(requestID, 8, 128) {
			requestID = randomRequestID()
		}
		w.Header().Set(headerRequestID, requestID)
		ctx := context.WithValue(r.Context(), requestIDContextKey, requestID)

		if r.Body == nil {
			r.Body = http.NoBody
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, a.maxBody))
		if err != nil {
			writeAPIError(w, requestID, apiError(http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds configured limit", err))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		bodyDigest := sha256.Sum256(body)
		bodyHash := hex.EncodeToString(bodyDigest[:])

		keyID := r.Header.Get(headerKeyID)
		timestampRaw := r.Header.Get(headerTimestamp)
		nonce := r.Header.Get(headerNonce)
		signatureRaw := strings.TrimPrefix(r.Header.Get(headerSignature), "v1=")
		if !keyIDPattern.MatchString(keyID) || !validOpaqueToken(nonce, 16, 128) || timestampRaw == "" || signatureRaw == "" {
			writeAPIError(w, requestID, apiError(http.StatusUnauthorized, "invalid_auth_headers", "missing or invalid signed request headers", nil))
			return
		}

		timestamp, err := strconv.ParseInt(timestampRaw, 10, 64)
		if err != nil {
			writeAPIError(w, requestID, apiError(http.StatusUnauthorized, "invalid_timestamp", "invalid request timestamp", err))
			return
		}
		requestTime := time.Unix(timestamp, 0)
		now := time.Now()
		if requestTime.Before(now.Add(-a.window)) || requestTime.After(now.Add(a.window)) {
			writeAPIError(w, requestID, apiError(http.StatusUnauthorized, "stale_request", "request timestamp is outside the accepted window", nil))
			return
		}

		secret, ok := a.keys.Secret(keyID)
		if !ok {
			writeAPIError(w, requestID, apiError(http.StatusUnauthorized, "unknown_key", "unknown or expired key id", nil))
			return
		}
		signature, err := hex.DecodeString(signatureRaw)
		if err != nil || len(signature) != sha256.Size {
			writeAPIError(w, requestID, apiError(http.StatusUnauthorized, "invalid_signature", "invalid request signature", err))
			return
		}
		canonical := canonicalRequest(r.Method, r.URL.EscapedPath(), r.URL.RawQuery, timestampRaw, nonce, bodyHash)
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(canonical))
		if !secureEqual(mac.Sum(nil), signature) {
			writeAPIError(w, requestID, apiError(http.StatusUnauthorized, "invalid_signature", "invalid request signature", nil))
			return
		}
		if !a.consumeNonce(keyID, nonce, requestTime.Add(a.window)) {
			writeAPIError(w, requestID, apiError(http.StatusConflict, "replay_detected", "request nonce has already been used", nil))
			return
		}

		ctx = context.WithValue(ctx, principalContextKey, Principal{KeyID: keyID})
		ctx = context.WithValue(ctx, bodyHashContextKey, bodyHash)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func canonicalRequest(method, escapedPath, rawQuery, timestamp, nonce, bodyHash string) string {
	return strings.Join([]string{
		strings.ToUpper(method),
		escapedPath,
		rawQuery,
		timestamp,
		nonce,
		bodyHash,
	}, "\n")
}

func (a *Authenticator) consumeNonce(keyID, nonce string, expiresAt time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if a.lastCleanup.IsZero() || now.Sub(a.lastCleanup) > time.Minute {
		for key, expiry := range a.seenNonces {
			if !expiry.After(now) {
				delete(a.seenNonces, key)
			}
		}
		a.lastCleanup = now
	}
	key := keyID + ":" + nonce
	if expiry, exists := a.seenNonces[key]; exists && expiry.After(now) {
		return false
	}
	a.seenNonces[key] = expiresAt
	return true
}

func validOpaqueToken(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
}

func randomRequestID() string {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err == nil {
		return hex.EncodeToString(value)
	}
	digest := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	return hex.EncodeToString(digest[:12])
}
