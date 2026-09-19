package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

type fakeController struct {
	mu           sync.Mutex
	active       bool
	restarts     int
	failNext     bool
	validateFail bool
}

func (f *fakeController) Validate(_ context.Context, configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	if f.validateFail || !json.Valid(data) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (f *fakeController) Restart(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restarts++
	if f.failNext {
		f.failNext = false
		f.active = false
		return io.ErrClosedPipe
	}
	f.active = true
	return nil
}

func (f *fakeController) Status(_ context.Context) (ProcessStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ProcessStatus{Active: f.active, PID: 42, Version: "Xray test", CheckedAt: time.Now().UTC()}, nil
}

func (f *fakeController) restartCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.restarts
}

func newTestServer(t *testing.T, controller *fakeController, initial []byte) (*Server, string, []byte, string) {
	t.Helper()
	dir := t.TempDir()
	keyID := "test-key-001"
	secret := bytes.Repeat([]byte{0x42}, 32)
	keyPath := filepath.Join(dir, "agent", "keys.json")
	if err := writeKeyFileAtomic(keyPath, keyFile{Active: keyRecord{
		ID:     keyID,
		Secret: base64.RawStdEncoding.EncodeToString(secret),
	}}); err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(dir, "xray", "config.json")
	if initial != nil {
		if err := atomicWriteFile(currentPath, initial, 0600); err != nil {
			t.Fatal(err)
		}
	}
	controller.active = true
	server, err := NewServer(ServerConfig{
		KeyFile:        keyPath,
		XrayConfig:     currentPath,
		StateDir:       filepath.Join(dir, "state"),
		AuditLog:       filepath.Join(dir, "log", "audit.jsonl"),
		Version:        "test",
		BuildTime:      "test",
		ReplayWindow:   time.Minute,
		MaxBodyBytes:   1 << 20,
		IdempotencyTTL: time.Hour,
	}, controller, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, keyID, secret, currentPath
}

func TestReplayProtection(t *testing.T) {
	server, keyID, secret, _ := newTestServer(t, &fakeController{}, []byte(`{"inbounds":[],"outbounds":[]}`))
	request := signedRequest(t, http.MethodGet, "/api/v1/health", nil, keyID, secret, "nonce-replay-0001", "")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("first request status=%d body=%s", response.Code, response.Body.String())
	}

	replayed := signedRequest(t, http.MethodGet, "/api/v1/health", nil, keyID, secret, "nonce-replay-0001", "")
	replayResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayResponse, replayed)
	if replayResponse.Code != http.StatusConflict {
		t.Fatalf("replay status=%d body=%s", replayResponse.Code, replayResponse.Body.String())
	}
}

func TestApplyIsIdempotentAndFailedRestartRollsBack(t *testing.T) {
	controller := &fakeController{}
	initial := []byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[]}`)
	server, keyID, secret, currentPath := newTestServer(t, controller, initial)
	candidate := []byte(`{"log":{"loglevel":"error"},"inbounds":[],"outbounds":[]}`)
	body := mustJSON(t, map[string]any{"config": json.RawMessage(candidate), "reason": "test apply"})

	request := signedRequest(t, http.MethodPost, "/api/v1/config/apply", body, keyID, secret, "nonce-apply-00001", "idem-apply-00000001")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", response.Code, response.Body.String())
	}
	if controller.restartCount() != 1 {
		t.Fatalf("restart count=%d", controller.restartCount())
	}

	retry := signedRequest(t, http.MethodPost, "/api/v1/config/apply", body, keyID, secret, "nonce-apply-00002", "idem-apply-00000001")
	retryResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(retryResponse, retry)
	if retryResponse.Code != http.StatusOK || retryResponse.Header().Get("X-Idempotent-Replay") != "true" {
		t.Fatalf("retry status=%d replay=%q body=%s", retryResponse.Code, retryResponse.Header().Get("X-Idempotent-Replay"), retryResponse.Body.String())
	}
	if controller.restartCount() != 1 {
		t.Fatalf("idempotent retry restarted Xray: count=%d", controller.restartCount())
	}

	controller.mu.Lock()
	controller.failNext = true
	controller.mu.Unlock()
	brokenCandidate := []byte(`{"log":{"loglevel":"debug"},"inbounds":[],"outbounds":[]}`)
	brokenBody := mustJSON(t, map[string]any{"config": json.RawMessage(brokenCandidate), "reason": "must roll back"})
	broken := signedRequest(t, http.MethodPost, "/api/v1/config/apply", brokenBody, keyID, secret, "nonce-apply-00003", "idem-apply-00000002")
	brokenResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(brokenResponse, broken)
	if brokenResponse.Code != http.StatusBadGateway {
		t.Fatalf("failed apply status=%d body=%s", brokenResponse.Code, brokenResponse.Body.String())
	}
	current, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, candidate) {
		t.Fatalf("rollback did not restore previous config: %s", current)
	}
}

func TestKeyRotationAcceptsNewKeyAndGraceKey(t *testing.T) {
	server, keyID, secret, _ := newTestServer(t, &fakeController{}, []byte(`{"inbounds":[],"outbounds":[]}`))
	newSecret := bytes.Repeat([]byte{0x77}, 32)
	body := mustJSON(t, map[string]any{
		"key_id":        "test-key-002",
		"secret":        base64.RawStdEncoding.EncodeToString(newSecret),
		"grace_seconds": 60,
	})
	request := signedRequest(t, http.MethodPost, "/api/v1/auth/rotate", body, keyID, secret, "nonce-rotate-0001", "idem-rotate-0000001")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", response.Code, response.Body.String())
	}

	newRequest := signedRequest(t, http.MethodGet, "/api/v1/auth/key", nil, "test-key-002", newSecret, "nonce-new-key-001", "")
	newResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(newResponse, newRequest)
	if newResponse.Code != http.StatusOK {
		t.Fatalf("new key rejected: %d %s", newResponse.Code, newResponse.Body.String())
	}
	oldRequest := signedRequest(t, http.MethodGet, "/api/v1/auth/key", nil, keyID, secret, "nonce-old-key-001", "")
	oldResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(oldResponse, oldRequest)
	if oldResponse.Code != http.StatusOK {
		t.Fatalf("grace key rejected: %d %s", oldResponse.Code, oldResponse.Body.String())
	}
}

func signedRequest(t *testing.T, method, target string, body []byte, keyID string, secret []byte, nonce, idempotencyKey string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	digest := sha256.Sum256(body)
	canonical := canonicalRequest(method, request.URL.EscapedPath(), request.URL.RawQuery, timestamp, nonce, hex.EncodeToString(digest[:]))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	request.Header.Set(headerKeyID, keyID)
	request.Header.Set(headerTimestamp, timestamp)
	request.Header.Set(headerNonce, nonce)
	request.Header.Set(headerSignature, "v1="+hex.EncodeToString(mac.Sum(nil)))
	if idempotencyKey != "" {
		request.Header.Set(idempotencyHeader, idempotencyKey)
	}
	return request
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
