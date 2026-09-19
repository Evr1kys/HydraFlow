package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Evr1kys/HydraFlow/xray"
)

const idempotencyHeader = "Idempotency-Key"

// ServerConfig controls the hardened Agent API server.
type ServerConfig struct {
	ListenAddress  string
	TLSCertFile    string
	TLSKeyFile     string
	ClientCAFile   string
	KeyFile        string
	XrayConfig     string
	StateDir       string
	AuditLog       string
	StatsAddress   string
	Version        string
	BuildTime      string
	MaxBodyBytes   int64
	MaxHistory     int
	ReplayWindow   time.Duration
	IdempotencyTTL time.Duration
}

// Server exposes authenticated configuration management for one Xray node.
type Server struct {
	config  ServerConfig
	logger  *slog.Logger
	keys    *KeyStore
	auth    *Authenticator
	store   *ConfigStore
	idem    *IdempotencyStore
	audit   *AuditLogger
	stats   *xray.StatsClient
	started time.Time
	handler http.Handler
}

func NewServer(config ServerConfig, controller Controller, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if config.ListenAddress == "" {
		config.ListenAddress = "0.0.0.0:8443"
	}
	if config.XrayConfig == "" {
		config.XrayConfig = "/etc/hydraflow/xray-config.json"
	}
	if config.StateDir == "" {
		config.StateDir = "/var/lib/hydraflow-agent"
	}
	if config.AuditLog == "" {
		config.AuditLog = "/var/log/hydraflow/agent-audit.jsonl"
	}
	if config.KeyFile == "" {
		config.KeyFile = "/etc/hydraflow/agent/keys.json"
	}
	if config.StatsAddress == "" {
		config.StatsAddress = "127.0.0.1:10085"
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 2 << 20
	}
	if controller == nil {
		return nil, fmt.Errorf("agent controller is required")
	}

	keys, err := LoadKeyStore(config.KeyFile)
	if err != nil {
		return nil, err
	}
	audit, err := NewAuditLogger(config.AuditLog)
	if err != nil {
		return nil, err
	}
	idem, err := NewIdempotencyStore(filepath.Join(config.StateDir, "idempotency"), config.IdempotencyTTL)
	if err != nil {
		_ = audit.Close()
		return nil, err
	}
	store := NewConfigStore(config.XrayConfig, config.StateDir, config.MaxHistory, controller)
	if err := store.Ensure(); err != nil {
		_ = audit.Close()
		return nil, err
	}

	server := &Server{
		config:  config,
		logger:  logger,
		keys:    keys,
		auth:    NewAuthenticator(keys, config.ReplayWindow, config.MaxBodyBytes),
		store:   store,
		idem:    idem,
		audit:   audit,
		stats:   xray.NewStatsClient(config.StatsAddress, logger),
		started: time.Now().UTC(),
	}
	server.handler = server.auth.Middleware(server.routes())
	return server, nil
}

func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) Close() error { return s.audit.Close() }

func (s *Server) Serve(ctx context.Context) error {
	if s.config.TLSCertFile == "" || s.config.TLSKeyFile == "" {
		return fmt.Errorf("TLS certificate and key are required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.config.ClientCAFile != "" {
		pem, err := os.ReadFile(s.config.ClientCAFile)
		if err != nil {
			return fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("client CA file contains no valid certificates")
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	httpServer := &http.Server{
		Addr:              s.config.ListenAddress,
		Handler:           s.handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/version", s.handleVersion)
	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/config/current", s.handleCurrentConfig)
	mux.HandleFunc("/api/v1/config/history", s.handleHistory)
	mux.HandleFunc("/api/v1/config/validate", s.handleValidate)
	mux.HandleFunc("/api/v1/config/apply", s.handleApply)
	mux.HandleFunc("/api/v1/config/rollback", s.handleRollback)
	mux.HandleFunc("/api/v1/xray/restart", s.handleRestart)
	mux.HandleFunc("/api/v1/stats/users", s.handleUserStats)
	mux.HandleFunc("/api/v1/auth/key", s.handleActiveKey)
	mux.HandleFunc("/api/v1/auth/rotate", s.handleRotateKey)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Hydra-Agent-Api", APIVersion)
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	status, err := s.store.Status(r.Context())
	health := "ok"
	if err != nil || !status.Active {
		health = "degraded"
	}
	current, currentErr := s.store.Current()
	if currentErr != nil {
		health = "degraded"
	}
	response := map[string]any{
		"status":      health,
		"api_version": APIVersion,
		"version":     s.config.Version,
		"build_time":  s.config.BuildTime,
		"uptime":      time.Since(s.started).Round(time.Second).String(),
		"xray":        status,
	}
	if current.Revision != nil {
		response["revision"] = current.Revision
	}
	if err != nil {
		response["xray_error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"api_version": APIVersion,
		"version":     s.config.Version,
		"build_time":  s.config.BuildTime,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	status, err := s.store.Status(r.Context())
	if err != nil {
		writeAPIError(w, requestIDFromContext(r.Context()), apiError(502, "status_failed", "failed to query Xray status", err))
		return
	}
	current, err := s.store.Current()
	if err != nil {
		writeAPIError(w, requestIDFromContext(r.Context()), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"xray": status, "revision": current.Revision})
}

func (s *Server) handleCurrentConfig(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	current, err := s.store.Current()
	if err != nil {
		writeAPIError(w, requestIDFromContext(r.Context()), err)
		return
	}
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	history, err := s.store.History()
	if err != nil {
		writeAPIError(w, requestIDFromContext(r.Context()), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": history})
}

type configRequest struct {
	Config json.RawMessage `json:"config"`
	Reason string          `json:"reason,omitempty"`
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var request configRequest
	if err := decodeRequest(r, &request); err != nil {
		writeAPIError(w, requestIDFromContext(r.Context()), err)
		return
	}
	config, err := normalizeConfig(request.Config)
	if err != nil {
		writeAPIError(w, requestIDFromContext(r.Context()), err)
		return
	}
	result, err := s.store.Validate(r.Context(), config)
	if err != nil {
		writeAPIError(w, requestIDFromContext(r.Context()), err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	s.idempotentMutation(w, r, "config.apply", func() (int, any, string, error) {
		var request configRequest
		if err := decodeRequest(r, &request); err != nil {
			return 0, nil, "", err
		}
		config, err := normalizeConfig(request.Config)
		if err != nil {
			return 0, nil, "", err
		}
		principal := principalFromContext(r.Context())
		revision, err := s.store.Apply(r.Context(), config, request.Reason, principal.KeyID)
		return http.StatusOK, map[string]any{"revision": revision}, revision.ID, err
	})
}

type rollbackRequest struct {
	Revision string `json:"revision"`
	Reason   string `json:"reason,omitempty"`
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	s.idempotentMutation(w, r, "config.rollback", func() (int, any, string, error) {
		var request rollbackRequest
		if err := decodeRequest(r, &request); err != nil {
			return 0, nil, "", err
		}
		principal := principalFromContext(r.Context())
		revision, err := s.store.Rollback(r.Context(), request.Revision, request.Reason, principal.KeyID)
		return http.StatusOK, map[string]any{"revision": revision}, revision.ID, err
	})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	s.idempotentMutation(w, r, "xray.restart", func() (int, any, string, error) {
		status, err := s.store.Restart(r.Context())
		return http.StatusOK, map[string]any{"xray": status}, "", err
	})
}

func (s *Server) handleUserStats(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	stats, err := s.stats.GetAllUserTraffic(false)
	if err != nil {
		writeAPIError(w, requestIDFromContext(r.Context()), apiError(502, "stats_unavailable", "failed to query Xray traffic statistics", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": stats, "collected_at": time.Now().UTC()})
}

func (s *Server) handleActiveKey(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"active_key_id": s.keys.ActiveID()})
}

type rotateKeyRequest struct {
	KeyID        string `json:"key_id"`
	Secret       string `json:"secret"`
	GraceSeconds int64  `json:"grace_seconds,omitempty"`
}

func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	s.idempotentMutation(w, r, "auth.rotate", func() (int, any, string, error) {
		var request rotateKeyRequest
		if err := decodeRequest(r, &request); err != nil {
			return 0, nil, "", err
		}
		if err := s.keys.Rotate(request.KeyID, request.Secret, time.Duration(request.GraceSeconds)*time.Second); err != nil {
			return 0, nil, "", err
		}
		return http.StatusOK, map[string]any{"active_key_id": request.KeyID}, "", nil
	})
}

func (s *Server) idempotentMutation(w http.ResponseWriter, r *http.Request, action string, operation func() (status int, payload any, revision string, err error)) {
	requestID := requestIDFromContext(r.Context())
	principal := principalFromContext(r.Context())
	key := r.Header.Get(idempotencyHeader)
	requestHash := bodyHashFromContext(r.Context())
	cached, found, conflict, err := s.idem.Get(key, requestHash)
	if err != nil {
		s.writeAudit(r, action, false, 400, "", asAPIError(err).Code)
		writeAPIError(w, requestID, err)
		return
	}
	if conflict {
		err := apiError(409, "idempotency_conflict", "Idempotency-Key was already used for a different request", nil)
		s.writeAudit(r, action, false, err.Status, "", err.Code)
		writeAPIError(w, requestID, err)
		return
	}
	if found {
		w.Header().Set("X-Idempotent-Replay", "true")
		writeRawJSON(w, cached.Status, cached.Body)
		return
	}

	status, payload, revision, operationErr := operation()
	if operationErr != nil {
		apiErr := asAPIError(operationErr)
		s.writeAudit(r, action, false, apiErr.Status, revision, apiErr.Code)
		writeAPIError(w, requestID, operationErr)
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		s.writeAudit(r, action, false, 500, revision, "response_encoding_failed")
		writeAPIError(w, requestID, err)
		return
	}
	if err := s.idem.Put(key, requestHash, status, body); err != nil {
		s.logger.Error("persist idempotency response", "error", err, "request_id", requestID)
	}
	s.writeAudit(r, action, true, status, revision, "")
	w.Header().Set("X-Authenticated-Key-Id", principal.KeyID)
	writeRawJSON(w, status, body)
}

func (s *Server) writeAudit(r *http.Request, action string, success bool, status int, revision, errorCode string) {
	principal := principalFromContext(r.Context())
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remote = host
	}
	entry := AuditEntry{
		Timestamp:  time.Now().UTC(),
		RequestID:  requestIDFromContext(r.Context()),
		ActorKeyID: principal.KeyID,
		RemoteAddr: remote,
		Action:     action,
		Success:    success,
		StatusCode: status,
		Revision:   revision,
		ErrorCode:  errorCode,
	}
	if err := s.audit.Write(entry); err != nil {
		s.logger.Error("write agent audit log", "error", err, "request_id", entry.RequestID)
	}
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeAPIError(w, requestIDFromContext(r.Context()), apiError(http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", nil))
	return false
}

func decodeRequest(r *http.Request, target any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return apiError(400, "invalid_request", "request body is invalid", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return apiError(400, "invalid_request", "request body must contain one JSON object", err)
	}
	return nil
}

func normalizeConfig(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, apiError(400, "missing_config", "config is required", nil)
	}
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "\"") {
		var legacy string
		if err := json.Unmarshal(raw, &legacy); err != nil {
			return nil, apiError(400, "invalid_config", "config string is invalid", err)
		}
		return []byte(legacy), nil
	}
	return append([]byte(nil), raw...), nil
}

func writeRawJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
	_, _ = w.Write([]byte("\n"))
}
