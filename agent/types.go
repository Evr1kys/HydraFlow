package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const APIVersion = "v1"

// APIError is the stable error envelope returned by the Agent API.
type APIError struct {
	Status  int            `json:"-"`
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
	Cause   error          `json:"-"`
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *APIError) Unwrap() error { return e.Cause }

func apiError(status int, code, message string, cause error) *APIError {
	return &APIError{Status: status, Code: code, Message: message, Cause: cause}
}

func asAPIError(err error) *APIError {
	if err == nil {
		return nil
	}
	var target *APIError
	if errors.As(err, &target) {
		return target
	}
	return apiError(http.StatusInternalServerError, "internal_error", "internal server error", err)
}

type errorEnvelope struct {
	Error struct {
		Code      string         `json:"code"`
		Message   string         `json:"message"`
		RequestID string         `json:"request_id"`
		Details   map[string]any `json:"details,omitempty"`
	} `json:"error"`
}

func writeAPIError(w http.ResponseWriter, requestID string, err error) {
	apiErr := asAPIError(err)
	if apiErr.Status == 0 {
		apiErr.Status = http.StatusInternalServerError
	}
	var envelope errorEnvelope
	envelope.Error.Code = apiErr.Code
	envelope.Error.Message = apiErr.Message
	envelope.Error.RequestID = requestID
	envelope.Error.Details = apiErr.Details
	writeJSON(w, apiErr.Status, envelope)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// Revision describes one immutable Xray configuration revision.
type Revision struct {
	ID             string    `json:"id"`
	Hash           string    `json:"hash"`
	Size           int64     `json:"size"`
	CreatedAt      time.Time `json:"created_at"`
	Reason         string    `json:"reason,omitempty"`
	ActorKeyID     string    `json:"actor_key_id,omitempty"`
	State          string    `json:"state"`
	RolledBackFrom string    `json:"rolled_back_from,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// ProcessStatus is a minimal, transport-safe view of the managed Xray service.
type ProcessStatus struct {
	Active    bool      `json:"active"`
	PID       int       `json:"pid,omitempty"`
	Version   string    `json:"version,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// CurrentConfig contains the active metadata and raw Xray JSON.
type CurrentConfig struct {
	Revision *Revision       `json:"revision,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
}

// ValidationResult is returned after the real Xray binary accepts a candidate.
type ValidationResult struct {
	Valid bool   `json:"valid"`
	Hash  string `json:"hash"`
	Size  int64  `json:"size"`
}
