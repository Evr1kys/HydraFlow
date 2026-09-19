package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEntry records security-sensitive Agent actions without storing secrets.
type AuditEntry struct {
	Timestamp  time.Time      `json:"timestamp"`
	RequestID  string         `json:"request_id"`
	ActorKeyID string         `json:"actor_key_id"`
	RemoteAddr string         `json:"remote_addr"`
	Action     string         `json:"action"`
	Success    bool           `json:"success"`
	StatusCode int            `json:"status_code"`
	Revision   string         `json:"revision,omitempty"`
	ErrorCode  string         `json:"error_code,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// AuditLogger writes one JSON object per line to a root-owned file.
type AuditLogger struct {
	mu   sync.Mutex
	file *os.File
}

func NewAuditLogger(path string) (*AuditLogger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure audit log: %w", err)
	}
	return &AuditLogger{file: file}, nil
}

func (l *AuditLogger) Write(entry AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry.Timestamp = entry.Timestamp.UTC()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := l.file.Write(data); err != nil {
		return err
	}
	return l.file.Sync()
}

func (l *AuditLogger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}
