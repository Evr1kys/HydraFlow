package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxConfigBytes = 4 << 20

// ConfigStore serializes all Xray configuration changes and maintains an
// immutable revision history suitable for deterministic rollback.
type ConfigStore struct {
	mu              sync.Mutex
	currentPath     string
	stateDir        string
	historyDir      string
	currentMetaPath string
	maxHistory      int
	controller      Controller
}

func NewConfigStore(currentPath, stateDir string, maxHistory int, controller Controller) *ConfigStore {
	if maxHistory <= 0 {
		maxHistory = 20
	}
	return &ConfigStore{
		currentPath:     currentPath,
		stateDir:        stateDir,
		historyDir:      filepath.Join(stateDir, "configs"),
		currentMetaPath: filepath.Join(stateDir, "current.json"),
		maxHistory:      maxHistory,
		controller:      controller,
	}
}

func (s *ConfigStore) Ensure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.currentPath), 0750); err != nil {
		return fmt.Errorf("create Xray config directory: %w", err)
	}
	if err := os.MkdirAll(s.historyDir, 0700); err != nil {
		return fmt.Errorf("create config history directory: %w", err)
	}
	if err := os.Chmod(s.historyDir, 0700); err != nil {
		return fmt.Errorf("secure config history directory: %w", err)
	}
	_, _, err := s.ensureCurrentSnapshotLocked()
	return err
}

func (s *ConfigStore) Validate(ctx context.Context, config []byte) (ValidationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.validateLocked(ctx, config)
}

func (s *ConfigStore) Apply(ctx context.Context, config []byte, reason, actor string) (Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyLocked(ctx, config, reason, actor, "")
}

func (s *ConfigStore) Rollback(ctx context.Context, revisionID, reason, actor string) (Revision, error) {
	if !validRevisionID(revisionID) {
		return Revision{}, apiError(400, "invalid_revision", "invalid revision id", nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	config, err := readFileLimit(s.revisionConfigPath(revisionID), maxConfigBytes)
	if errors.Is(err, os.ErrNotExist) {
		return Revision{}, apiError(404, "revision_not_found", "configuration revision not found", nil)
	}
	if err != nil {
		return Revision{}, fmt.Errorf("read rollback revision: %w", err)
	}
	if reason == "" {
		reason = "rollback to " + revisionID
	}
	return s.applyLocked(ctx, config, reason, actor, revisionID)
}

func (s *ConfigStore) Restart(ctx context.Context) (ProcessStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.controller.Restart(ctx); err != nil {
		return ProcessStatus{}, apiError(502, "xray_restart_failed", "failed to restart Xray", err)
	}
	return s.waitActiveLocked(ctx)
}

func (s *ConfigStore) Status(ctx context.Context) (ProcessStatus, error) {
	return s.controller.Status(ctx)
}

func (s *ConfigStore) Current() (CurrentConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	config, err := readFileLimit(s.currentPath, maxConfigBytes)
	if errors.Is(err, os.ErrNotExist) {
		return CurrentConfig{}, nil
	}
	if err != nil {
		return CurrentConfig{}, fmt.Errorf("read current config: %w", err)
	}
	revision, err := s.readCurrentMetaLocked()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return CurrentConfig{}, err
	}
	return CurrentConfig{Revision: revision, Config: json.RawMessage(config)}, nil
}

func (s *ConfigStore) History() ([]Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.historyDir)
	if err != nil {
		return nil, err
	}
	result := make([]Revision, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".meta.json") {
			continue
		}
		data, err := readFileLimit(filepath.Join(s.historyDir, entry.Name()), 1<<20)
		if err != nil {
			return nil, err
		}
		var revision Revision
		if err := json.Unmarshal(data, &revision); err != nil {
			return nil, fmt.Errorf("parse revision metadata %s: %w", entry.Name(), err)
		}
		result = append(result, revision)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

func (s *ConfigStore) applyLocked(ctx context.Context, config []byte, reason, actor, rolledBackFrom string) (Revision, error) {
	validation, err := s.validateLocked(ctx, config)
	if err != nil {
		return Revision{}, err
	}
	if reason == "" {
		reason = "configuration apply"
	}

	oldConfig, oldRevision, err := s.ensureCurrentSnapshotLocked()
	if err != nil {
		return Revision{}, err
	}

	revision := Revision{
		ID:             newRevisionID(validation.Hash),
		Hash:           validation.Hash,
		Size:           validation.Size,
		CreatedAt:      time.Now().UTC(),
		Reason:         reason,
		ActorKeyID:     actor,
		State:          "pending",
		RolledBackFrom: rolledBackFrom,
	}
	if err := s.writeRevisionLocked(revision, config); err != nil {
		return Revision{}, fmt.Errorf("store candidate revision: %w", err)
	}
	if err := atomicWriteFile(s.currentPath, config, 0640); err != nil {
		revision.State = "failed"
		revision.Error = err.Error()
		_ = s.writeRevisionMetaLocked(revision)
		return Revision{}, fmt.Errorf("replace Xray config: %w", err)
	}

	restartErr := s.controller.Restart(ctx)
	var status ProcessStatus
	if restartErr == nil {
		status, restartErr = s.waitActiveLocked(ctx)
		if restartErr == nil && !status.Active {
			restartErr = fmt.Errorf("Xray service is not active after restart")
		}
	}
	if restartErr != nil {
		rollbackErr := s.restorePreviousLocked(ctx, oldConfig, oldRevision)
		revision.State = "failed"
		revision.Error = restartErr.Error()
		_ = s.writeRevisionMetaLocked(revision)
		details := map[string]any{"rollback_succeeded": rollbackErr == nil}
		if rollbackErr != nil {
			details["rollback_error"] = rollbackErr.Error()
		}
		apiErr := apiError(502, "apply_failed", "Xray rejected the applied configuration; previous state was restored", restartErr)
		apiErr.Details = details
		return revision, apiErr
	}

	if oldRevision != nil && oldRevision.ID != revision.ID {
		oldRevision.State = "historical"
		_ = s.writeRevisionMetaLocked(*oldRevision)
	}
	revision.State = "active"
	if err := s.writeRevisionMetaLocked(revision); err != nil {
		return Revision{}, err
	}
	if err := atomicWriteJSON(s.currentMetaPath, revision, 0600); err != nil {
		return Revision{}, fmt.Errorf("write current revision metadata: %w", err)
	}
	_ = s.pruneLocked(revision.ID)
	return revision, nil
}

func (s *ConfigStore) validateLocked(ctx context.Context, config []byte) (ValidationResult, error) {
	if len(config) == 0 {
		return ValidationResult{}, apiError(400, "empty_config", "configuration is empty", nil)
	}
	if len(config) > maxConfigBytes {
		return ValidationResult{}, apiError(413, "config_too_large", "configuration exceeds 4 MiB", nil)
	}
	var root map[string]any
	if err := json.Unmarshal(config, &root); err != nil {
		return ValidationResult{}, apiError(400, "invalid_json", "configuration is not valid JSON", err)
	}
	if root == nil {
		return ValidationResult{}, apiError(400, "invalid_config", "configuration root must be an object", nil)
	}
	if err := os.MkdirAll(filepath.Dir(s.currentPath), 0750); err != nil {
		return ValidationResult{}, err
	}
	candidate, err := os.CreateTemp(filepath.Dir(s.currentPath), ".agent-candidate-*.json")
	if err != nil {
		return ValidationResult{}, err
	}
	candidatePath := candidate.Name()
	defer os.Remove(candidatePath)
	if err := candidate.Chmod(0600); err != nil {
		_ = candidate.Close()
		return ValidationResult{}, err
	}
	if _, err := candidate.Write(config); err != nil {
		_ = candidate.Close()
		return ValidationResult{}, err
	}
	if err := candidate.Sync(); err != nil {
		_ = candidate.Close()
		return ValidationResult{}, err
	}
	if err := candidate.Close(); err != nil {
		return ValidationResult{}, err
	}
	if err := s.controller.Validate(ctx, candidatePath); err != nil {
		return ValidationResult{}, apiError(422, "xray_validation_failed", "Xray rejected the candidate configuration", err)
	}
	digest := sha256.Sum256(config)
	return ValidationResult{
		Valid: true,
		Hash:  hex.EncodeToString(digest[:]),
		Size:  int64(len(config)),
	}, nil
}

func (s *ConfigStore) ensureCurrentSnapshotLocked() ([]byte, *Revision, error) {
	config, err := readFileLimit(s.currentPath, maxConfigBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read existing Xray config: %w", err)
	}
	digest := sha256.Sum256(config)
	hash := hex.EncodeToString(digest[:])
	current, metaErr := s.readCurrentMetaLocked()
	if metaErr == nil && current != nil && current.Hash == hash {
		if _, err := os.Stat(s.revisionConfigPath(current.ID)); err == nil {
			return config, current, nil
		}
	}

	revision := Revision{
		ID:        newRevisionID(hash),
		Hash:      hash,
		Size:      int64(len(config)),
		CreatedAt: time.Now().UTC(),
		Reason:    "import existing configuration",
		State:     "active",
	}
	if err := s.writeRevisionLocked(revision, config); err != nil {
		return nil, nil, err
	}
	if err := atomicWriteJSON(s.currentMetaPath, revision, 0600); err != nil {
		return nil, nil, err
	}
	return config, &revision, nil
}

func (s *ConfigStore) restorePreviousLocked(ctx context.Context, oldConfig []byte, oldRevision *Revision) error {
	if oldConfig == nil {
		if err := os.Remove(s.currentPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		_ = os.Remove(s.currentMetaPath)
		return nil
	}
	if err := atomicWriteFile(s.currentPath, oldConfig, 0640); err != nil {
		return err
	}
	if oldRevision != nil {
		oldRevision.State = "active"
		if err := s.writeRevisionMetaLocked(*oldRevision); err != nil {
			return err
		}
		if err := atomicWriteJSON(s.currentMetaPath, *oldRevision, 0600); err != nil {
			return err
		}
	}
	if err := s.controller.Restart(ctx); err != nil {
		return fmt.Errorf("restart restored configuration: %w", err)
	}
	_, err := s.waitActiveLocked(ctx)
	return err
}

func (s *ConfigStore) waitActiveLocked(ctx context.Context) (ProcessStatus, error) {
	deadline := time.Now().Add(10 * time.Second)
	var last ProcessStatus
	var lastErr error
	for {
		last, lastErr = s.controller.Status(ctx)
		if lastErr == nil && last.Active {
			return last, nil
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return last, lastErr
			}
			return last, fmt.Errorf("Xray did not become active before timeout")
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (s *ConfigStore) readCurrentMetaLocked() (*Revision, error) {
	data, err := readFileLimit(s.currentMetaPath, 1<<20)
	if err != nil {
		return nil, err
	}
	var revision Revision
	if err := json.Unmarshal(data, &revision); err != nil {
		return nil, fmt.Errorf("parse current revision metadata: %w", err)
	}
	return &revision, nil
}

func (s *ConfigStore) writeRevisionLocked(revision Revision, config []byte) error {
	if err := atomicWriteFile(s.revisionConfigPath(revision.ID), config, 0600); err != nil {
		return err
	}
	return s.writeRevisionMetaLocked(revision)
}

func (s *ConfigStore) writeRevisionMetaLocked(revision Revision) error {
	return atomicWriteJSON(s.revisionMetaPath(revision.ID), revision, 0600)
}

func (s *ConfigStore) revisionConfigPath(id string) string {
	return filepath.Join(s.historyDir, id+".json")
}

func (s *ConfigStore) revisionMetaPath(id string) string {
	return filepath.Join(s.historyDir, id+".meta.json")
}

func (s *ConfigStore) pruneLocked(activeID string) error {
	entries, err := os.ReadDir(s.historyDir)
	if err != nil {
		return err
	}
	type candidate struct {
		id      string
		modTime time.Time
	}
	candidates := make([]candidate, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".meta.json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".meta.json")
		if id == activeID {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate{id: id, modTime: info.ModTime()})
	}
	if len(candidates) <= s.maxHistory-1 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].modTime.Before(candidates[j].modTime) })
	removeCount := len(candidates) - (s.maxHistory - 1)
	for i := 0; i < removeCount; i++ {
		_ = os.Remove(s.revisionConfigPath(candidates[i].id))
		_ = os.Remove(s.revisionMetaPath(candidates[i].id))
	}
	return nil
}

func newRevisionID(hash string) string {
	prefix := hash
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + prefix
}

func validRevisionID(id string) bool {
	if len(id) < 8 || len(id) > 128 || strings.Contains(id, "..") || strings.ContainsAny(id, `/\\`) {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-", r) {
			continue
		}
		return false
	}
	return true
}

func atomicWriteJSON(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(data, '\n'), mode)
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".hydraflow-atomic-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func syncDirectory(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func readFileLimit(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file %s exceeds size limit", path)
	}
	return data, nil
}
