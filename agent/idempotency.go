package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`)

type idempotencyKeyLock struct {
	mu   sync.Mutex
	refs int
}

type cachedResponse struct {
	RequestHash string          `json:"request_hash"`
	Status      int             `json:"status"`
	Body        json.RawMessage `json:"body"`
	CreatedAt   time.Time       `json:"created_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
}

// IdempotencyStore persists successful mutation responses across restarts.
type IdempotencyStore struct {
	mu  sync.Mutex
	dir string
	ttl time.Duration
	now func() time.Time

	locksMu sync.Mutex
	locks   map[string]*idempotencyKeyLock
}

func NewIdempotencyStore(dir string, ttl time.Duration) (*IdempotencyStore, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create idempotency directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("secure idempotency directory: %w", err)
	}
	store := &IdempotencyStore{
		dir:   dir,
		ttl:   ttl,
		now:   time.Now,
		locks: make(map[string]*idempotencyKeyLock),
	}
	_ = store.Cleanup()
	return store, nil
}

// Acquire serializes concurrent mutations using the same idempotency key.
// The returned release function must always be called. Different keys remain
// independent, so an unrelated deployment cannot block this request.
func (s *IdempotencyStore) Acquire(key string) (func(), error) {
	if !idempotencyKeyPattern.MatchString(key) {
		return nil, apiError(400, "invalid_idempotency_key", "Idempotency-Key must contain 16-128 safe characters", nil)
	}

	s.locksMu.Lock()
	lock := s.locks[key]
	if lock == nil {
		lock = &idempotencyKeyLock{}
		s.locks[key] = lock
	}
	lock.refs++
	s.locksMu.Unlock()

	lock.mu.Lock()
	var once sync.Once
	return func() {
		once.Do(func() {
			lock.mu.Unlock()
			s.locksMu.Lock()
			lock.refs--
			if lock.refs == 0 && s.locks[key] == lock {
				delete(s.locks, key)
			}
			s.locksMu.Unlock()
		})
	}, nil
}

// Get returns a cached response. conflict is true when the same idempotency key
// was reused with a different request body.
func (s *IdempotencyStore) Get(key, requestHash string) (response cachedResponse, found, conflict bool, err error) {
	if !idempotencyKeyPattern.MatchString(key) {
		return response, false, false, apiError(400, "invalid_idempotency_key", "Idempotency-Key must contain 16-128 safe characters", nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return response, false, false, nil
	}
	if err != nil {
		return response, false, false, err
	}
	if len(data) > 1<<20 {
		_ = os.Remove(s.path(key))
		return response, false, false, fmt.Errorf("idempotency entry exceeds size limit")
	}
	if err := json.Unmarshal(data, &response); err != nil {
		_ = os.Remove(s.path(key))
		return response, false, false, fmt.Errorf("parse idempotency entry: %w", err)
	}
	if !response.ExpiresAt.After(s.now()) {
		_ = os.Remove(s.path(key))
		return response, false, false, nil
	}
	if response.RequestHash != requestHash {
		return response, false, true, nil
	}
	return response, true, false, nil
}

func (s *IdempotencyStore) Put(key, requestHash string, status int, body []byte) error {
	if !idempotencyKeyPattern.MatchString(key) {
		return apiError(400, "invalid_idempotency_key", "Idempotency-Key must contain 16-128 safe characters", nil)
	}
	now := s.now().UTC()
	entry := cachedResponse{
		RequestHash: requestHash,
		Status:      status,
		Body:        append(json.RawMessage(nil), body...),
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.ttl),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteFile(s.path(key), data, 0600)
}

func (s *IdempotencyStore) Cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	now := s.now()
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		var cached cachedResponse
		if json.Unmarshal(data, &cached) != nil || !cached.ExpiresAt.After(now) {
			_ = os.Remove(path)
		}
	}
	return nil
}

func (s *IdempotencyStore) path(key string) string {
	digest := sha256.Sum256([]byte(key))
	return filepath.Join(s.dir, hex.EncodeToString(digest[:])+".json")
}
