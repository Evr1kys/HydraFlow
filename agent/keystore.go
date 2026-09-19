package agent

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

type keyRecord struct {
	ID        string     `json:"id"`
	Secret    string     `json:"secret"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type keyFile struct {
	Active   keyRecord   `json:"active"`
	Previous []keyRecord `json:"previous,omitempty"`
}

type loadedKey struct {
	secret    []byte
	expiresAt *time.Time
}

// KeyStore loads HMAC credentials from a root-owned JSON file and supports
// overlap-based rotation without exposing old secrets through the API.
type KeyStore struct {
	mu       sync.RWMutex
	path     string
	activeID string
	keys     map[string]loadedKey
}

func LoadKeyStore(path string) (*KeyStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent key file: %w", err)
	}
	var file keyFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse agent key file: %w", err)
	}
	store := &KeyStore{path: path, keys: make(map[string]loadedKey)}
	if err := store.load(file); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *KeyStore) load(file keyFile) error {
	if !keyIDPattern.MatchString(file.Active.ID) {
		return fmt.Errorf("invalid active key id")
	}
	activeSecret, err := decodeSecret(file.Active.Secret)
	if err != nil {
		return fmt.Errorf("decode active key: %w", err)
	}
	keys := map[string]loadedKey{
		file.Active.ID: {secret: activeSecret},
	}
	now := time.Now()
	for _, previous := range file.Previous {
		if !keyIDPattern.MatchString(previous.ID) || previous.ID == file.Active.ID {
			continue
		}
		if previous.ExpiresAt == nil || !previous.ExpiresAt.After(now) {
			continue
		}
		secret, err := decodeSecret(previous.Secret)
		if err != nil {
			return fmt.Errorf("decode previous key %s: %w", previous.ID, err)
		}
		expires := previous.ExpiresAt.UTC()
		keys[previous.ID] = loadedKey{secret: secret, expiresAt: &expires}
	}
	s.activeID = file.Active.ID
	s.keys = keys
	return nil
}

func decodeSecret(encoded string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.RawStdEncoding,
		base64.StdEncoding,
		base64.RawURLEncoding,
		base64.URLEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(encoded)
		if err != nil {
			lastErr = err
			continue
		}
		if len(decoded) < 32 {
			return nil, fmt.Errorf("secret must decode to at least 32 bytes")
		}
		return decoded, nil
	}
	return nil, fmt.Errorf("invalid base64 secret: %w", lastErr)
}

func (s *KeyStore) Secret(keyID string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[keyID]
	if !ok {
		return nil, false
	}
	if key.expiresAt != nil && !key.expiresAt.After(time.Now()) {
		return nil, false
	}
	copySecret := make([]byte, len(key.secret))
	copy(copySecret, key.secret)
	return copySecret, true
}

func (s *KeyStore) ActiveID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeID
}

func (s *KeyStore) Rotate(newID, encodedSecret string, grace time.Duration) error {
	if !keyIDPattern.MatchString(newID) {
		return apiError(400, "invalid_key_id", "key id must match [A-Za-z0-9._-]{3,64}", nil)
	}
	if grace < 0 || grace > 24*time.Hour {
		return apiError(400, "invalid_grace_period", "grace period must be between zero and 24 hours", nil)
	}
	newSecret, err := decodeSecret(encodedSecret)
	if err != nil {
		return apiError(400, "invalid_key_secret", "new key secret must be base64 and at least 32 bytes", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.keys[newID]; exists {
		return apiError(409, "key_exists", "key id already exists", nil)
	}

	file := keyFile{
		Active: keyRecord{ID: newID, Secret: base64.RawStdEncoding.EncodeToString(newSecret)},
	}
	now := time.Now().UTC()
	if current, ok := s.keys[s.activeID]; ok && grace > 0 {
		expires := now.Add(grace)
		file.Previous = append(file.Previous, keyRecord{
			ID:        s.activeID,
			Secret:    base64.RawStdEncoding.EncodeToString(current.secret),
			ExpiresAt: &expires,
		})
	}
	for id, key := range s.keys {
		if id == s.activeID || key.expiresAt == nil || !key.expiresAt.After(now) {
			continue
		}
		file.Previous = append(file.Previous, keyRecord{
			ID:        id,
			Secret:    base64.RawStdEncoding.EncodeToString(key.secret),
			ExpiresAt: key.expiresAt,
		})
	}

	if err := writeKeyFileAtomic(s.path, file); err != nil {
		return fmt.Errorf("persist rotated agent key: %w", err)
	}
	return s.load(file)
}

func writeKeyFileAtomic(path string, file keyFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agent-keys-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
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
	return os.Chmod(path, 0600)
}

func secureEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
