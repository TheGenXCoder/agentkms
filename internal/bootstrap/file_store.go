// Package bootstrap provides file-backed bootstrap token storage for bare-metal AgentKMS.
package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/agentkms/agentkms/internal/auth"
)

// FileStore persists bootstrap tokens as JSON files keyed by SHA-256 of the raw token.
type FileStore struct {
	dir string
}

// NewFileStore creates a bootstrap store under dir (created if missing).
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("bootstrap file store: mkdir: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) path(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	key := hex.EncodeToString(sum[:])
	return filepath.Join(s.dir, key+".json")
}

// Create implements auth.BootstrapStore.
func (s *FileStore) Create(ctx context.Context, record auth.BootstrapRecord) (string, error) {
	_ = ctx
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("bootstrap file store: generate token: %w", err)
	}
	rawToken := hex.EncodeToString(raw[:])
	record.Used = false
	data, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(s.path(rawToken), data, 0600); err != nil {
		return "", fmt.Errorf("bootstrap file store: write: %w", err)
	}
	return rawToken, nil
}

// Fetch implements auth.BootstrapStore.
func (s *FileStore) Fetch(ctx context.Context, rawToken string) (*auth.BootstrapRecord, error) {
	_ = ctx
	data, err := os.ReadFile(s.path(rawToken))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rec auth.BootstrapRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// MarkUsed implements auth.BootstrapStore.
func (s *FileStore) MarkUsed(ctx context.Context, rawToken string) error {
	rec, err := s.Fetch(ctx, rawToken)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("bootstrap file store: token not found")
	}
	rec.Used = true
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path(rawToken), data, 0600)
}
