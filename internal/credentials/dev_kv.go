package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// DevKVStore is an in-memory KVReader for local development.
// It implements the same interface as OpenBaoKV so the Vender works
// identically in dev and production — only the backend differs.
//
// Secrets are loaded from a JSON file at startup. The file format mirrors
// the Vault KV v2 path structure used by the Vender:
//
//	{
//	  "kv/data/generic/forge/telegram": { "token": "7xxx:AAA..." },
//	  "kv/data/llm/anthropic":          { "api_key": "sk-ant-..." }
//	}
//
// The path format must match exactly what Vender constructs:
//   - Generic:  "kv/data/generic/{path}"
//   - LLM keys: "kv/data/llm/{provider}"
//
// SECURITY: the secrets file must be mode 0600. NewDevKVStoreFromFile
// refuses to load a file with broader permissions.
//
// Not for production use. Keys are held in plaintext in memory.
type DevKVStore struct {
	mu      sync.RWMutex
	secrets map[string]map[string]string // path → field → value
}

// devKVFile is the on-disk format for the secrets file.
// Top-level keys are the full KV v2 data paths.
type devKVFile map[string]map[string]string

// NewDevKVStore returns an empty DevKVStore.
// Use Set or LoadFile to populate it.
func NewDevKVStore() *DevKVStore {
	return &DevKVStore{
		secrets: make(map[string]map[string]string),
	}
}

// NewDevKVStoreFromFile loads secrets from a JSON file and returns a
// populated DevKVStore. Returns an error if the file has permissions
// broader than 0600 (i.e., readable by group or others).
func NewDevKVStoreFromFile(path string) (*DevKVStore, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("dev_kv: stat %q: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf(
			"dev_kv: secrets file %q has permissions %o — must be 0600 (readable only by owner)",
			path, info.Mode().Perm(),
		)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dev_kv: reading %q: %w", path, err)
	}

	var file devKVFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("dev_kv: parsing %q: %w", path, err)
	}

	store := NewDevKVStore()
	for kvPath, fields := range file {
		if len(fields) == 0 {
			continue
		}
		copied := make(map[string]string, len(fields))
		for k, v := range fields {
			copied[k] = v
		}
		store.secrets[kvPath] = copied
	}
	return store, nil
}

// Set stores a secret at the given KV v2 data path.
// path must be the full data path, e.g. "kv/data/generic/forge/telegram".
// This is safe for concurrent use.
func (s *DevKVStore) Set(path string, fields map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := make(map[string]string, len(fields))
	for k, v := range fields {
		copied[k] = v
	}
	s.secrets[path] = copied
}

// GetSecret implements KVReader. Returns ErrCredentialNotFound if the path
// is not present in the store.
func (s *DevKVStore) GetSecret(_ context.Context, path string) (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fields, ok := s.secrets[path]
	if !ok {
		return nil, fmt.Errorf("%w: path %q not found in dev KV store", ErrCredentialNotFound, path)
	}

	// Return a copy — callers must not retain a reference into our map.
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	return out, nil
}

// Paths returns all registered KV paths (sorted for deterministic output).
// Intended for diagnostic use only — never called in production paths.
func (s *DevKVStore) Paths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	paths := make([]string, 0, len(s.secrets))
	for p := range s.secrets {
		paths = append(paths, p)
	}
	return paths
}

// ── Convenience constructors for the Vender's expected path layout ────────────

// SetGeneric stores a secret at "kv/data/generic/{path}".
// This corresponds to GET /credentials/generic/{path} on the API.
func (s *DevKVStore) SetGeneric(path string, fields map[string]string) {
	s.Set("kv/data/generic/"+strings.TrimPrefix(path, "/"), fields)
}

// SetLLM stores an LLM provider key at "kv/data/llm/{provider}".
// fields must contain an "api_key" field.
// This corresponds to GET /credentials/llm/{provider} on the API.
func (s *DevKVStore) SetLLM(provider string, apiKey string) {
	s.Set("kv/data/llm/"+provider, map[string]string{"api_key": apiKey})
}
