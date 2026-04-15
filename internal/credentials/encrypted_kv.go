package credentials

// EncryptedKV stores secrets in an AES-256-GCM encrypted file on disk.
//
// The encryption key is derived from the server's EC private key using
// HKDF-SHA256. This means:
//   - secrets.enc is useless without server.key
//   - server.key is mode 0600 (only readable by owner)
//   - Works in any terminal context (tmux, SSH, etc.) — no Keychain session needed
//   - Secrets are never in plaintext on disk
//
// File format (secrets.enc):
//
//	[12-byte nonce][AES-256-GCM ciphertext of JSON map[string]map[string]string]
//
// Path layout mirrors Vault KV v2 (same as DevKVStore and KeychainKV):
//
//	"kv/data/generic/forge/telegram" → { "token": "..." }
//	"kv/data/llm/anthropic"          → { "api_key": "..." }

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// EncryptedKV implements KVReader backed by an AES-256-GCM encrypted file.
type EncryptedKV struct {
	secretsPath string
	keyPath     string
	mu          sync.RWMutex
}

// NewEncryptedKV creates an EncryptedKV.
//   - secretsPath: path to the encrypted secrets file (e.g. ~/.agentkms/dev/secrets.enc)
//   - keyPath:     path to the EC server private key used for key derivation
func NewEncryptedKV(secretsPath, keyPath string) *EncryptedKV {
	return &EncryptedKV{
		secretsPath: secretsPath,
		keyPath:     keyPath,
	}
}

// GetSecret implements KVReader.
func (e *EncryptedKV) GetSecret(_ context.Context, path string) (map[string]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	all, err := e.loadAll()
	if err != nil {
		return nil, err
	}

	fields, ok := all[path]
	if !ok {
		return nil, fmt.Errorf("%w: path %q not found", ErrCredentialNotFound, path)
	}

	// Return a defensive copy
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	return out, nil
}

// Set writes or updates a secret at path in the encrypted file.
// Reads the current file, updates in memory, re-encrypts, and writes atomically.
func (e *EncryptedKV) Set(path string, fields map[string]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	all, err := e.loadAll()
	if err != nil && !errors.Is(err, ErrCredentialNotFound) && !os.IsNotExist(err) {
		// If file doesn't exist yet, start with empty map
		if !errors.Is(err, errFileNotFound) {
			return err
		}
	}
	if all == nil {
		all = make(map[string]map[string]string)
	}

	copied := make(map[string]string, len(fields))
	for k, v := range fields {
		copied[k] = v
	}
	all[path] = copied

	return e.saveAll(all)
}

// Delete removes a path from the encrypted file.
func (e *EncryptedKV) Delete(path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	all, err := e.loadAll()
	if err != nil {
		return err
	}
	delete(all, path)
	return e.saveAll(all)
}

// Paths returns all stored paths (for listing).
func (e *EncryptedKV) Paths() ([]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	all, err := e.loadAll()
	if err != nil {
		if errors.Is(err, errFileNotFound) {
			return nil, nil
		}
		return nil, err
	}
	paths := make([]string, 0, len(all))
	for p := range all {
		paths = append(paths, p)
	}
	return paths, nil
}

// SetSecret implements KVWriter.
func (e *EncryptedKV) SetSecret(_ context.Context, path string, fields map[string]string) error {
	return e.Set(path, fields)
}

// DeleteSecret implements KVWriter.
func (e *EncryptedKV) DeleteSecret(_ context.Context, path string) error {
	return e.Delete(path)
}

// ListPaths implements KVWriter.
func (e *EncryptedKV) ListPaths(_ context.Context) ([]string, error) {
	return e.Paths()
}

// ── Crypto internals ──────────────────────────────────────────────────────────

var errFileNotFound = errors.New("secrets file not found")

func (e *EncryptedKV) deriveKey() ([]byte, error) {
	keyPEM, err := os.ReadFile(e.keyPath)
	if err != nil {
		return nil, fmt.Errorf("encrypted_kv: reading server key %q: %w", e.keyPath, err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("encrypted_kv: no PEM block in %q", e.keyPath)
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("encrypted_kv: parsing EC private key: %w", err)
	}

	// Derive a 32-byte AES key from the EC private key using HKDF-SHA256.
	// Salt: SHA-256("agentkms-dev-secrets") — domain separation.
	// Info: "agentkms-dev-kv-v1" — version binding.
	ikm := derivedIKM(privKey)
	salt := sha256.Sum256([]byte("agentkms-dev-secrets"))
	reader := hkdf.New(sha256.New, ikm, salt[:], []byte("agentkms-dev-kv-v1"))

	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("encrypted_kv: HKDF derivation failed: %w", err)
	}
	return key, nil
}

// derivedIKM extracts the EC private key's scalar bytes as input key material.
// We use the raw D value (32 bytes for P-256) as the IKM for HKDF.
func derivedIKM(key *ecdsa.PrivateKey) []byte {
	return key.D.Bytes()
}

func (e *EncryptedKV) loadAll() (map[string]map[string]string, error) {
	if _, err := os.Stat(e.secretsPath); os.IsNotExist(err) {
		return nil, errFileNotFound
	}

	ciphertext, err := os.ReadFile(e.secretsPath)
	if err != nil {
		return nil, fmt.Errorf("encrypted_kv: reading %q: %w", e.secretsPath, err)
	}

	key, err := e.deriveKey()
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcmDecrypt(key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("encrypted_kv: decryption failed (wrong key or corrupted file): %w", err)
	}

	var all map[string]map[string]string
	if err := json.Unmarshal(plaintext, &all); err != nil {
		return nil, fmt.Errorf("encrypted_kv: parsing decrypted data: %w", err)
	}
	return all, nil
}

func (e *EncryptedKV) saveAll(all map[string]map[string]string) error {
	plaintext, err := json.Marshal(all)
	if err != nil {
		return fmt.Errorf("encrypted_kv: marshalling: %w", err)
	}

	key, err := e.deriveKey()
	if err != nil {
		return err
	}

	ciphertext, err := aesgcmEncrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypted_kv: encryption failed: %w", err)
	}

	// Atomic write: write to temp file then rename.
	tmpPath := e.secretsPath + ".tmp"
	if err := os.WriteFile(tmpPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("encrypted_kv: writing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, e.secretsPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("encrypted_kv: atomic rename failed: %w", err)
	}
	return nil
}

// aesgcmEncrypt encrypts plaintext with AES-256-GCM.
// Output: [12-byte nonce][ciphertext+tag]
func aesgcmEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// aesgcmDecrypt decrypts AES-256-GCM ciphertext.
// Input: [12-byte nonce][ciphertext+tag]
func aesgcmDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
