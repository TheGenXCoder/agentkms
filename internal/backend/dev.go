package backend

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// DevBackend is a fully in-memory Backend implementation used for local
// development and unit tests.  It has zero external dependencies.
//
// SECURITY PROPERTIES (same as production backends):
//   - Private key material is stored only in unexported struct fields.
//   - No Backend interface method returns key material.
//   - Sign returns a cryptographic signature, not the key.
//   - Encrypt returns ciphertext, not the key.
//   - Decrypt returns plaintext, not the key.
//   - ListKeys and RotateKey return KeyMeta, which has no key-material field.
//
// LIMITATIONS (acceptable for local dev only):
//   - Not persistent: all keys are lost when the process exits.
//   - Not distributed: single-process only.
//   - Not FIPS validated: uses Go standard library crypto.
//
// Concurrency: all methods are safe for concurrent use.
type DevBackend struct {
	mu   sync.RWMutex
	keys map[string]*keyEntry
}

// NewDevBackend constructs an empty DevBackend with no keys.
// Keys are added via CreateKey.
func NewDevBackend() *DevBackend {
	return &DevBackend{
		keys: make(map[string]*keyEntry),
	}
}

// ── Internal types ────────────────────────────────────────────────────────────

// keyVersion holds the key material for one version of a key.
// The version number is 1-based (first version = 1).
//
// SECURITY NOTE: all fields holding key material are unexported.
// They are accessible within this package for adversarial testing only.
type keyVersion struct {
	version   int
	createdAt time.Time

	// signing key material — exactly one is non-nil for signing keys.
	ecPrivKey  *ecdsa.PrivateKey  // ES256
	rsaPrivKey *rsa.PrivateKey    // RS256
	edPrivKey  ed25519.PrivateKey // EdDSA (nil slice = unset; len > 0 = set)

	// encryption key material — set for AES256GCM keys.
	aesKey []byte // 32 bytes
}

// keyEntry is the top-level record for a logical key, holding all its
// versions.  Versions are appended on each RotateKey call.
type keyEntry struct {
	mu        sync.RWMutex
	keyID     string
	algorithm Algorithm
	teamID    string
	createdAt time.Time
	rotatedAt *time.Time // nil until first rotation

	// versions[0] = version 1, versions[n-1] = latest.
	versions []*keyVersion
}

// latestVersion returns the newest keyVersion.  The caller must hold at
// least a read lock on entry.mu.
func (e *keyEntry) latestVersion() *keyVersion {
	return e.versions[len(e.versions)-1]
}

// versionByNumber looks up a keyVersion by its 1-based version number.
// Returns nil if the version does not exist.  The caller must hold at least
// a read lock on entry.mu.
func (e *keyEntry) versionByNumber(n int) *keyVersion {
	idx := n - 1 // convert to 0-based index
	if idx < 0 || idx >= len(e.versions) {
		return nil
	}
	return e.versions[idx]
}

// ── Key creation (DevBackend-specific, not part of Backend interface) ─────────

// CreateKey generates a new key with the given ID, algorithm, and team
// ownership, and stores it in the backend.
//
// CreateKey is not part of the Backend interface; it is a DevBackend-specific
// operation used by the dev CLI and tests to seed the key store.
//
// Supported algorithms:
//   - AlgorithmES256       — ECDSA P-256
//   - AlgorithmRS256       — RSA-2048 (generation is intentionally slower)
//   - AlgorithmEdDSA       — Ed25519
//   - AlgorithmAES256GCM   — AES-256
//
// Returns an error if keyID already exists or the algorithm is unsupported.
func (b *DevBackend) CreateKey(keyID string, alg Algorithm, teamID string) error {
	if keyID == "" {
		return fmt.Errorf("%w: keyID must not be empty", ErrInvalidInput)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.keys[keyID]; exists {
		return fmt.Errorf("backend: key %q already exists", keyID)
	}

	ver, err := generateKeyVersion(1, alg)
	if err != nil {
		return fmt.Errorf("backend: generating key material for %q: %w", keyID, err)
	}

	now := time.Now().UTC()
	b.keys[keyID] = &keyEntry{
		keyID:     keyID,
		algorithm: alg,
		teamID:    teamID,
		createdAt: now,
		versions:  []*keyVersion{ver},
	}
	return nil
}

// generateKeyVersion creates new key material for the given version number
// and algorithm.  It never returns key material outside of the keyVersion
// struct; the returned struct is stored in unexported fields only.
func generateKeyVersion(version int, alg Algorithm) (*keyVersion, error) {
	ver := &keyVersion{
		version:   version,
		createdAt: time.Now().UTC(),
	}

	switch alg {
	case AlgorithmES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ES256 key generation: %w", err)
		}
		ver.ecPrivKey = priv

	case AlgorithmRS256:
		// RSA-2048 is the minimum acceptable key size.  Generation is slower
		// than ECDSA or EdDSA; this is expected and acceptable in dev mode.
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("RS256 key generation: %w", err)
		}
		ver.rsaPrivKey = priv

	case AlgorithmEdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("EdDSA key generation: %w", err)
		}
		ver.edPrivKey = priv

	case AlgorithmAES256GCM:
		key := make([]byte, 32) // AES-256
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("AES-256 key generation: %w", err)
		}
		ver.aesKey = key

	default:
		return nil, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidInput, alg)
	}

	return ver, nil
}

// ── Backend interface implementation ──────────────────────────────────────────

// Sign computes a cryptographic signature over payloadHash using the
// identified key.  payloadHash must be exactly 32 bytes (SHA-256).
//
// The signature is returned in result.Signature; no key material is included.
func (b *DevBackend) Sign(ctx context.Context, keyID string, payloadHash []byte, alg Algorithm) (*SignResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(payloadHash) != 32 {
		return nil, fmt.Errorf("%w: payloadHash must be exactly 32 bytes (SHA-256), got %d", ErrInvalidInput, len(payloadHash))
	}

	entry, err := b.getEntry(keyID)
	if err != nil {
		return nil, err
	}

	entry.mu.RLock()
	defer entry.mu.RUnlock()

	if !entry.algorithm.IsSigningAlgorithm() {
		return nil, fmt.Errorf("%w: key %q has algorithm %q (encryption key), cannot sign",
			ErrKeyTypeMismatch, keyID, entry.algorithm)
	}
	if entry.algorithm != alg {
		return nil, fmt.Errorf("%w: key %q uses %q, caller requested %q",
			ErrAlgorithmMismatch, keyID, entry.algorithm, alg)
	}

	ver := entry.latestVersion()

	var sig []byte
	switch alg {
	case AlgorithmES256:
		sig, err = ecdsa.SignASN1(rand.Reader, ver.ecPrivKey, payloadHash)
		if err != nil {
			return nil, fmt.Errorf("backend: ES256 sign: %w", err)
		}

	case AlgorithmRS256:
		// rsa.SignPKCS1v15 requires the hash to already be the correct size;
		// payloadHash is 32 bytes (SHA-256), matching crypto.SHA256.
		sig, err = rsa.SignPKCS1v15(rand.Reader, ver.rsaPrivKey, 0, payloadHash)
		if err != nil {
			return nil, fmt.Errorf("backend: RS256 sign: %w", err)
		}

	case AlgorithmEdDSA:
		// ed25519.Sign accepts the message directly; it applies SHA-512
		// internally.  We pass payloadHash (the SHA-256 of the original
		// payload) as the message.  Verification must use the same input.
		sig = ed25519.Sign(ver.edPrivKey, payloadHash)

	default:
		// Unreachable: algorithm mismatch was checked above.
		return nil, fmt.Errorf("%w: unhandled signing algorithm %q", ErrInvalidInput, alg)
	}

	return &SignResult{
		Signature:  sig,
		KeyVersion: ver.version,
	}, nil
}

// Encrypt encrypts plaintext with the identified AES-256-GCM key.
//
// Ciphertext format (opaque to callers):
//
//	[4 bytes: key version, uint32 big-endian]
//	[12 bytes: AES-GCM nonce]
//	[remaining: AES-GCM Seal output = ciphertext || 16-byte authentication tag]
//
// The key version is embedded so that Decrypt can retrieve the correct
// historical key version without any external metadata.
func (b *DevBackend) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if plaintext == nil {
		return nil, fmt.Errorf("%w: plaintext must not be nil", ErrInvalidInput)
	}

	entry, err := b.getEntry(keyID)
	if err != nil {
		return nil, err
	}

	entry.mu.RLock()
	defer entry.mu.RUnlock()

	if !entry.algorithm.IsEncryptionAlgorithm() {
		return nil, fmt.Errorf("%w: key %q has algorithm %q (signing key), cannot encrypt",
			ErrKeyTypeMismatch, keyID, entry.algorithm)
	}
	if entry.algorithm != AlgorithmAES256GCM {
		return nil, fmt.Errorf("%w: dev backend only supports AES256GCM encryption, key uses %q",
			ErrInvalidInput, entry.algorithm)
	}

	ver := entry.latestVersion()

	block, err := aes.NewCipher(ver.aesKey)
	if err != nil {
		return nil, fmt.Errorf("backend: AES cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backend: GCM init: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("backend: nonce generation: %w", err)
	}

	// Build output: [4-byte version][12-byte nonce][sealed ciphertext+tag]
	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 4+len(nonce)+len(sealed))
	binary.BigEndian.PutUint32(out[0:4], uint32(ver.version))
	copy(out[4:4+len(nonce)], nonce)
	copy(out[4+len(nonce):], sealed)

	return &EncryptResult{
		Ciphertext: out,
		KeyVersion: ver.version,
	}, nil
}

// Decrypt decrypts ciphertext produced by Encrypt.  The key version is
// extracted from the ciphertext header; historical versions are retained
// after key rotation to support decryption of old data.
func (b *DevBackend) Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*DecryptResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Minimum size: 4 (version) + 12 (nonce) + 16 (GCM tag) = 32 bytes.
	// Zero-byte plaintext produces a 16-byte tag, so 32 bytes is the minimum.
	const minSize = 4 + 12 + 16
	if len(ciphertext) < minSize {
		return nil, fmt.Errorf("%w: ciphertext too short (%d bytes, minimum %d)",
			ErrInvalidInput, len(ciphertext), minSize)
	}

	entry, err := b.getEntry(keyID)
	if err != nil {
		return nil, err
	}

	entry.mu.RLock()
	defer entry.mu.RUnlock()

	if !entry.algorithm.IsEncryptionAlgorithm() {
		return nil, fmt.Errorf("%w: key %q has algorithm %q (signing key), cannot decrypt",
			ErrKeyTypeMismatch, keyID, entry.algorithm)
	}

	// Parse the embedded version to select the correct historical key.
	keyVersionNum := int(binary.BigEndian.Uint32(ciphertext[0:4]))
	ver := entry.versionByNumber(keyVersionNum)
	if ver == nil {
		return nil, fmt.Errorf("%w: key %q version %d not found (current version: %d)",
			ErrInvalidInput, keyID, keyVersionNum, entry.latestVersion().version)
	}

	nonce := ciphertext[4:16]
	sealed := ciphertext[16:]

	block, err := aes.NewCipher(ver.aesKey)
	if err != nil {
		return nil, fmt.Errorf("backend: AES cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backend: GCM init: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		// Do not include ciphertext bytes in the error: they could be
		// large or sensitive.
		return nil, fmt.Errorf("backend: AES-GCM authentication failed for key %q version %d: %w",
			keyID, keyVersionNum, err)
	}

	return &DecryptResult{Plaintext: plaintext}, nil
}

// ListKeys returns metadata for all keys whose ID matches the given scope.
// No key material is included in the returned KeyMeta values.
func (b *DevBackend) ListKeys(ctx context.Context, scope KeyScope) ([]*KeyMeta, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	var result []*KeyMeta
	for _, entry := range b.keys {
		entry.mu.RLock()

		if scope.Prefix != "" && !strings.HasPrefix(entry.keyID, scope.Prefix) {
			entry.mu.RUnlock()
			continue
		}
		if scope.TeamID != "" && entry.teamID != scope.TeamID {
			entry.mu.RUnlock()
			continue
		}

		latest := entry.latestVersion()
		meta := &KeyMeta{
			KeyID:     entry.keyID,
			Algorithm: entry.algorithm,
			Version:   latest.version,
			CreatedAt: entry.createdAt,
			TeamID:    entry.teamID,
		}
		if entry.rotatedAt != nil {
			t := *entry.rotatedAt
			meta.RotatedAt = &t
		}

		entry.mu.RUnlock()
		result = append(result, meta)
	}

	return result, nil
}

// RotateKey generates new key material for keyID, incrementing the version.
// The previous version is retained so that data encrypted with it can still
// be decrypted.
//
// After rotation, Sign and Encrypt automatically use the new version.
func (b *DevBackend) RotateKey(ctx context.Context, keyID string) (*KeyMeta, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	entry, err := b.getEntry(keyID)
	if err != nil {
		return nil, err
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	newVersionNum := entry.latestVersion().version + 1
	ver, err := generateKeyVersion(newVersionNum, entry.algorithm)
	if err != nil {
		return nil, fmt.Errorf("backend: rotate key %q: %w", keyID, err)
	}

	entry.versions = append(entry.versions, ver)
	now := time.Now().UTC()
	entry.rotatedAt = &now

	return &KeyMeta{
		KeyID:     entry.keyID,
		Algorithm: entry.algorithm,
		Version:   newVersionNum,
		CreatedAt: entry.createdAt,
		RotatedAt: entry.rotatedAt,
		TeamID:    entry.teamID,
	}, nil
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// getEntry looks up a key by ID.  Returns ErrKeyNotFound if absent.
// The returned *keyEntry should be locked by the caller as needed.
func (b *DevBackend) getEntry(keyID string) (*keyEntry, error) {
	b.mu.RLock()
	entry, ok := b.keys[keyID]
	b.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, keyID)
	}
	return entry, nil
}
