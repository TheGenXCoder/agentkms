// Package backend defines the only permitted interface for cryptographic
// operations in AgentKMS.  All callers — API handlers, credential vending,
// and tests — must use the Backend interface.  Concrete implementations live
// alongside this file (dev.go, openbao.go, awskms.go, …).
//
// SECURITY INVARIANT: No Backend implementation may return, log, or otherwise
// expose private key material through any method in this interface.  Return
// types are intentionally narrow to make accidental exposure structurally
// impossible.
package backend

import (
	"context"
	"errors"
	"time"
)

// ── Sentinel errors ───────────────────────────────────────────────────────────

// Callers should use errors.Is to test for these; they are wrapped with
// additional context by implementations.

var (
	// ErrKeyNotFound is returned when the requested key ID does not exist in
	// the backend.
	ErrKeyNotFound = errors.New("backend: key not found")

	// ErrAlgorithmMismatch is returned when the requested algorithm does not
	// match the algorithm the key was created for.
	ErrAlgorithmMismatch = errors.New("backend: algorithm does not match key type")

	// ErrKeyTypeMismatch is returned when the operation is not valid for the
	// key's type (e.g. calling Sign on an encryption key).
	ErrKeyTypeMismatch = errors.New("backend: operation not supported for this key type")

	// ErrInvalidInput is returned when caller-supplied input is malformed
	// (e.g. empty payload hash, malformed ciphertext).
	ErrInvalidInput = errors.New("backend: invalid input")
)

// ── Algorithm ─────────────────────────────────────────────────────────────────

// Algorithm identifies the cryptographic algorithm associated with a key.
//
// Signing algorithms: ES256, RS256, EdDSA.
// Encryption algorithms: AES256GCM, RSA_OAEP_SHA256.
type Algorithm string

const (
	// AlgorithmES256 — ECDSA with NIST P-256 and SHA-256.
	// Default for new signing keys.
	AlgorithmES256 Algorithm = "ES256"

	// AlgorithmRS256 — RSASSA-PKCS1-v1_5 with SHA-256 (RSA-2048 minimum).
	// Use when the verifier requires RSA.
	AlgorithmRS256 Algorithm = "RS256"

	// AlgorithmEdDSA — Ed25519 (Edwards-curve Digital Signature Algorithm).
	// Fast, small signatures, no random nonce required.
	AlgorithmEdDSA Algorithm = "EdDSA"

	// AlgorithmAES256GCM — AES-256 in Galois/Counter Mode.
	// Default for new encryption keys.
	AlgorithmAES256GCM Algorithm = "AES256GCM"

	// AlgorithmRSAOAEPSHA256 — RSA-OAEP with SHA-256.
	// Asymmetric encryption; use when the recipient holds an RSA public key.
	AlgorithmRSAOAEPSHA256 Algorithm = "RSA_OAEP_SHA256"
)

// IsSigningAlgorithm reports whether the algorithm is used for signing.
func (a Algorithm) IsSigningAlgorithm() bool {
	switch a {
	case AlgorithmES256, AlgorithmRS256, AlgorithmEdDSA:
		return true
	}
	return false
}

// IsEncryptionAlgorithm reports whether the algorithm is used for encryption.
func (a Algorithm) IsEncryptionAlgorithm() bool {
	switch a {
	case AlgorithmAES256GCM, AlgorithmRSAOAEPSHA256:
		return true
	}
	return false
}

// ── KeyScope ──────────────────────────────────────────────────────────────────

// KeyScope filters the set of keys returned by ListKeys.
// Zero value matches all keys visible to the caller.
type KeyScope struct {
	// Prefix restricts results to keys whose ID begins with this string.
	// Example: "payments/" returns only keys in the payments namespace.
	// Empty string matches all keys.
	Prefix string

	// TeamID restricts results to keys owned by a specific team.
	// Empty string matches all teams.
	TeamID string
}

// ── Result types ──────────────────────────────────────────────────────────────

// KeyMeta carries metadata describing a key.  It never contains key material.
type KeyMeta struct {
	// KeyID is the stable identifier for this key, e.g. "payments/signing-key".
	KeyID string

	// Algorithm is the cryptographic algorithm this key was created for.
	Algorithm Algorithm

	// Version is the current (latest) version number.  Versions start at 1
	// and increment by 1 on each RotateKey call.
	Version int

	// CreatedAt is when version 1 of this key was created (UTC).
	CreatedAt time.Time

	// RotatedAt is when the most recent rotation occurred (UTC).
	// Nil if the key has never been rotated.
	RotatedAt *time.Time

	// TeamID is the team that owns this key.
	TeamID string
}

// SignResult is returned by Backend.Sign.
// It contains only the signature and key version — never key material.
type SignResult struct {
	// Signature is the raw signature bytes.
	// For ES256: DER-encoded ASN.1 (r, s).
	// For RS256: raw PKCS#1 v1.5 signature.
	// For EdDSA: raw 64-byte Ed25519 signature.
	Signature []byte

	// KeyVersion is the version of the key that produced this signature.
	// Must be recorded alongside the signature to enable future key rotation
	// without breaking verification of historical signatures.
	KeyVersion int
}

// EncryptResult is returned by Backend.Encrypt.
// It contains only the ciphertext — never key material or plaintext.
type EncryptResult struct {
	// Ciphertext is the encrypted payload.  Format is backend-specific;
	// callers must treat it as an opaque blob and pass it unmodified to
	// Backend.Decrypt.
	Ciphertext []byte

	// KeyVersion is the version of the key used for encryption.
	// The key version is also embedded in Ciphertext for self-contained
	// decryption, so this field is informational only.
	KeyVersion int
}

// DecryptResult is returned by Backend.Decrypt.
// It contains only the recovered plaintext — never key material.
type DecryptResult struct {
	// Plaintext is the decrypted payload.
	Plaintext []byte
}

// ── Backend interface ──────────────────────────────────────────────────────────

// Backend is the sole gateway for cryptographic operations in AgentKMS.
//
// All API handlers, credential-vending logic, and tests must call operations
// through this interface.  Direct use of any cryptographic SDK (OpenBao, AWS
// KMS, etc.) from outside the backend package is prohibited.
//
// SECURITY CONTRACT (all implementations must uphold):
//
//  1. Private key material MUST NOT appear in any return value, error message,
//     log line, or stack trace produced by any method of this interface.
//
//  2. Sign accepts a SHA-256 hash of the payload (payloadHash), NOT the payload
//     itself.  The backend never handles raw payload data.
//
//  3. Encrypt returns ciphertext only.  The plaintext MUST NOT be echoed back.
//
//  4. Decrypt returns plaintext only.  Key material MUST NOT be included.
//
//  5. ListKeys and RotateKey return key METADATA only.  Field KeyMeta
//     intentionally has no field that could hold key material.
//
//  6. Implementations MUST be safe for concurrent use by multiple goroutines.
//
// Callers are responsible for: policy evaluation, audit logging, and input
// validation before reaching this interface.
type Backend interface {
	// Sign computes a signature over payloadHash using the specified key and
	// algorithm.
	//
	// payloadHash MUST be the SHA-256 hash of the actual payload (32 bytes).
	// The backend never receives the raw payload.
	//
	// Returns ErrKeyNotFound if keyID does not exist.
	// Returns ErrAlgorithmMismatch if alg does not match the key's algorithm.
	// Returns ErrKeyTypeMismatch if the key is an encryption key.
	// Returns ErrInvalidInput if payloadHash is empty or not 32 bytes.
	Sign(ctx context.Context, keyID string, payloadHash []byte, alg Algorithm) (*SignResult, error)

	// Encrypt encrypts plaintext using the identified key.  The encryption
	// algorithm is determined by the key's configuration, not the caller.
	//
	// The returned ciphertext is self-contained: it embeds the key version
	// so that Decrypt can retrieve the correct historical key version.
	//
	// Returns ErrKeyNotFound if keyID does not exist.
	// Returns ErrKeyTypeMismatch if the key is a signing key.
	// Returns ErrInvalidInput if plaintext is nil.
	Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptResult, error)

	// Decrypt decrypts ciphertext produced by Encrypt.  The key version is
	// extracted from the ciphertext header; historical key versions are
	// retained after rotation to support this.
	//
	// Returns ErrKeyNotFound if keyID does not exist.
	// Returns ErrKeyTypeMismatch if the key is a signing key.
	// Returns ErrInvalidInput if ciphertext is malformed or truncated.
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*DecryptResult, error)

	// ListKeys returns metadata for all keys matching the given scope.
	// It never returns key material.
	//
	// An empty KeyScope matches all keys visible to the backend instance.
	ListKeys(ctx context.Context, scope KeyScope) ([]*KeyMeta, error)

	// RotateKey creates a new key version, making it the active version for
	// all subsequent Sign and Encrypt operations.  Historical versions are
	// retained so that ciphertext produced before rotation remains decryptable.
	//
	// Returns ErrKeyNotFound if keyID does not exist.
	RotateKey(ctx context.Context, keyID string) (*KeyMeta, error)
}
