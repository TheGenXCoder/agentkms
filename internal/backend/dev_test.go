// Package backend — adversarial tests for the Backend interface contract.
//
// F-08: These tests verify the core security guarantee of the Backend
// interface: private key material MUST NOT appear in any return value, error
// message, or serialised form produced by Backend methods.
//
// This file is in package backend (not package backend_test) so that it can
// access unexported fields to extract raw key material for comparison.  This
// is an intentional testing pattern: we need to know what the key bytes ARE
// in order to assert they do NOT appear elsewhere.
//
// Test categories:
//   1. Happy-path correctness: sign → verify, encrypt → decrypt roundtrips.
//   2. Key versioning: rotate → old ciphertext still decryptable.
//   3. ADVERSARIAL — key material never in return values.
//   4. ADVERSARIAL — key material never in error messages.
//   5. Input validation: malformed inputs return errors, not panics.
//   6. Concurrency: safe for parallel use.
//   7. ListKeys / RotateKey: metadata only, no key material.
package backend

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// ── Test fixtures ─────────────────────────────────────────────────────────────

// rsaKeyOnce ensures the slow RSA-2048 key is generated only once per test
// binary invocation.  RSA key generation takes ~100-400ms; generating one
// key for the whole suite is acceptable.
var (
	rsaKeyOnce sync.Once
	rsaBackend *DevBackend
)

func getSharedRSABackend(t *testing.T) *DevBackend {
	t.Helper()
	rsaKeyOnce.Do(func() {
		rsaBackend = NewDevBackend()
		if err := rsaBackend.CreateKey("rsa/shared", AlgorithmRS256, "test-team"); err != nil {
			panic(fmt.Sprintf("failed to create shared RSA key: %v", err))
		}
	})
	return rsaBackend
}

// testHash returns a deterministic 32-byte SHA-256 hash of msg.
func testHash(msg string) []byte {
	h := sha256.Sum256([]byte(msg))
	return h[:]
}

// newBackendWithKey creates a fresh DevBackend with a single key of the
// given algorithm.  Fails the test immediately on any error.
func newBackendWithKey(t *testing.T, keyID string, alg Algorithm) *DevBackend {
	t.Helper()
	b := NewDevBackend()
	if err := b.CreateKey(keyID, alg, "test-team"); err != nil {
		t.Fatalf("CreateKey(%q, %q): %v", keyID, alg, err)
	}
	return b
}

// ── 1. Happy-path correctness ─────────────────────────────────────────────────

func TestDevBackend_Sign_ES256_RoundTrip(t *testing.T) {
	b := newBackendWithKey(t, "test/es256", AlgorithmES256)
	hash := testHash("hello ES256")

	result, err := b.Sign(context.Background(), "test/es256", hash, AlgorithmES256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(result.Signature) == 0 {
		t.Fatal("Sign returned empty signature")
	}
	if result.KeyVersion != 1 {
		t.Fatalf("expected KeyVersion 1, got %d", result.KeyVersion)
	}

	// Verify the signature using the public key extracted from the backend.
	b.mu.RLock()
	entry := b.keys["test/es256"]
	b.mu.RUnlock()

	entry.mu.RLock()
	pubKey := &entry.versions[0].ecPrivKey.PublicKey
	entry.mu.RUnlock()

	if !ecdsa.VerifyASN1(pubKey, hash, result.Signature) {
		t.Fatal("ECDSA signature verification failed")
	}
}

func TestDevBackend_Sign_RS256_RoundTrip(t *testing.T) {
	b := getSharedRSABackend(t)
	hash := testHash("hello RS256")

	result, err := b.Sign(context.Background(), "rsa/shared", hash, AlgorithmRS256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(result.Signature) == 0 {
		t.Fatal("Sign returned empty signature")
	}

	// Verify with the RSA public key.
	b.mu.RLock()
	entry := b.keys["rsa/shared"]
	b.mu.RUnlock()

	entry.mu.RLock()
	pubKey := &entry.versions[0].rsaPrivKey.PublicKey
	entry.mu.RUnlock()

	if err := rsa.VerifyPKCS1v15(pubKey, 0, hash, result.Signature); err != nil {
		t.Fatalf("RSA signature verification failed: %v", err)
	}
}

func TestDevBackend_Sign_EdDSA_RoundTrip(t *testing.T) {
	b := newBackendWithKey(t, "test/eddsa", AlgorithmEdDSA)
	hash := testHash("hello EdDSA")

	result, err := b.Sign(context.Background(), "test/eddsa", hash, AlgorithmEdDSA)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(result.Signature) != ed25519.SignatureSize {
		t.Fatalf("expected %d-byte Ed25519 signature, got %d", ed25519.SignatureSize, len(result.Signature))
	}

	// Verify with the Ed25519 public key.
	b.mu.RLock()
	entry := b.keys["test/eddsa"]
	b.mu.RUnlock()

	entry.mu.RLock()
	pubKey := entry.versions[0].edPrivKey.Public().(ed25519.PublicKey)
	entry.mu.RUnlock()

	if !ed25519.Verify(pubKey, hash, result.Signature) {
		t.Fatal("Ed25519 signature verification failed")
	}
}

func TestDevBackend_Encrypt_Decrypt_RoundTrip(t *testing.T) {
	b := newBackendWithKey(t, "test/aes", AlgorithmAES256GCM)
	plaintext := []byte("AgentKMS roundtrip test — sensitive data placeholder")

	enc, err := b.Encrypt(context.Background(), "test/aes", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(enc.Ciphertext) == 0 {
		t.Fatal("Encrypt returned empty ciphertext")
	}
	if enc.KeyVersion != 1 {
		t.Fatalf("expected KeyVersion 1, got %d", enc.KeyVersion)
	}
	// Ciphertext must not equal plaintext.
	if bytes.Equal(enc.Ciphertext, plaintext) {
		t.Fatal("Ciphertext equals plaintext — encryption not applied")
	}

	dec, err := b.Decrypt(context.Background(), "test/aes", enc.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(dec.Plaintext, plaintext) {
		t.Fatalf("Decrypt produced wrong plaintext:\n  want: %q\n  got:  %q", plaintext, dec.Plaintext)
	}
}

func TestDevBackend_Encrypt_EmptyPlaintext(t *testing.T) {
	b := newBackendWithKey(t, "test/aes-empty", AlgorithmAES256GCM)

	enc, err := b.Encrypt(context.Background(), "test/aes-empty", []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty plaintext: %v", err)
	}

	dec, err := b.Decrypt(context.Background(), "test/aes-empty", enc.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt of empty plaintext: %v", err)
	}
	if len(dec.Plaintext) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(dec.Plaintext))
	}
}

// ── 2. Key versioning ─────────────────────────────────────────────────────────

func TestDevBackend_RotateKey_NewVersionUsed(t *testing.T) {
	b := newBackendWithKey(t, "test/rotate-sign", AlgorithmES256)
	hash := testHash("before rotation")

	// Sign before rotation → version 1.
	r1, err := b.Sign(context.Background(), "test/rotate-sign", hash, AlgorithmES256)
	if err != nil {
		t.Fatalf("Sign v1: %v", err)
	}
	if r1.KeyVersion != 1 {
		t.Fatalf("expected v1, got %d", r1.KeyVersion)
	}

	// Rotate.
	meta, err := b.RotateKey(context.Background(), "test/rotate-sign")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if meta.Version != 2 {
		t.Fatalf("expected version 2 after rotation, got %d", meta.Version)
	}
	if meta.RotatedAt == nil {
		t.Fatal("RotatedAt should be non-nil after rotation")
	}

	// Sign after rotation → version 2.
	r2, err := b.Sign(context.Background(), "test/rotate-sign", hash, AlgorithmES256)
	if err != nil {
		t.Fatalf("Sign v2: %v", err)
	}
	if r2.KeyVersion != 2 {
		t.Fatalf("expected v2 after rotation, got %d", r2.KeyVersion)
	}
}

func TestDevBackend_RotateKey_OldCiphertextStillDecryptable(t *testing.T) {
	b := newBackendWithKey(t, "test/rotate-enc", AlgorithmAES256GCM)
	plaintext := []byte("data encrypted before rotation")

	// Encrypt with version 1.
	enc1, err := b.Encrypt(context.Background(), "test/rotate-enc", plaintext)
	if err != nil {
		t.Fatalf("Encrypt v1: %v", err)
	}
	if enc1.KeyVersion != 1 {
		t.Fatalf("expected KeyVersion 1, got %d", enc1.KeyVersion)
	}

	// Rotate to version 2.
	if _, err := b.RotateKey(context.Background(), "test/rotate-enc"); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// New encryption uses version 2.
	enc2, err := b.Encrypt(context.Background(), "test/rotate-enc", []byte("new data"))
	if err != nil {
		t.Fatalf("Encrypt v2: %v", err)
	}
	if enc2.KeyVersion != 2 {
		t.Fatalf("expected KeyVersion 2, got %d", enc2.KeyVersion)
	}

	// Old ciphertext (v1) must still decrypt correctly.
	dec1, err := b.Decrypt(context.Background(), "test/rotate-enc", enc1.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt v1 ciphertext after rotation: %v", err)
	}
	if !bytes.Equal(dec1.Plaintext, plaintext) {
		t.Fatalf("Decrypted v1 plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, dec1.Plaintext)
	}

	// New ciphertext (v2) also decrypts.
	dec2, err := b.Decrypt(context.Background(), "test/rotate-enc", enc2.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt v2 ciphertext: %v", err)
	}
	if string(dec2.Plaintext) != "new data" {
		t.Fatalf("Decrypted v2 plaintext mismatch: %q", dec2.Plaintext)
	}
}

// ── 3. ADVERSARIAL — key material never in return values ──────────────────────

// TestAdversarial_Sign_ES256_NoPrivateKeyInSignature verifies that the ECDSA
// private key's DER encoding does not appear anywhere in the signature bytes
// or in its JSON serialisation.
func TestAdversarial_Sign_ES256_NoPrivateKeyInSignature(t *testing.T) {
	b := newBackendWithKey(t, "adv/es256", AlgorithmES256)

	// Extract private key bytes from inside the backend.
	b.mu.RLock()
	entry := b.keys["adv/es256"]
	b.mu.RUnlock()

	entry.mu.RLock()
	privKey := entry.versions[0].ecPrivKey
	entry.mu.RUnlock()

	// DER-encode the private key: this is the canonical byte representation
	// that would appear in logs or responses if the key leaked.
	privDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	// Also check the raw private scalar (D) — 32 bytes.
	privD := privKey.D.FillBytes(make([]byte, 32))

	hash := testHash("adversarial ES256 test")
	result, err := b.Sign(context.Background(), "adv/es256", hash, AlgorithmES256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// The signature must not contain the private key's DER encoding.
	if bytes.Contains(result.Signature, privDER) {
		t.Fatal("ADVERSARIAL: Sign result.Signature contains private key DER")
	}
	// The signature must not contain the raw private scalar.
	if bytes.Contains(result.Signature, privD) {
		t.Fatal("ADVERSARIAL: Sign result.Signature contains private key scalar D")
	}

	// Serialise the entire SignResult to JSON and re-check.
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(SignResult): %v", err)
	}
	if bytes.Contains(encoded, privDER) {
		t.Fatal("ADVERSARIAL: JSON-encoded SignResult contains private key DER")
	}
	if bytes.Contains(encoded, privD) {
		t.Fatal("ADVERSARIAL: JSON-encoded SignResult contains private key scalar D")
	}
}

// TestAdversarial_Sign_RS256_NoPrivateKeyInSignature verifies that the RSA
// private key does not appear in the RS256 signature.
func TestAdversarial_Sign_RS256_NoPrivateKeyInSignature(t *testing.T) {
	b := getSharedRSABackend(t)

	b.mu.RLock()
	entry := b.keys["rsa/shared"]
	b.mu.RUnlock()

	entry.mu.RLock()
	privKey := entry.versions[0].rsaPrivKey
	entry.mu.RUnlock()

	// DER-encode the RSA private key (PKCS#1).
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	// Check the raw prime P bytes as a substring probe.
	primeP := privKey.Primes[0].Bytes()

	hash := testHash("adversarial RS256 test")
	result, err := b.Sign(context.Background(), "rsa/shared", hash, AlgorithmRS256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if bytes.Contains(result.Signature, privDER) {
		t.Fatal("ADVERSARIAL: RS256 Signature contains private key DER")
	}
	// The RSA signature is exactly 256 bytes; prime P is ~128 bytes.
	// A coincidental match here would indicate a catastrophic bug.
	if bytes.Contains(result.Signature, primeP) {
		t.Fatal("ADVERSARIAL: RS256 Signature contains RSA prime P")
	}
}

// TestAdversarial_Sign_EdDSA_NoPrivateKeyInSignature verifies that the Ed25519
// private key bytes do not appear in the 64-byte signature.
func TestAdversarial_Sign_EdDSA_NoPrivateKeyInSignature(t *testing.T) {
	b := newBackendWithKey(t, "adv/eddsa", AlgorithmEdDSA)

	b.mu.RLock()
	entry := b.keys["adv/eddsa"]
	b.mu.RUnlock()

	entry.mu.RLock()
	privKey := entry.versions[0].edPrivKey // []byte, length 64
	entry.mu.RUnlock()

	// The Ed25519 private key in Go is: [32-byte seed || 32-byte public key].
	// We check both halves independently.
	privSeed := privKey[:32]
	privAll := []byte(privKey)

	hash := testHash("adversarial EdDSA test")
	result, err := b.Sign(context.Background(), "adv/eddsa", hash, AlgorithmEdDSA)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if bytes.Equal(result.Signature, privAll) {
		t.Fatal("ADVERSARIAL: EdDSA Signature equals the private key bytes verbatim")
	}
	if bytes.Contains(result.Signature, privSeed) {
		t.Fatal("ADVERSARIAL: EdDSA Signature contains the private key seed (first 32 bytes)")
	}
}

// TestAdversarial_Encrypt_NoAESKeyInCiphertext verifies that the raw AES-256
// key bytes do not appear anywhere in the ciphertext output.
func TestAdversarial_Encrypt_NoAESKeyInCiphertext(t *testing.T) {
	b := newBackendWithKey(t, "adv/aes", AlgorithmAES256GCM)

	b.mu.RLock()
	entry := b.keys["adv/aes"]
	b.mu.RUnlock()

	entry.mu.RLock()
	aesKey := make([]byte, len(entry.versions[0].aesKey))
	copy(aesKey, entry.versions[0].aesKey)
	entry.mu.RUnlock()

	plaintext := []byte("adversarial encryption test payload")
	result, err := b.Encrypt(context.Background(), "adv/aes", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Contains(result.Ciphertext, aesKey) {
		t.Fatal("ADVERSARIAL: Ciphertext contains AES key material")
	}

	// JSON-encode the EncryptResult and check again.
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(EncryptResult): %v", err)
	}
	if bytes.Contains(encoded, aesKey) {
		t.Fatal("ADVERSARIAL: JSON-encoded EncryptResult contains AES key material")
	}
}

// TestAdversarial_Decrypt_NoAESKeyInPlaintext verifies the DecryptResult
// contains only the original plaintext — the AES key does not appear in it.
func TestAdversarial_Decrypt_NoAESKeyInPlaintext(t *testing.T) {
	b := newBackendWithKey(t, "adv/aes-dec", AlgorithmAES256GCM)

	b.mu.RLock()
	entry := b.keys["adv/aes-dec"]
	b.mu.RUnlock()

	entry.mu.RLock()
	aesKey := make([]byte, len(entry.versions[0].aesKey))
	copy(aesKey, entry.versions[0].aesKey)
	entry.mu.RUnlock()

	plaintext := []byte("decrypt adversarial test")
	enc, err := b.Encrypt(context.Background(), "adv/aes-dec", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	dec, err := b.Decrypt(context.Background(), "adv/aes-dec", enc.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if bytes.Contains(dec.Plaintext, aesKey) {
		t.Fatal("ADVERSARIAL: DecryptResult.Plaintext contains AES key material")
	}
	if !bytes.Equal(dec.Plaintext, plaintext) {
		t.Fatalf("wrong plaintext: want %q, got %q", plaintext, dec.Plaintext)
	}
}

// TestAdversarial_ListKeys_NoKeyMaterial verifies that KeyMeta values returned
// by ListKeys contain no key material fields — by construction (the struct has
// no such fields) and by serialisation check.
func TestAdversarial_ListKeys_NoKeyMaterial(t *testing.T) {
	b := NewDevBackend()
	for _, alg := range []Algorithm{AlgorithmES256, AlgorithmEdDSA, AlgorithmAES256GCM} {
		if err := b.CreateKey(fmt.Sprintf("list/%s", alg), alg, "test-team"); err != nil {
			t.Fatalf("CreateKey %q: %v", alg, err)
		}
	}

	metas, err := b.ListKeys(context.Background(), KeyScope{})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(metas) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(metas))
	}

	// Collect all AES key material from inside the backend for comparison.
	var allKeyBytes [][]byte
	b.mu.RLock()
	for _, entry := range b.keys {
		entry.mu.RLock()
		for _, ver := range entry.versions {
			if ver.aesKey != nil {
				k := make([]byte, len(ver.aesKey))
				copy(k, ver.aesKey)
				allKeyBytes = append(allKeyBytes, k)
			}
			if ver.ecPrivKey != nil {
				if der, err := x509.MarshalECPrivateKey(ver.ecPrivKey); err == nil {
					allKeyBytes = append(allKeyBytes, der)
				}
			}
			if ver.edPrivKey != nil {
				k := make([]byte, len(ver.edPrivKey))
				copy(k, ver.edPrivKey)
				allKeyBytes = append(allKeyBytes, k)
			}
		}
		entry.mu.RUnlock()
	}
	b.mu.RUnlock()

	// Serialise all KeyMeta to JSON and check none of the key bytes appear.
	for _, meta := range metas {
		encoded, err := json.Marshal(meta)
		if err != nil {
			t.Fatalf("json.Marshal(KeyMeta): %v", err)
		}
		for _, keyBytes := range allKeyBytes {
			if bytes.Contains(encoded, keyBytes) {
				t.Fatalf("ADVERSARIAL: JSON-encoded KeyMeta for %q contains key material",
					meta.KeyID)
			}
		}
	}
}

// ── 4. ADVERSARIAL — error messages contain no key material ──────────────────

// TestAdversarial_ErrorMessages_NoKeyMaterial verifies that error messages
// from all Backend operations do not contain PEM headers or raw key bytes.
func TestAdversarial_ErrorMessages_NoKeyMaterial(t *testing.T) {
	b := newBackendWithKey(t, "err/es256", AlgorithmES256)

	// Extract private key bytes.
	b.mu.RLock()
	entry := b.keys["err/es256"]
	b.mu.RUnlock()
	entry.mu.RLock()
	privDER, _ := x509.MarshalECPrivateKey(entry.versions[0].ecPrivKey)
	privD := entry.versions[0].ecPrivKey.D.FillBytes(make([]byte, 32))
	entry.mu.RUnlock()

	errorCases := []struct {
		name string
		fn   func() error
	}{
		{
			name: "Sign_WrongAlgorithm",
			fn: func() error {
				_, err := b.Sign(context.Background(), "err/es256", testHash("x"), AlgorithmRS256)
				return err
			},
		},
		{
			name: "Sign_EmptyHash",
			fn: func() error {
				_, err := b.Sign(context.Background(), "err/es256", nil, AlgorithmES256)
				return err
			},
		},
		{
			name: "Sign_ShortHash",
			fn: func() error {
				_, err := b.Sign(context.Background(), "err/es256", []byte("tooshort"), AlgorithmES256)
				return err
			},
		},
		{
			name: "Sign_NotFound",
			fn: func() error {
				_, err := b.Sign(context.Background(), "nonexistent", testHash("x"), AlgorithmES256)
				return err
			},
		},
		{
			name: "Sign_WrongKeyType_EncryptionKey",
			fn: func() error {
				b2 := newBackendWithKey(t, "err/aes-for-sign", AlgorithmAES256GCM)
				_, err := b2.Sign(context.Background(), "err/aes-for-sign", testHash("x"), AlgorithmES256)
				return err
			},
		},
		{
			name: "Encrypt_WrongKeyType_SigningKey",
			fn: func() error {
				_, err := b.Encrypt(context.Background(), "err/es256", []byte("test"))
				return err
			},
		},
		{
			name: "Decrypt_MalformedCiphertext",
			fn: func() error {
				b2 := newBackendWithKey(t, "err/aes-malformed", AlgorithmAES256GCM)
				_, err := b2.Decrypt(context.Background(), "err/aes-malformed", []byte("short"))
				return err
			},
		},
		{
			name: "RotateKey_NotFound",
			fn: func() error {
				_, err := b.RotateKey(context.Background(), "nonexistent/key")
				return err
			},
		},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				// Some cases expect an error; if there's none, that may be a
				// test design issue — but it's not a key-leak.
				return
			}
			msg := err.Error()

			// No PEM headers.
			if strings.Contains(msg, "-----BEGIN") || strings.Contains(msg, "-----END") {
				t.Fatalf("ADVERSARIAL: error message contains PEM header: %q", msg)
			}
			// No private key DER bytes (as hex or raw in string representation).
			if bytes.Contains([]byte(msg), privDER) {
				t.Fatalf("ADVERSARIAL: error message contains private key DER bytes")
			}
			if bytes.Contains([]byte(msg), privD) {
				t.Fatalf("ADVERSARIAL: error message contains private key scalar D")
			}
		})
	}
}

// ── 5. Input validation ───────────────────────────────────────────────────────

func TestDevBackend_Sign_EmptyPayloadHash(t *testing.T) {
	b := newBackendWithKey(t, "val/es256", AlgorithmES256)

	_, err := b.Sign(context.Background(), "val/es256", nil, AlgorithmES256)
	if err == nil {
		t.Fatal("expected error for nil payloadHash, got nil")
	}
	_, err = b.Sign(context.Background(), "val/es256", []byte{}, AlgorithmES256)
	if err == nil {
		t.Fatal("expected error for empty payloadHash, got nil")
	}
}

func TestDevBackend_Sign_WrongHashLength(t *testing.T) {
	b := newBackendWithKey(t, "val/hash-len", AlgorithmES256)

	// 31 bytes — one short of required 32.
	_, err := b.Sign(context.Background(), "val/hash-len", make([]byte, 31), AlgorithmES256)
	if err == nil {
		t.Fatal("expected error for 31-byte hash, got nil")
	}
	// 33 bytes — one too many.
	_, err = b.Sign(context.Background(), "val/hash-len", make([]byte, 33), AlgorithmES256)
	if err == nil {
		t.Fatal("expected error for 33-byte hash, got nil")
	}
}

func TestDevBackend_Sign_KeyNotFound(t *testing.T) {
	b := NewDevBackend()

	_, err := b.Sign(context.Background(), "does/not/exist", testHash("x"), AlgorithmES256)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !isErrKeyNotFound(err) {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestDevBackend_Sign_AlgorithmMismatch(t *testing.T) {
	b := newBackendWithKey(t, "val/alg", AlgorithmES256)

	_, err := b.Sign(context.Background(), "val/alg", testHash("x"), AlgorithmEdDSA)
	if err == nil {
		t.Fatal("expected error for algorithm mismatch")
	}
	if !isErrAlgorithmMismatch(err) {
		t.Fatalf("expected ErrAlgorithmMismatch, got: %v", err)
	}
}

func TestDevBackend_Sign_WrongKeyType_EncryptionKey(t *testing.T) {
	b := newBackendWithKey(t, "val/aes", AlgorithmAES256GCM)

	_, err := b.Sign(context.Background(), "val/aes", testHash("x"), AlgorithmES256)
	if err == nil {
		t.Fatal("expected ErrKeyTypeMismatch for signing with encryption key")
	}
	if !isErrKeyTypeMismatch(err) {
		t.Fatalf("expected ErrKeyTypeMismatch, got: %v", err)
	}
}

func TestDevBackend_Encrypt_NilPlaintext(t *testing.T) {
	b := newBackendWithKey(t, "val/enc-nil", AlgorithmAES256GCM)

	_, err := b.Encrypt(context.Background(), "val/enc-nil", nil)
	if err == nil {
		t.Fatal("expected error for nil plaintext, got nil")
	}
}

func TestDevBackend_Encrypt_WrongKeyType_SigningKey(t *testing.T) {
	b := newBackendWithKey(t, "val/enc-sign", AlgorithmES256)

	_, err := b.Encrypt(context.Background(), "val/enc-sign", []byte("data"))
	if err == nil {
		t.Fatal("expected ErrKeyTypeMismatch for encrypting with signing key")
	}
	if !isErrKeyTypeMismatch(err) {
		t.Fatalf("expected ErrKeyTypeMismatch, got: %v", err)
	}
}

func TestDevBackend_Decrypt_TruncatedCiphertext(t *testing.T) {
	b := newBackendWithKey(t, "val/dec-trunc", AlgorithmAES256GCM)

	// Anything shorter than 32 bytes must be rejected.
	for _, length := range []int{0, 1, 15, 31} {
		_, err := b.Decrypt(context.Background(), "val/dec-trunc", make([]byte, length))
		if err == nil {
			t.Fatalf("expected error for %d-byte ciphertext, got nil", length)
		}
	}
}

func TestDevBackend_Decrypt_TamperedCiphertext(t *testing.T) {
	b := newBackendWithKey(t, "val/dec-tamper", AlgorithmAES256GCM)
	plaintext := []byte("tamper test")

	enc, err := b.Encrypt(context.Background(), "val/dec-tamper", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a bit in the ciphertext (after the 4+12 byte header).
	tampered := make([]byte, len(enc.Ciphertext))
	copy(tampered, enc.Ciphertext)
	tampered[16] ^= 0xFF // flip bits in the first ciphertext byte

	_, err = b.Decrypt(context.Background(), "val/dec-tamper", tampered)
	if err == nil {
		t.Fatal("expected authentication failure for tampered ciphertext, got nil error")
	}
}

func TestDevBackend_Decrypt_WrongKeyType_SigningKey(t *testing.T) {
	b := newBackendWithKey(t, "val/dec-sign", AlgorithmES256)
	// Construct a syntactically valid-length ciphertext (all zeros).
	_, err := b.Decrypt(context.Background(), "val/dec-sign", make([]byte, 64))
	if err == nil {
		t.Fatal("expected ErrKeyTypeMismatch for decrypting with signing key")
	}
	if !isErrKeyTypeMismatch(err) {
		t.Fatalf("expected ErrKeyTypeMismatch, got: %v", err)
	}
}

func TestDevBackend_CreateKey_EmptyID(t *testing.T) {
	b := NewDevBackend()

	err := b.CreateKey("", AlgorithmES256, "team")
	if err == nil {
		t.Fatal("expected error for empty keyID, got nil")
	}
}

func TestDevBackend_CreateKey_Duplicate(t *testing.T) {
	b := newBackendWithKey(t, "dup/key", AlgorithmES256)

	err := b.CreateKey("dup/key", AlgorithmES256, "team")
	if err == nil {
		t.Fatal("expected error for duplicate key creation, got nil")
	}
}

func TestDevBackend_RotateKey_NotFound(t *testing.T) {
	b := NewDevBackend()

	_, err := b.RotateKey(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected ErrKeyNotFound")
	}
	if !isErrKeyNotFound(err) {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

// ── 6. Concurrency ────────────────────────────────────────────────────────────

// TestDevBackend_Concurrent_Sign verifies that concurrent Sign calls on the
// same key do not race or corrupt each other.
func TestDevBackend_Concurrent_Sign(t *testing.T) {
	b := newBackendWithKey(t, "conc/sign", AlgorithmES256)
	hash := testHash("concurrent sign test")

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := b.Sign(context.Background(), "conc/sign", hash, AlgorithmES256)
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: Sign error: %v", i, err)
		}
	}
}

// TestDevBackend_Concurrent_EncryptDecrypt verifies concurrent encrypt and
// decrypt operations do not corrupt data or race on internal state.
func TestDevBackend_Concurrent_EncryptDecrypt(t *testing.T) {
	b := newBackendWithKey(t, "conc/enc", AlgorithmAES256GCM)
	plaintext := []byte("concurrent encrypt/decrypt test")

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			enc, err := b.Encrypt(context.Background(), "conc/enc", plaintext)
			if err != nil {
				errs[idx] = fmt.Errorf("Encrypt: %w", err)
				return
			}
			dec, err := b.Decrypt(context.Background(), "conc/enc", enc.Ciphertext)
			if err != nil {
				errs[idx] = fmt.Errorf("Decrypt: %w", err)
				return
			}
			if !bytes.Equal(dec.Plaintext, plaintext) {
				errs[idx] = fmt.Errorf("plaintext mismatch")
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}

// TestDevBackend_Concurrent_RotateAndSign verifies that RotateKey and Sign
// can run concurrently without data races or panics.
func TestDevBackend_Concurrent_RotateAndSign(t *testing.T) {
	b := newBackendWithKey(t, "conc/rotate", AlgorithmES256)
	hash := testHash("rotate+sign concurrent")

	var wg sync.WaitGroup

	// One goroutine rotates repeatedly.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			if _, err := b.RotateKey(context.Background(), "conc/rotate"); err != nil {
				t.Errorf("RotateKey: %v", err)
			}
		}
	}()

	// Many goroutines sign concurrently.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = b.Sign(context.Background(), "conc/rotate", hash, AlgorithmES256)
		}()
	}
	wg.Wait()
}

// ── 7. ListKeys / RotateKey metadata correctness ─────────────────────────────

func TestDevBackend_ListKeys_Scope_Prefix(t *testing.T) {
	b := NewDevBackend()
	keys := map[string]Algorithm{
		"payments/signing":   AlgorithmES256,
		"payments/encrypt":   AlgorithmAES256GCM,
		"ml/signing":         AlgorithmEdDSA,
		"infrastructure/key": AlgorithmES256,
	}
	for id, alg := range keys {
		if err := b.CreateKey(id, alg, "test-team"); err != nil {
			t.Fatalf("CreateKey %q: %v", id, err)
		}
	}

	metas, err := b.ListKeys(context.Background(), KeyScope{Prefix: "payments/"})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("expected 2 keys with prefix 'payments/', got %d", len(metas))
	}
	for _, m := range metas {
		if !strings.HasPrefix(m.KeyID, "payments/") {
			t.Fatalf("key %q does not have prefix 'payments/'", m.KeyID)
		}
	}
}

func TestDevBackend_ListKeys_Scope_TeamID(t *testing.T) {
	b := NewDevBackend()
	if err := b.CreateKey("team-a/key", AlgorithmES256, "team-a"); err != nil {
		t.Fatal(err)
	}
	if err := b.CreateKey("team-b/key", AlgorithmES256, "team-b"); err != nil {
		t.Fatal(err)
	}

	metas, err := b.ListKeys(context.Background(), KeyScope{TeamID: "team-a"})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(metas) != 1 || metas[0].KeyID != "team-a/key" {
		t.Fatalf("expected only team-a/key, got: %+v", metas)
	}
}

func TestDevBackend_ListKeys_NoKeysCreated(t *testing.T) {
	b := NewDevBackend()

	metas, err := b.ListKeys(context.Background(), KeyScope{})
	if err != nil {
		t.Fatalf("ListKeys on empty backend: %v", err)
	}
	if len(metas) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(metas))
	}
}

func TestDevBackend_RotateKey_MetadataCorrect(t *testing.T) {
	b := newBackendWithKey(t, "meta/key", AlgorithmEdDSA)

	meta1, err := b.RotateKey(context.Background(), "meta/key")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if meta1.Version != 2 {
		t.Fatalf("expected version 2, got %d", meta1.Version)
	}
	if meta1.RotatedAt == nil {
		t.Fatal("RotatedAt must not be nil after rotation")
	}
	if meta1.Algorithm != AlgorithmEdDSA {
		t.Fatalf("expected EdDSA algorithm, got %q", meta1.Algorithm)
	}
	if meta1.KeyID != "meta/key" {
		t.Fatalf("expected KeyID 'meta/key', got %q", meta1.KeyID)
	}
	if meta1.TeamID != "test-team" {
		t.Fatalf("expected TeamID 'test-team', got %q", meta1.TeamID)
	}
}

// ── 8. Context cancellation ───────────────────────────────────────────────────

func TestDevBackend_Sign_CancelledContext(t *testing.T) {
	b := newBackendWithKey(t, "ctx/sign", AlgorithmES256)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := b.Sign(ctx, "ctx/sign", testHash("cancelled"), AlgorithmES256)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestDevBackend_Encrypt_CancelledContext(t *testing.T) {
	b := newBackendWithKey(t, "ctx/enc", AlgorithmAES256GCM)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.Encrypt(ctx, "ctx/enc", []byte("data"))
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestDevBackend_Decrypt_CancelledContext(t *testing.T) {
	b := newBackendWithKey(t, "ctx/dec", AlgorithmAES256GCM)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A syntactically valid-length ciphertext (all zeros, 32 bytes minimum).
	_, err := b.Decrypt(ctx, "ctx/dec", make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestDevBackend_ListKeys_CancelledContext(t *testing.T) {
	b := newBackendWithKey(t, "ctx/list", AlgorithmES256)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.ListKeys(ctx, KeyScope{})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestDevBackend_RotateKey_CancelledContext(t *testing.T) {
	b := newBackendWithKey(t, "ctx/rotate", AlgorithmES256)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.RotateKey(ctx, "ctx/rotate")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// ── 9. Additional adversarial tests ──────────────────────────────────────────

// TestAdversarial_RotateKey_NoKeyMaterialInResult verifies that the KeyMeta
// returned by RotateKey — which reflects a freshly generated key version —
// contains no key material from either the old or the new key version.
//
// This is the "rotate and leak" attack surface: a buggy implementation could
// accidentally embed new key material in the returned metadata.
func TestAdversarial_RotateKey_NoKeyMaterialInResult(t *testing.T) {
	b := newBackendWithKey(t, "adv/rotate-meta", AlgorithmES256)

	// Rotate the key — this generates a fresh EC key (version 2).
	meta, err := b.RotateKey(context.Background(), "adv/rotate-meta")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if meta.Version != 2 {
		t.Fatalf("expected version 2, got %d", meta.Version)
	}

	// Collect raw key material from both versions inside the backend.
	var allKeyBytes [][]byte
	b.mu.RLock()
	entry := b.keys["adv/rotate-meta"]
	b.mu.RUnlock()

	entry.mu.RLock()
	for _, ver := range entry.versions {
		if ver.ecPrivKey != nil {
			if der, err2 := x509.MarshalECPrivateKey(ver.ecPrivKey); err2 == nil {
				allKeyBytes = append(allKeyBytes, der)
			}
			privD := ver.ecPrivKey.D.FillBytes(make([]byte, 32))
			allKeyBytes = append(allKeyBytes, privD)
		}
		if ver.aesKey != nil {
			k := make([]byte, len(ver.aesKey))
			copy(k, ver.aesKey)
			allKeyBytes = append(allKeyBytes, k)
		}
		if ver.edPrivKey != nil {
			k := make([]byte, len(ver.edPrivKey))
			copy(k, ver.edPrivKey)
			allKeyBytes = append(allKeyBytes, k[:32]) // seed
		}
	}
	entry.mu.RUnlock()

	// JSON-encode the returned KeyMeta and check none of the key bytes appear.
	encoded, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("json.Marshal(KeyMeta): %v", err)
	}
	for _, keyBytes := range allKeyBytes {
		if bytes.Contains(encoded, keyBytes) {
			t.Fatalf("ADVERSARIAL: JSON-encoded RotateKey KeyMeta contains key material")
		}
	}
}

// TestAdversarial_Decrypt_SpoofedVersion verifies that attacker-controlled
// ciphertext bytes with manipulated version fields do not cause panics and
// return a proper error instead.
//
// Attack scenario: an attacker intercepts ciphertext and modifies the 4-byte
// version header to reference a version that does not exist.  The backend
// must return ErrInvalidInput without panicking or producing garbage output.
func TestAdversarial_Decrypt_SpoofedVersion(t *testing.T) {
	b := newBackendWithKey(t, "adv/spoof", AlgorithmAES256GCM)

	// Build a structurally valid ciphertext (≥32 bytes) but with a spoofed
	// version header.  The content after the header is garbage — AES-GCM
	// authentication will also fail, but the version check must come first.

	// Minimum valid-length ciphertext = 4 (version) + 12 (nonce) + 16 (tag)
	bogusBody := make([]byte, 32) // 4 + 12 + 16

	versionCases := []struct {
		name    string
		version uint32
	}{
		{"version_zero", 0},
		{"version_max_uint32", ^uint32(0)}, // 4294967295
		{"version_9999", 9999},
	}

	for _, tc := range versionCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext := make([]byte, len(bogusBody))
			copy(ciphertext, bogusBody)
			// Write the spoofed version into bytes [0:4].
			ciphertext[0] = byte(tc.version >> 24)
			ciphertext[1] = byte(tc.version >> 16)
			ciphertext[2] = byte(tc.version >> 8)
			ciphertext[3] = byte(tc.version)

			_, err := b.Decrypt(context.Background(), "adv/spoof", ciphertext)
			if err == nil {
				t.Fatalf("ADVERSARIAL: Decrypt with spoofed version %d returned nil error",
					tc.version)
			}
			// Must be ErrInvalidInput — not a panic, not a silent success.
			if !isErrInvalidInput(err) {
				t.Fatalf("ADVERSARIAL: expected ErrInvalidInput for version %d, got: %v",
					tc.version, err)
			}
			// Error message must not contain PEM headers or internal state.
			msg := err.Error()
			if strings.Contains(msg, "-----BEGIN") || strings.Contains(msg, "-----END") {
				t.Fatalf("ADVERSARIAL: error message for spoofed version contains PEM header: %q", msg)
			}
		})
	}
}

// TestAdversarial_Sign_EdDSA_NoPrivateKeyInJSONResult verifies that the
// JSON-encoded SignResult for EdDSA does not contain the private key seed
// or the full 64-byte private key bytes.  (ES256 and AES have this check;
// EdDSA was missing it.)
func TestAdversarial_Sign_EdDSA_NoPrivateKeyInJSONResult(t *testing.T) {
	b := newBackendWithKey(t, "adv/eddsa-json", AlgorithmEdDSA)

	b.mu.RLock()
	entry := b.keys["adv/eddsa-json"]
	b.mu.RUnlock()

	entry.mu.RLock()
	privKey := entry.versions[0].edPrivKey
	privSeed := make([]byte, 32)
	copy(privSeed, privKey[:32]) // Ed25519 seed = first 32 bytes
	privAll := make([]byte, len(privKey))
	copy(privAll, privKey)
	entry.mu.RUnlock()

	hash := testHash("adversarial EdDSA JSON test")
	result, err := b.Sign(context.Background(), "adv/eddsa-json", hash, AlgorithmEdDSA)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(SignResult): %v", err)
	}
	if bytes.Contains(encoded, privAll) {
		t.Fatal("ADVERSARIAL: JSON-encoded EdDSA SignResult contains full private key bytes")
	}
	if bytes.Contains(encoded, privSeed) {
		t.Fatal("ADVERSARIAL: JSON-encoded EdDSA SignResult contains private key seed")
	}
}

// TestDevBackend_CreateKey_UnsupportedAlgorithm verifies that CreateKey
// returns an error (wrapping ErrInvalidInput) for an unrecognised algorithm
// and does not create a partial key entry in the backend.
func TestDevBackend_CreateKey_UnsupportedAlgorithm(t *testing.T) {
	b := NewDevBackend()

	err := b.CreateKey("bad/alg", Algorithm("UNSUPPORTED_ALG"), "test-team")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
	if !isErrInvalidInput(err) {
		t.Fatalf("expected ErrInvalidInput for unsupported algorithm, got: %v", err)
	}

	// The failed CreateKey must NOT have left a partial entry in the backend.
	_, lookupErr := b.Sign(context.Background(), "bad/alg", testHash("x"), AlgorithmES256)
	if lookupErr == nil {
		t.Fatal("ADVERSARIAL: partial key entry exists after failed CreateKey")
	}
	if !isErrKeyNotFound(lookupErr) {
		t.Fatalf("expected ErrKeyNotFound for partial key, got: %v", lookupErr)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isErrKeyNotFound(err error) bool {
	return containsSentinel(err, ErrKeyNotFound)
}

func isErrAlgorithmMismatch(err error) bool {
	return containsSentinel(err, ErrAlgorithmMismatch)
}

func isErrKeyTypeMismatch(err error) bool {
	return containsSentinel(err, ErrKeyTypeMismatch)
}

func isErrInvalidInput(err error) bool {
	return containsSentinel(err, ErrInvalidInput)
}

// containsSentinel unwraps err checking for target using errors.Is.
// Using the errors package directly avoids an import cycle.
func containsSentinel(err, target error) bool {
	// Walk the error chain manually to avoid importing "errors" from a
	// different package — we're already in package backend.
	for err != nil {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return false
}

// generateTestPayload produces a random 32-byte hash for use in tests.
func generateTestPayload(t *testing.T) []byte {
	t.Helper()
	h := make([]byte, 32)
	if _, err := rand.Read(h); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return h
}
