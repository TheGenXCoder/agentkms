package ghsecret

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// TestEncrypt_RoundTrip generates a real Curve25519 keypair, encrypts a known
// plaintext, then decrypts with OpenAnonymous and verifies the recovered message.
func TestEncrypt_RoundTrip(t *testing.T) {
	t.Parallel()

	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Encode the public key as base64 (as GitHub would return it).
	pubKeyB64 := base64.StdEncoding.EncodeToString(recipientPub[:])

	plaintext := []byte("super-secret-database-password-12345")

	// Encrypt.
	ciphertext, err := Seal(plaintext, pubKeyB64)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("Seal returned empty ciphertext")
	}

	// Decrypt using OpenAnonymous.
	recovered, ok := box.OpenAnonymous(nil, ciphertext, recipientPub, recipientPriv)
	if !ok {
		t.Fatal("OpenAnonymous: decryption failed")
	}
	if string(recovered) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", recovered, plaintext)
	}
}

// TestEncrypt_Base64Variants verifies that both standard and URL-safe base64
// are accepted as input for the public key.
func TestEncrypt_Base64Variants(t *testing.T) {
	t.Parallel()

	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Standard base64.
	stdB64 := base64.StdEncoding.EncodeToString(pub[:])
	if _, err := Seal([]byte("hello"), stdB64); err != nil {
		t.Errorf("Seal with StdEncoding failed: %v", err)
	}

	// URL-safe base64 (no padding).
	urlB64 := base64.RawURLEncoding.EncodeToString(pub[:])
	if _, err := Seal([]byte("hello"), urlB64); err != nil {
		t.Errorf("Seal with RawURLEncoding failed: %v", err)
	}
}

// TestEncrypt_InvalidKey verifies that a garbage base64 key returns an error.
func TestEncrypt_InvalidKey(t *testing.T) {
	t.Parallel()

	_, err := Seal([]byte("hello"), "not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64 key, got nil")
	}
}

// TestEncrypt_WrongKeyLength verifies that a key that is not 32 bytes is rejected.
func TestEncrypt_WrongKeyLength(t *testing.T) {
	t.Parallel()

	shortKey := base64.StdEncoding.EncodeToString([]byte("too-short"))
	_, err := Seal([]byte("hello"), shortKey)
	if err == nil {
		t.Fatal("expected error for short key, got nil")
	}
}

// TestSealBase64_Format verifies that SealBase64 returns valid base64.
func TestSealBase64_Format(t *testing.T) {
	t.Parallel()

	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])

	b64ct, err := SealBase64([]byte("test"), pubB64)
	if err != nil {
		t.Fatalf("SealBase64: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(b64ct); err != nil {
		t.Errorf("SealBase64 output is not valid base64: %v", err)
	}
}
