package plugin

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
)

// Signer signs plugin binaries using Ed25519.
type Signer struct {
	privateKey ed25519.PrivateKey
}

// NewSigner creates a Signer from an Ed25519 private key.
// Returns an error if the key is invalid.
func NewSigner(privateKey []byte) (*Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key: expected %d bytes, got %d", ed25519.PrivateKeySize, len(privateKey))
	}
	return &Signer{privateKey: ed25519.PrivateKey(privateKey)}, nil
}

// Sign reads the plugin binary at pluginPath and produces a detached Ed25519 signature.
func (s *Signer) Sign(pluginPath string) ([]byte, error) {
	data, err := os.ReadFile(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin: %w", err)
	}
	sig := ed25519.Sign(s.privateKey, data)
	return sig, nil
}

// Verifier verifies plugin signatures using Ed25519.
type Verifier struct {
	publicKey ed25519.PublicKey
}

// NewVerifier creates a Verifier from an Ed25519 public key.
// Returns an error if the key is invalid.
func NewVerifier(publicKey []byte) (*Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key: expected %d bytes, got %d", ed25519.PublicKeySize, len(publicKey))
	}
	return &Verifier{publicKey: ed25519.PublicKey(publicKey)}, nil
}

// Verify checks a plugin binary against a detached signature.
// Returns nil if valid, error if invalid or missing.
func (v *Verifier) Verify(pluginPath string, signature []byte) error {
	if signature == nil {
		return errors.New("signature is nil")
	}
	data, err := os.ReadFile(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to read plugin: %w", err)
	}
	if !ed25519.Verify(v.publicKey, data, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

// VerifyStatus represents the result of a signature status check.
type VerifyStatus string

const (
	StatusSigned   VerifyStatus = "signed"
	StatusUnsigned VerifyStatus = "unsigned"
	StatusInvalid  VerifyStatus = "invalid"
)

// Status returns a human-readable verification status for a plugin binary.
func (v *Verifier) Status(pluginPath string, signature []byte) VerifyStatus {
	if signature == nil {
		return StatusUnsigned
	}
	if err := v.Verify(pluginPath, signature); err != nil {
		return StatusInvalid
	}
	return StatusSigned
}
