// Package backend — HashiCorp Vault Transit backend implementation.
//
// B-03: Implements the Backend interface against the HashiCorp Vault Transit
// secrets engine.  This implementation is separate from the OpenBao backend
// to allow for divergent configuration and namespace handling as the two
// projects evolve.
//
// Dependency rationale: This file uses only the Go standard library.
// No external Vault SDK is imported to minimize the supply chain surface.
//
// SECURITY INVARIANTS:
//   - No method returns, logs, or stores key material.
//   - Transit API responses that contain key material are NEVER called.
//   - Error messages contain only key IDs and HTTP status codes.
package backend

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
)

// VaultConfig holds configuration for the HashiCorp Vault backend.
// It is structurally identical to OpenBaoConfig but kept separate to allow
// for future Vault-specific extensions (e.g. specialized auth methods).
type VaultConfig struct {
	// Address is the base URL of the Vault server.
	Address string

	// Token is the Vault token used for authentication.
	// SECURITY: json:"-" prevents accidental exposure.
	Token string `json:"-"`

	// TLSConfig is the TLS configuration for the Vault client.
	TLSConfig *tls.Config

	// MountPath is the path where the Transit engine is mounted.
	// Defaults to "transit".
	MountPath string

	// Namespace is the Vault Enterprise namespace.
	Namespace string

	// HTTPClient overrides the default client.
	HTTPClient *http.Client
}

func (c *VaultConfig) mountPath() string {
	mp := c.MountPath
	if mp == "" {
		mp = "transit"
	}
	return strings.Trim(mp, "/")
}

// VaultBackend implements Backend against HashiCorp Vault.
type VaultBackend struct {
	// VaultBackend delegates most logic to an internal OpenBaoBackend
	// instance, as the Transit API is currently compatible between both.
	// This wrapper ensures we can specialize Vault-specific logic here
	// without affecting the OpenBao implementation.
	inner *OpenBaoBackend
}

// NewVaultBackend constructs a VaultBackend from cfg.
func NewVaultBackend(cfg VaultConfig) (*VaultBackend, error) {
	// Map VaultConfig to OpenBaoConfig for the internal implementation.
	obCfg := OpenBaoConfig{
		Address:    cfg.Address,
		Token:      cfg.Token,
		TLSConfig:  cfg.TLSConfig,
		MountPath:  cfg.MountPath,
		Namespace:  cfg.Namespace,
		HTTPClient: cfg.HTTPClient,
	}

	inner, err := NewOpenBaoBackend(obCfg)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}

	return &VaultBackend{inner: inner}, nil
}

func (b *VaultBackend) Sign(ctx context.Context, keyID string, payloadHash []byte, alg Algorithm) (*SignResult, error) {
	return b.inner.Sign(ctx, keyID, payloadHash, alg)
}

func (b *VaultBackend) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptResult, error) {
	return b.inner.Encrypt(ctx, keyID, plaintext)
}

func (b *VaultBackend) Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*DecryptResult, error) {
	return b.inner.Decrypt(ctx, keyID, ciphertext)
}

func (b *VaultBackend) ListKeys(ctx context.Context, scope KeyScope) ([]*KeyMeta, error) {
	return b.inner.ListKeys(ctx, scope)
}

func (b *VaultBackend) RotateKey(ctx context.Context, keyID string) (*KeyMeta, error) {
	return b.inner.RotateKey(ctx, keyID)
}

// CreateTransitKey is an admin helper for tests/setup.
func (b *VaultBackend) CreateTransitKey(ctx context.Context, keyID string, alg Algorithm, teamID string) error {
	return b.inner.CreateTransitKey(ctx, keyID, alg, teamID)
}
