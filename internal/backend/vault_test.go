// Package backend — unit tests for VaultBackend.
package backend

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewVaultBackend_MissingAddress(t *testing.T) {
	_, err := NewVaultBackend(VaultConfig{Token: "root"})
	if err == nil {
		t.Fatal("expected error for empty Address")
	}
}

func TestNewVaultBackend_MissingToken(t *testing.T) {
	_, err := NewVaultBackend(VaultConfig{Address: "http://127.0.0.1:8200"})
	if err == nil {
		t.Fatal("expected error for empty Token")
	}
}

// ── SECURITY: Token must not appear in JSON serialisation ─────────────────────

func TestAdversarial_VaultConfig_TokenNotInJSON(t *testing.T) {
	const secret = "hvs.super-secret-vault-token-CCCC9999"
	cfg := VaultConfig{
		Address:   "http://127.0.0.1:8200",
		Token:     secret,
		MountPath: "transit",
		Namespace: "admin",
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal(VaultConfig): %v", err)
	}

	if strings.Contains(string(encoded), secret) {
		t.Fatalf("ADVERSARIAL: Token appears in JSON-encoded VaultConfig: %s", encoded)
	}
}

func TestAdversarial_VaultBackend_TokenNotInError(t *testing.T) {
	const secret = "hvs.sensitive-token-DDDD0000"

	_, err := NewVaultBackend(VaultConfig{
		Address: "", // triggers "Address must not be empty" error
		Token:   secret,
	})
	if err == nil {
		t.Fatal("expected construction error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("ADVERSARIAL: token appears in error message: %q", err.Error())
	}
}
