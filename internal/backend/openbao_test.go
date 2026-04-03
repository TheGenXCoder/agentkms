// Package backend — unit tests for OpenBaoBackend that do not require a
// running Vault instance.  Integration tests are in openbao_integration_test.go
// (build tag: integration).
package backend

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ── Config / construction ──────────────────────────────────────────────────────

func TestNewOpenBaoBackend_MissingAddress(t *testing.T) {
	_, err := NewOpenBaoBackend(OpenBaoConfig{Token: "root"})
	if err == nil {
		t.Fatal("expected error for empty Address")
	}
}

func TestNewOpenBaoBackend_MissingToken(t *testing.T) {
	_, err := NewOpenBaoBackend(OpenBaoConfig{Address: "http://127.0.0.1:8200"})
	if err == nil {
		t.Fatal("expected error for empty Token")
	}
}

func TestNewOpenBaoBackend_DefaultMountPath(t *testing.T) {
	b, err := NewOpenBaoBackend(OpenBaoConfig{
		Address: "http://127.0.0.1:8200",
		Token:   "root",
	})
	if err != nil {
		t.Fatalf("NewOpenBaoBackend: %v", err)
	}
	if b.mount != "transit" {
		t.Fatalf("expected default mount 'transit', got %q", b.mount)
	}
}

func TestNewOpenBaoBackend_CustomMountPath(t *testing.T) {
	b, err := NewOpenBaoBackend(OpenBaoConfig{
		Address:   "http://127.0.0.1:8200",
		Token:     "root",
		MountPath: "/custom-transit/",
	})
	if err != nil {
		t.Fatalf("NewOpenBaoBackend: %v", err)
	}
	// Leading and trailing slashes must be stripped.
	if b.mount != "custom-transit" {
		t.Fatalf("expected mount 'custom-transit', got %q", b.mount)
	}
}

// ── SECURITY: Token must not appear in JSON serialisation ─────────────────────

// TestAdversarial_OpenBaoConfig_TokenNotInJSON verifies that json.Marshal of
// OpenBaoConfig does not expose the Vault token.
//
// Attack scenario: a developer logs config structs for debugging (e.g. with
// fmt.Printf("%+v", cfg) or encoding/json).  Without json:"-" on the Token
// field the token would appear in the output and potentially in log sinks,
// violating the zero-key-exposure guarantee (tokens are key material).
func TestAdversarial_OpenBaoConfig_TokenNotInJSON(t *testing.T) {
	const secret = "s.super-secret-vault-token-AAAA1234"
	cfg := OpenBaoConfig{
		Address:   "http://127.0.0.1:8200",
		Token:     secret,
		MountPath: "transit",
		Namespace: "ns1",
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal(OpenBaoConfig): %v", err)
	}

	if strings.Contains(string(encoded), secret) {
		t.Fatalf("ADVERSARIAL: Token appears in JSON-encoded OpenBaoConfig: %s", encoded)
	}
	// Also check that no substring of the token leaks (partial match).
	tokenSubstring := secret[5:20] // "uper-secret-vault"
	if strings.Contains(string(encoded), tokenSubstring) {
		t.Fatalf("ADVERSARIAL: Token substring appears in JSON-encoded OpenBaoConfig: %s", encoded)
	}
}

// TestAdversarial_OpenBaoBackend_TokenNotInError verifies that error messages
// from NewOpenBaoBackend do not include the token string.
func TestAdversarial_OpenBaoBackend_TokenNotInError(t *testing.T) {
	// A deliberately bad address to trigger a construction error path.
	// The token should never appear in any error from the backend.
	const secret = "s.sensitive-token-BBBB5678"

	_, err := NewOpenBaoBackend(OpenBaoConfig{
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

// ── Algorithm / type mapping ──────────────────────────────────────────────────

func TestAlgorithmToTransitType_AllSupported(t *testing.T) {
	cases := []struct {
		alg      Algorithm
		wantType string
	}{
		{AlgorithmES256, "ecdsa-p256"},
		{AlgorithmRS256, "rsa-2048"},
		{AlgorithmEdDSA, "ed25519"},
		{AlgorithmAES256GCM, "aes256-gcm96"},
	}
	for _, tc := range cases {
		got, err := algorithmToTransitType(tc.alg)
		if err != nil {
			t.Errorf("algorithmToTransitType(%q): unexpected error: %v", tc.alg, err)
			continue
		}
		if got != tc.wantType {
			t.Errorf("algorithmToTransitType(%q): want %q, got %q", tc.alg, tc.wantType, got)
		}
	}
}

// TestAlgorithmToTransitType_RSAOAEPReturnsError verifies that
// AlgorithmRSAOAEPSHA256 is explicitly rejected.
//
// Vault Transit uses the same "rsa-2048" key type for both RS256 signing and
// RSA-OAEP encryption, but OpenBaoBackend always maps "rsa-2048" →
// AlgorithmRS256.  AlgorithmRSAOAEPSHA256 is therefore unsupported through
// this backend; callers must use AlgorithmAES256GCM for symmetric encryption
// or target an AWS KMS / Azure Key Vault backend for RSA-OAEP.
func TestAlgorithmToTransitType_RSAOAEPReturnsError(t *testing.T) {
	_, err := algorithmToTransitType(AlgorithmRSAOAEPSHA256)
	if err == nil {
		t.Fatal("expected error for AlgorithmRSAOAEPSHA256, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got: %v", err)
	}
}

func TestAlgorithmToTransitType_Unsupported(t *testing.T) {
	_, err := algorithmToTransitType(Algorithm("UNSUPPORTED"))
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got: %v", err)
	}
}

func TestTransitTypeToAlgorithm_AllSupported(t *testing.T) {
	cases := []struct {
		keyType string
		wantAlg Algorithm
	}{
		{"ecdsa-p256", AlgorithmES256},
		{"rsa-2048", AlgorithmRS256},
		{"ed25519", AlgorithmEdDSA},
		{"aes256-gcm96", AlgorithmAES256GCM},
	}
	for _, tc := range cases {
		got, err := transitTypeToAlgorithm(tc.keyType)
		if err != nil {
			t.Errorf("transitTypeToAlgorithm(%q): unexpected error: %v", tc.keyType, err)
			continue
		}
		if got != tc.wantAlg {
			t.Errorf("transitTypeToAlgorithm(%q): want %q, got %q", tc.keyType, tc.wantAlg, got)
		}
	}
}

func TestTransitTypeToAlgorithm_Unknown(t *testing.T) {
	_, err := transitTypeToAlgorithm("chacha20-poly1305")
	if err == nil {
		t.Fatal("expected error for unknown transit key type")
	}
}

// ── Signature parsing ─────────────────────────────────────────────────────────

func TestDecodeVaultSignature_Valid(t *testing.T) {
	// A realistic vault:vN:base64 signature string.
	// 64 bytes of zero — structurally valid standard base64.
	const sigBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	raw := "vault:v3:" + sigBase64

	sigBytes, err := decodeVaultSignature(raw)
	if err != nil {
		t.Fatalf("decodeVaultSignature: %v", err)
	}
	if len(sigBytes) == 0 {
		t.Fatal("expected non-empty signature bytes")
	}
}

func TestDecodeVaultSignature_MissingPrefix(t *testing.T) {
	_, err := decodeVaultSignature("notavaultprefix:v1:abc")
	if err == nil {
		t.Fatal("expected error for missing vault: prefix")
	}
	// Error message must not contain the raw input string.
	msg := err.Error()
	if strings.Contains(msg, "notavaultprefix") {
		t.Fatalf("error message contains raw input: %q", msg)
	}
}

func TestDecodeVaultSignature_MissingColon(t *testing.T) {
	_, err := decodeVaultSignature("vault:v1-no-colon-base64")
	if err == nil {
		t.Fatal("expected error for missing colon after version")
	}
}

func TestDecodeVaultSignature_InvalidBase64(t *testing.T) {
	_, err := decodeVaultSignature("vault:v1:!!!notbase64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	// Error message must not contain the raw invalid bytes.
	if strings.Contains(err.Error(), "!!!") {
		t.Fatalf("error message contains raw input bytes: %q", err.Error())
	}
}

// ── Error mapping ─────────────────────────────────────────────────────────────

func TestMapTransitError_404_IsKeyNotFound(t *testing.T) {
	vErr := &vaultAPIError{StatusCode: 404, Messages: []string{"key not found"}}
	err := mapTransitError(vErr, "test-key")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound for 404, got: %v", err)
	}
}

func TestMapTransitError_400_KeyNotFound(t *testing.T) {
	vErr := &vaultAPIError{StatusCode: 400, Messages: []string{"signing key not found"}}
	err := mapTransitError(vErr, "test-key")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound for 400 key not found, got: %v", err)
	}
}

func TestMapTransitError_400_AlgorithmMismatch(t *testing.T) {
	vErr := &vaultAPIError{StatusCode: 400, Messages: []string{"requested algorithm not compatible with key type"}}
	err := mapTransitError(vErr, "test-key")
	if !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("expected ErrAlgorithmMismatch for 400 algorithm message, got: %v", err)
	}
}

func TestMapTransitError_400_Default_IsInvalidInput(t *testing.T) {
	vErr := &vaultAPIError{StatusCode: 400, Messages: []string{"some unrecognised error"}}
	err := mapTransitError(vErr, "test-key")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for unclassified 400, got: %v", err)
	}
}

func TestMapTransitError_422_IsKeyTypeMismatch(t *testing.T) {
	vErr := &vaultAPIError{StatusCode: 422, Messages: []string{"operation not valid for key type"}}
	err := mapTransitError(vErr, "test-key")
	if !errors.Is(err, ErrKeyTypeMismatch) {
		t.Fatalf("expected ErrKeyTypeMismatch for 422, got: %v", err)
	}
}

func TestMapTransitError_NonVaultError_PassThrough(t *testing.T) {
	// A non-vaultAPIError should be returned unchanged.
	original := errors.New("network timeout")
	result := mapTransitError(original, "test-key")
	if result != original {
		t.Fatalf("expected original error to pass through, got: %v", result)
	}
}

func TestVaultAPIError_SafeMessage_NoKeyMaterial(t *testing.T) {
	// Vault error messages come from the server and should not contain key
	// material (they are operation descriptions, not data values).  Verify
	// that safeMessage() only joins the Messages slice.
	vErr := &vaultAPIError{
		StatusCode: 400,
		Messages:   []string{"invalid key id", "operation denied"},
	}
	msg := vErr.safeMessage()
	if msg != "invalid key id; operation denied" {
		t.Fatalf("unexpected safeMessage output: %q", msg)
	}
}
