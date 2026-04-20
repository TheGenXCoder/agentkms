package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// helper: generate a fresh Ed25519 key pair.
func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return pub, priv
}

// helper: create a temp file with the given content and return its path.
func createTempPlugin(t *testing.T, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-plugin")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatalf("failed to write temp plugin: %v", err)
	}
	return path
}

func TestSigning_SignAndVerify_RoundTrip(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	pluginPath := createTempPlugin(t, []byte("fake plugin binary data"))

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	sig, err := signer.Sign(pluginPath)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig == nil || len(sig) == 0 {
		t.Fatal("Sign returned nil or empty signature")
	}

	verifier, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	if err := verifier.Verify(pluginPath, sig); err != nil {
		t.Fatalf("Verify should succeed for valid signature, got: %v", err)
	}
}

func TestSigning_Verify_WrongKey(t *testing.T) {
	_, privA := generateTestKeyPair(t)
	pubB, _ := generateTestKeyPair(t)
	pluginPath := createTempPlugin(t, []byte("fake plugin binary data"))

	signer, err := NewSigner(privA)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	sig, err := signer.Sign(pluginPath)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifier, err := NewVerifier(pubB)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	if err := verifier.Verify(pluginPath, sig); err == nil {
		t.Fatal("Verify should fail when using a different public key")
	}
}

func TestSigning_Verify_TamperedBinary(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	pluginPath := createTempPlugin(t, []byte("original plugin binary"))

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	sig, err := signer.Sign(pluginPath)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper with the binary after signing.
	if err := os.WriteFile(pluginPath, []byte("tampered plugin binary"), 0o755); err != nil {
		t.Fatalf("failed to tamper with plugin: %v", err)
	}

	verifier, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	if err := verifier.Verify(pluginPath, sig); err == nil {
		t.Fatal("Verify should fail for tampered binary")
	}
}

func TestSigning_Verify_NilSignature(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	pluginPath := createTempPlugin(t, []byte("fake plugin binary data"))

	verifier, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	if err := verifier.Verify(pluginPath, nil); err == nil {
		t.Fatal("Verify should fail when signature is nil")
	}
}

func TestSigning_Status_Signed(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	pluginPath := createTempPlugin(t, []byte("fake plugin binary data"))

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	sig, err := signer.Sign(pluginPath)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifier, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	status := verifier.Status(pluginPath, sig)
	if status != StatusSigned {
		t.Fatalf("Status should be %q for valid signature, got %q", StatusSigned, status)
	}
}

func TestSigning_Status_Unsigned(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	pluginPath := createTempPlugin(t, []byte("fake plugin binary data"))

	verifier, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	status := verifier.Status(pluginPath, nil)
	if status != StatusUnsigned {
		t.Fatalf("Status should be %q for nil signature, got %q", StatusUnsigned, status)
	}
}

func TestSigning_Status_Invalid(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	pluginPath := createTempPlugin(t, []byte("original plugin binary"))

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	sig, err := signer.Sign(pluginPath)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper with the binary after signing.
	if err := os.WriteFile(pluginPath, []byte("tampered plugin binary"), 0o755); err != nil {
		t.Fatalf("failed to tamper with plugin: %v", err)
	}

	verifier, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	status := verifier.Status(pluginPath, sig)
	if status != StatusInvalid {
		t.Fatalf("Status should be %q for tampered binary, got %q", StatusInvalid, status)
	}
}

func TestSigning_NewSigner_InvalidKey(t *testing.T) {
	_, err := NewSigner([]byte("garbage-not-a-valid-key"))
	if err == nil {
		t.Fatal("NewSigner should return error for invalid private key")
	}
}

func TestSigning_NewVerifier_InvalidKey(t *testing.T) {
	_, err := NewVerifier([]byte("garbage-not-a-valid-key"))
	if err == nil {
		t.Fatal("NewVerifier should return error for invalid public key")
	}
}

func TestSigning_Sign_FileNotExist(t *testing.T) {
	_, priv := generateTestKeyPair(t)

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	_, err = signer.Sign("/nonexistent/path/to/plugin")
	if err == nil {
		t.Fatal("Sign should return error for non-existent file")
	}
}
