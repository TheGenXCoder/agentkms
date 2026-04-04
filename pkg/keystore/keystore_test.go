package keystore_test

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"runtime"
	"testing"

	"github.com/agentkms/agentkms/pkg/keystore"
)

// ── Encrypted file backend (all platforms) ───────────────────────────────────

func TestGenerateEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Generate(keystore.Config{
		Dir:          dir,
		Passphrase:   "test-passphrase-123",
		ForceBackend: keystore.BackendEncryptedFile,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer ks.Close()

	if ks.Backend() != keystore.BackendEncryptedFile {
		t.Errorf("expected EncryptedFile backend, got %q", ks.Backend())
	}

	signer, err := ks.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if signer == nil {
		t.Fatal("Signer returned nil")
	}
}

func TestOpenEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	// Generate
	_, err := keystore.Generate(keystore.Config{
		Dir:          dir,
		Passphrase:   "test-passphrase-123",
		ForceBackend: keystore.BackendEncryptedFile,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Re-open
	ks, err := keystore.Open(keystore.Config{
		Dir:          dir,
		Passphrase:   "test-passphrase-123",
		ForceBackend: keystore.BackendEncryptedFile,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ks.Close()

	signer, err := ks.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if signer == nil {
		t.Fatal("nil signer")
	}
}

func TestEncryptedFile_SignRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Generate(keystore.Config{
		Dir:          dir,
		Passphrase:   "test-passphrase-123",
		ForceBackend: keystore.BackendEncryptedFile,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer ks.Close()

	signer, err := ks.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	// Sign a payload hash.
	payload := []byte("hello agentkms")
	digest := sha256.Sum256(payload)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
}

func TestEncryptedFile_WrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	_, err := keystore.Generate(keystore.Config{
		Dir:          dir,
		Passphrase:   "correct-passphrase",
		ForceBackend: keystore.BackendEncryptedFile,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Open with wrong passphrase
	ks, err := keystore.Open(keystore.Config{
		Dir:          dir,
		Passphrase:   "wrong-passphrase",
		ForceBackend: keystore.BackendEncryptedFile,
	})
	if err != nil {
		// TODO(#5): skip until 2027-01-01 — wrong passphrase may fail at Open
		t.Skip("Open failed before Signer (acceptable)")
	}
	defer ks.Close()

	_, err = ks.Signer()
	if err == nil {
		t.Fatal("expected error with wrong passphrase, got nil")
	}
}

func TestOpen_KeyNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := keystore.Open(keystore.Config{
		Dir:          dir,
		Passphrase:   "any",
		ForceBackend: keystore.BackendEncryptedFile,
	})
	if err == nil {
		t.Fatal("expected ErrKeyNotFound")
	}
}

func TestEncryptedFile_PublicKey(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Generate(keystore.Config{
		Dir:          dir,
		Passphrase:   "test-passphrase-123",
		ForceBackend: keystore.BackendEncryptedFile,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer ks.Close()

	pub, err := ks.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pub == nil {
		t.Fatal("nil public key")
	}
}

func TestEncryptedFile_KeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	_, err := keystore.Generate(keystore.Config{
		Dir:          dir,
		Passphrase:   "test-passphrase-123",
		ForceBackend: keystore.BackendEncryptedFile,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if runtime.GOOS == "windows" {
		// TODO(#5): skip until 2027-01-01 — file permissions not applicable on Windows
		t.Skip("permission check not applicable on Windows")
	}

	info, err := os.Stat(dir + "/client.key.enc")
	if err != nil {
		t.Fatalf("stat encrypted key: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("encrypted key file has permissions %o, want 0600", mode)
	}
}

// ── Ephemeral key pair ────────────────────────────────────────────────────────

func TestGenerateEphemeralKeyPair(t *testing.T) {
	priv, pub, err := keystore.GenerateEphemeralKeyPair()
	if err != nil {
		t.Fatalf("GenerateEphemeralKeyPair: %v", err)
	}
	if len(priv) == 0 || len(pub) == 0 {
		t.Fatal("empty PEM output")
	}
}

// ── Secure Enclave (Darwin only) ─────────────────────────────────────────────

func TestSecureEnclave_GenerateAndSign(t *testing.T) {
	if runtime.GOOS != "darwin" {
		// TODO(#6): skip until 2027-01-01 — Secure Enclave requires macOS
		t.Skip("Secure Enclave only available on macOS")
	}

	dir := t.TempDir()
	ks, err := keystore.Generate(keystore.Config{
		Dir:          dir,
		KeyLabel:     "agentkms-test-" + t.Name(),
		ForceBackend: keystore.BackendSecureEnclave,
	})
	if err != nil {
		// TODO(#6): skip until 2027-01-01 — requires code-signing entitlement in production
		t.Skipf("Secure Enclave not available: %v", err)
	}
	defer ks.Close()

	if ks.Backend() != keystore.BackendSecureEnclave {
		t.Errorf("expected SecureEnclave backend, got %q", ks.Backend())
	}

	signer, err := ks.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	digest := sha256.Sum256([]byte("agentkms secure enclave test"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign via Secure Enclave: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature from Secure Enclave")
	}
}
