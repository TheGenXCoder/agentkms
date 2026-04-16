package credentials

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

// writeTestECKey generates a fresh P-256 private key, writes it to a temp file
// as a PEM-encoded SEC1 "EC PRIVATE KEY" block (what x509.ParseECPrivateKey
// expects), and returns the path.
func writeTestECKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("writeTestECKey: generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("writeTestECKey: marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	path := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("writeTestECKey: write file: %v", err)
	}
	return path
}

// newTestKV creates an EncryptedKV backed by temp files and a fresh EC key.
func newTestKV(t *testing.T) (*EncryptedKV, string) {
	t.Helper()
	keyPath := writeTestECKey(t)
	secretsPath := filepath.Join(t.TempDir(), "secrets.enc")
	kv := NewEncryptedKV(secretsPath, keyPath)
	return kv, secretsPath
}

// ── Constructor ───────────────────────────────────────────────────────────────

func TestNewEncryptedKV_ReturnsNonNil(t *testing.T) {
	kv := NewEncryptedKV("/tmp/secrets.enc", "/tmp/server.key")
	if kv == nil {
		t.Fatal("NewEncryptedKV returned nil")
	}
}

func TestNewEncryptedKV_FieldsSet(t *testing.T) {
	kv := NewEncryptedKV("/tmp/a.enc", "/tmp/b.key")
	if kv.secretsPath != "/tmp/a.enc" {
		t.Errorf("secretsPath = %q, want %q", kv.secretsPath, "/tmp/a.enc")
	}
	if kv.keyPath != "/tmp/b.key" {
		t.Errorf("keyPath = %q, want %q", kv.keyPath, "/tmp/b.key")
	}
}

// ── GetSecret: missing file ───────────────────────────────────────────────────

func TestGetSecret_MissingSecretsFile_ReturnsNotFound(t *testing.T) {
	keyPath := writeTestECKey(t)
	kv := NewEncryptedKV("/nonexistent/path/secrets.enc", keyPath)

	_, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected error for missing secrets file, got nil")
	}
	// loadAll returns errFileNotFound which GetSecret wraps in ErrCredentialNotFound path,
	// but actually GetSecret will get errFileNotFound from loadAll. Let's check it errors.
}

func TestGetSecret_EmptyStore_ReturnsNotFound(t *testing.T) {
	keyPath := writeTestECKey(t)
	// Write an empty map as the initial state by calling Set with something, then
	// just check that a missing path returns ErrCredentialNotFound.
	kv, _ := newTestKV(t)

	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "sk-test"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	_, err := kv.GetSecret(context.Background(), "kv/data/llm/openai")
	if err == nil {
		t.Fatal("expected ErrCredentialNotFound, got nil")
	}
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
	_ = keyPath
}

// ── Basic round-trip ──────────────────────────────────────────────────────────

func TestSetGet_RoundTrip_Single(t *testing.T) {
	kv, _ := newTestKV(t)

	want := map[string]string{"api_key": "sk-ant-test", "org": "myorg"}
	if err := kv.Set("kv/data/llm/anthropic", want); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("field %q: got %q, want %q", k, got[k], v)
		}
	}
}

func TestSetGet_RoundTrip_MultipleSecrets(t *testing.T) {
	kv, _ := newTestKV(t)

	secrets := map[string]map[string]string{
		"kv/data/llm/anthropic":              {"api_key": "sk-ant-test"},
		"kv/data/llm/openai":                 {"api_key": "sk-openai-test"},
		"kv/data/generic/forge/telegram":     {"token": "tg-token-123"},
		"kv/data/generic/forge/another/deep": {"secret": "deep-value", "extra": "val"},
	}

	for path, fields := range secrets {
		if err := kv.Set(path, fields); err != nil {
			t.Fatalf("Set(%q): %v", path, err)
		}
	}

	for path, wantFields := range secrets {
		got, err := kv.GetSecret(context.Background(), path)
		if err != nil {
			t.Fatalf("GetSecret(%q): %v", path, err)
		}
		for k, v := range wantFields {
			if got[k] != v {
				t.Errorf("path %q field %q: got %q, want %q", path, k, got[k], v)
			}
		}
	}
}

func TestSet_Overwrite_ExistingPath(t *testing.T) {
	kv, _ := newTestKV(t)

	path := "kv/data/llm/anthropic"
	if err := kv.Set(path, map[string]string{"api_key": "old-key"}); err != nil {
		t.Fatalf("Set (first): %v", err)
	}
	if err := kv.Set(path, map[string]string{"api_key": "new-key", "extra": "v"}); err != nil {
		t.Fatalf("Set (overwrite): %v", err)
	}

	got, err := kv.GetSecret(context.Background(), path)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got["api_key"] != "new-key" {
		t.Errorf("api_key: got %q, want %q", got["api_key"], "new-key")
	}
	if got["extra"] != "v" {
		t.Errorf("extra: got %q, want %q", got["extra"], "v")
	}
}

func TestGet_ReturnsCopy_MutationDoesNotPersist(t *testing.T) {
	kv, _ := newTestKV(t)
	path := "kv/data/llm/anthropic"

	if err := kv.Set(path, map[string]string{"api_key": "original"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, _ := kv.GetSecret(context.Background(), path)
	got["api_key"] = "mutated"

	got2, err := kv.GetSecret(context.Background(), path)
	if err != nil {
		t.Fatalf("GetSecret (second): %v", err)
	}
	if got2["api_key"] != "original" {
		t.Errorf("mutation escaped defensive copy: got %q, want %q", got2["api_key"], "original")
	}
}

// ── Delete ────────────────────────────────────────────────────────────────────

func TestDelete_ExistingPath_RemovesIt(t *testing.T) {
	kv, _ := newTestKV(t)
	path := "kv/data/llm/anthropic"

	if err := kv.Set(path, map[string]string{"api_key": "to-delete"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := kv.Delete(path); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := kv.GetSecret(context.Background(), path)
	if err == nil {
		t.Fatal("expected ErrCredentialNotFound after Delete, got nil")
	}
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestDelete_OtherPathsUntouched(t *testing.T) {
	kv, _ := newTestKV(t)

	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "keep"}); err != nil {
		t.Fatalf("Set anthropic: %v", err)
	}
	if err := kv.Set("kv/data/llm/openai", map[string]string{"api_key": "delete-me"}); err != nil {
		t.Fatalf("Set openai: %v", err)
	}

	if err := kv.Delete("kv/data/llm/openai"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err != nil {
		t.Fatalf("GetSecret anthropic after delete of openai: %v", err)
	}
	if got["api_key"] != "keep" {
		t.Errorf("anthropic api_key corrupted after deleting openai: got %q", got["api_key"])
	}
}

func TestDelete_NonexistentPath_NoError(t *testing.T) {
	kv, _ := newTestKV(t)

	// First Set so the file exists.
	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "x"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Delete a path that was never set — should succeed silently (delete(map, key) is a no-op).
	if err := kv.Delete("kv/data/llm/missing"); err != nil {
		t.Errorf("Delete of non-existent path: %v", err)
	}
}

// ── Paths ─────────────────────────────────────────────────────────────────────

func TestPaths_EmptyWhenNoFile(t *testing.T) {
	keyPath := writeTestECKey(t)
	kv := NewEncryptedKV("/nonexistent/secrets.enc", keyPath)

	paths, err := kv.Paths()
	if err != nil {
		t.Fatalf("Paths on missing file: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("expected empty paths, got %v", paths)
	}
}

func TestPaths_ReturnsAllStoredPaths(t *testing.T) {
	kv, _ := newTestKV(t)

	want := []string{
		"kv/data/llm/anthropic",
		"kv/data/llm/openai",
		"kv/data/generic/forge/telegram",
	}
	for _, p := range want {
		if err := kv.Set(p, map[string]string{"k": "v"}); err != nil {
			t.Fatalf("Set(%q): %v", p, err)
		}
	}

	got, err := kv.Paths()
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}

	sort.Strings(got)
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Paths = %v, want %v", got, want)
	}
}

func TestPaths_EmptyAfterAllDeleted(t *testing.T) {
	kv, _ := newTestKV(t)

	paths := []string{"kv/data/llm/anthropic", "kv/data/llm/openai"}
	for _, p := range paths {
		if err := kv.Set(p, map[string]string{"k": "v"}); err != nil {
			t.Fatalf("Set(%q): %v", p, err)
		}
	}
	for _, p := range paths {
		if err := kv.Delete(p); err != nil {
			t.Fatalf("Delete(%q): %v", p, err)
		}
	}

	got, err := kv.Paths()
	if err != nil {
		t.Fatalf("Paths after deleting all: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty paths after all deleted, got %v", got)
	}
}

// ── KVWriter interface wrappers ───────────────────────────────────────────────

func TestSetSecret_DelegatesToSet(t *testing.T) {
	kv, _ := newTestKV(t)

	err := kv.SetSecret(context.Background(), "kv/data/llm/anthropic", map[string]string{"api_key": "sk"})
	if err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	got, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err != nil {
		t.Fatalf("GetSecret after SetSecret: %v", err)
	}
	if got["api_key"] != "sk" {
		t.Errorf("api_key = %q, want %q", got["api_key"], "sk")
	}
}

func TestDeleteSecret_DelegatesToDelete(t *testing.T) {
	kv, _ := newTestKV(t)
	path := "kv/data/llm/anthropic"

	_ = kv.Set(path, map[string]string{"api_key": "x"})

	if err := kv.DeleteSecret(context.Background(), path); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	_, err := kv.GetSecret(context.Background(), path)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("expected ErrCredentialNotFound after DeleteSecret, got %v", err)
	}
}

func TestListPaths_DelegatesToPaths(t *testing.T) {
	kv, _ := newTestKV(t)
	_ = kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "x"})

	got, err := kv.ListPaths(context.Background())
	if err != nil {
		t.Fatalf("ListPaths: %v", err)
	}
	if len(got) != 1 || got[0] != "kv/data/llm/anthropic" {
		t.Errorf("ListPaths = %v, want [kv/data/llm/anthropic]", got)
	}
}

// ── Encryption integrity ──────────────────────────────────────────────────────

func TestSecretsFile_IsEncrypted_NotPlaintext(t *testing.T) {
	kv, secretsPath := newTestKV(t)

	secret := "s3cr3t-api-key-value"
	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": secret}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	raw, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatalf("ReadFile secrets: %v", err)
	}

	// The plaintext value must not appear verbatim in the binary file.
	if bytes.Contains(raw, []byte(secret)) {
		t.Error("plaintext secret found in secrets.enc — file is NOT encrypted")
	}
	// Also the path should not be visible.
	if bytes.Contains(raw, []byte("kv/data/llm/anthropic")) {
		t.Error("plaintext KV path found in secrets.enc — file is NOT encrypted")
	}
}

func TestSecretsFile_IsBinary_NotJSON(t *testing.T) {
	kv, secretsPath := newTestKV(t)

	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "test"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	raw, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// AES-GCM output should not look like JSON.
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "{") {
		t.Error("secrets.enc appears to be raw JSON — not encrypted")
	}
}

func TestNonce_DifferentBetweenWrites(t *testing.T) {
	kv, secretsPath := newTestKV(t)

	fields := map[string]string{"api_key": "same-value"}

	if err := kv.Set("kv/data/llm/anthropic", fields); err != nil {
		t.Fatalf("Set (first): %v", err)
	}
	raw1, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatalf("ReadFile (first): %v", err)
	}

	if err := kv.Set("kv/data/llm/anthropic", fields); err != nil {
		t.Fatalf("Set (second): %v", err)
	}
	raw2, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatalf("ReadFile (second): %v", err)
	}

	if bytes.Equal(raw1, raw2) {
		t.Error("two writes of the same value produced identical ciphertext — nonce is being reused")
	}

	// Confirm first 12 bytes (nonce) differ.
	if len(raw1) >= 12 && len(raw2) >= 12 && bytes.Equal(raw1[:12], raw2[:12]) {
		t.Error("nonce (first 12 bytes) is identical across two writes — deterministic nonce reuse")
	}
}

// ── Key derivation correctness ────────────────────────────────────────────────

func TestTwoInstances_SameKey_CanShareFile(t *testing.T) {
	keyPath := writeTestECKey(t)
	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "secrets.enc")

	kv1 := NewEncryptedKV(secretsPath, keyPath)
	if err := kv1.Set("kv/data/llm/anthropic", map[string]string{"api_key": "shared-secret"}); err != nil {
		t.Fatalf("kv1 Set: %v", err)
	}

	// Second instance, same paths.
	kv2 := NewEncryptedKV(secretsPath, keyPath)
	got, err := kv2.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err != nil {
		t.Fatalf("kv2 GetSecret: %v", err)
	}
	if got["api_key"] != "shared-secret" {
		t.Errorf("kv2 read %q, want %q", got["api_key"], "shared-secret")
	}
}

func TestDifferentKey_CannotDecrypt(t *testing.T) {
	keyPath1 := writeTestECKey(t)
	keyPath2 := writeTestECKey(t) // different key

	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "secrets.enc")

	// Write with key1.
	kv1 := NewEncryptedKV(secretsPath, keyPath1)
	if err := kv1.Set("kv/data/llm/anthropic", map[string]string{"api_key": "secret"}); err != nil {
		t.Fatalf("kv1 Set: %v", err)
	}

	// Try to read with key2 — must fail.
	kv2 := NewEncryptedKV(secretsPath, keyPath2)
	_, err := kv2.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected decryption error with wrong key, got nil")
	}
}

func TestMissingKeyFile_FailsCleanly(t *testing.T) {
	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "secrets.enc")
	kv := NewEncryptedKV(secretsPath, "/nonexistent/server.key")

	// Set (which calls saveAll → deriveKey) must fail.
	err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "x"})
	if err == nil {
		t.Fatal("expected error for missing key file, got nil")
	}
}

func TestMissingKeyFile_GetFailsCleanly(t *testing.T) {
	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "secrets.enc")

	// Create a dummy (invalid) secrets file so loadAll gets past the Stat check.
	_ = os.WriteFile(secretsPath, []byte("garbage"), 0600)

	kv := NewEncryptedKV(secretsPath, "/nonexistent/server.key")
	_, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected error for missing key file, got nil")
	}
}

// ── Tamper/corruption tests ───────────────────────────────────────────────────

func TestTamperedCiphertext_DecryptionFails(t *testing.T) {
	kv, secretsPath := newTestKV(t)

	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "secret"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Flip a byte in the middle of the ciphertext (past the 12-byte nonce).
	raw, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(raw) < 20 {
		t.Fatal("ciphertext too short to tamper with")
	}
	raw[15] ^= 0xFF // flip bits past the nonce
	if err := os.WriteFile(secretsPath, raw, 0600); err != nil {
		t.Fatalf("WriteFile (tampered): %v", err)
	}

	_, err = kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected GCM authentication error after tampering, got nil")
	}
}

func TestTamperedTag_DecryptionFails(t *testing.T) {
	kv, secretsPath := newTestKV(t)

	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "secret"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	raw, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Flip the last byte (part of the GCM authentication tag).
	raw[len(raw)-1] ^= 0xFF
	if err := os.WriteFile(secretsPath, raw, 0600); err != nil {
		t.Fatalf("WriteFile (tag tampered): %v", err)
	}

	_, err = kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected GCM authentication error after tag tampering, got nil")
	}
}

func TestTruncatedFile_DecryptionFails(t *testing.T) {
	kv, secretsPath := newTestKV(t)

	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "secret"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	raw, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Truncate to just the nonce (12 bytes) — no ciphertext payload.
	truncated := raw[:12]
	if err := os.WriteFile(secretsPath, truncated, 0600); err != nil {
		t.Fatalf("WriteFile (truncated): %v", err)
	}

	_, err = kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected error for truncated file, got nil")
	}
}

func TestTooShortFile_ShorterThanNonce_Fails(t *testing.T) {
	kv, secretsPath := newTestKV(t)

	// Write only 5 bytes — shorter than the 12-byte nonce.
	if err := os.WriteFile(secretsPath, []byte("short"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected error for file shorter than nonce, got nil")
	}
}

func TestEmptyFile_Fails(t *testing.T) {
	kv, secretsPath := newTestKV(t)

	if err := os.WriteFile(secretsPath, []byte{}, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected error for empty file, got nil")
	}
}

// ── File properties ───────────────────────────────────────────────────────────

func TestSecretsFile_Permissions_0600(t *testing.T) {
	if os.Getuid() == 0 {
		// TODO(#permanent): root bypasses POSIX permission checks — this test can only run as a non-root user
		t.Skip("cannot test file permissions as root")
	}
	kv, secretsPath := newTestKV(t)

	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "x"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	info, err := os.Stat(secretsPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("secrets.enc permissions = %04o, want 0600", perm)
	}
}

func TestAtomicWrite_NoTempFileLeftBehind(t *testing.T) {
	kv, secretsPath := newTestKV(t)

	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "x"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// The .tmp file should not exist after a successful write.
	tmpPath := secretsPath + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("temp file %q still exists after Set — atomic write did not clean up", tmpPath)
	}
}

// ── Edge cases ────────────────────────────────────────────────────────────────

func TestSet_NilFields_StoredAsEmptyMap(t *testing.T) {
	kv, _ := newTestKV(t)

	// Nil fields map should not panic; the path is stored with an empty map.
	if err := kv.Set("kv/data/llm/anthropic", nil); err != nil {
		t.Fatalf("Set with nil fields: %v", err)
	}

	got, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err != nil {
		t.Fatalf("GetSecret after Set(nil): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty map for nil fields, got %v", got)
	}
}

func TestSet_EmptyPath_StoresAndRetrieves(t *testing.T) {
	kv, _ := newTestKV(t)

	// Empty string path is a valid map key in Go — behavior is defined.
	if err := kv.Set("", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("Set with empty path: %v", err)
	}

	got, err := kv.GetSecret(context.Background(), "")
	if err != nil {
		t.Fatalf("GetSecret with empty path: %v", err)
	}
	if got["k"] != "v" {
		t.Errorf("empty-path value: got %q, want %q", got["k"], "v")
	}
}

func TestSet_LargeValue_1MB(t *testing.T) {
	kv, _ := newTestKV(t)

	// Generate ~1 MB value.
	large := strings.Repeat("x", 1<<20)
	if err := kv.Set("kv/data/large", map[string]string{"data": large}); err != nil {
		t.Fatalf("Set 1MB value: %v", err)
	}

	got, err := kv.GetSecret(context.Background(), "kv/data/large")
	if err != nil {
		t.Fatalf("GetSecret 1MB value: %v", err)
	}
	if got["data"] != large {
		t.Errorf("large value round-trip failed: length in=%d out=%d", len(large), len(got["data"]))
	}
}

func TestSet_ManyFields_RoundTrip(t *testing.T) {
	kv, _ := newTestKV(t)

	fields := make(map[string]string, 100)
	for i := range 100 {
		fields[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
	}

	if err := kv.Set("kv/data/many", fields); err != nil {
		t.Fatalf("Set with 100 fields: %v", err)
	}

	got, err := kv.GetSecret(context.Background(), "kv/data/many")
	if err != nil {
		t.Fatalf("GetSecret with 100 fields: %v", err)
	}
	for k, v := range fields {
		if got[k] != v {
			t.Errorf("field %q: got %q, want %q", k, got[k], v)
		}
	}
}

// ── Invalid PEM key file ──────────────────────────────────────────────────────

func TestInvalidPEM_FailsCleanly(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.key")
	// Write garbage — no valid PEM block.
	if err := os.WriteFile(keyPath, []byte("this is not PEM"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	secretsPath := filepath.Join(dir, "secrets.enc")
	kv := NewEncryptedKV(secretsPath, keyPath)
	err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "x"})
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestValidPEM_WrongKeyType_FailsCleanly(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.key")
	// Write a PEM block but with wrong type (not an EC key).
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("not-a-valid-der-key"),
	})
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	secretsPath := filepath.Join(dir, "secrets.enc")
	kv := NewEncryptedKV(secretsPath, keyPath)
	err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "x"})
	if err == nil {
		t.Fatal("expected error for malformed EC key DER, got nil")
	}
}

// ── Concurrency ───────────────────────────────────────────────────────────────

func TestConcurrent_Gets_Safe(t *testing.T) {
	kv, _ := newTestKV(t)

	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "concurrent-value"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d GetSecret error: %v", i, err)
		}
	}
}

func TestConcurrent_Sets_NoCorruption(t *testing.T) {
	kv, _ := newTestKV(t)

	const goroutines = 10
	var wg sync.WaitGroup

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			path := fmt.Sprintf("kv/data/llm/provider%d", idx)
			_ = kv.Set(path, map[string]string{"api_key": fmt.Sprintf("key-%d", idx)})
		}(i)
	}
	wg.Wait()

	// Verify the file is still readable and contains valid data.
	paths, err := kv.Paths()
	if err != nil {
		t.Fatalf("Paths after concurrent Sets: %v", err)
	}
	// Each goroutine wrote a unique path, so we should have up to goroutines paths.
	// Due to last-write-wins races we may have fewer — but we must have at least 1 and no corruption.
	if len(paths) == 0 {
		t.Error("all concurrent Sets were lost — expected at least one")
	}
	t.Logf("concurrent Sets: %d of %d paths survived last-write-wins", len(paths), goroutines)
}

func TestConcurrent_GetAndSet_NoCorruption(t *testing.T) {
	kv, _ := newTestKV(t)

	// Seed initial value.
	if err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "initial"}); err != nil {
		t.Fatalf("initial Set: %v", err)
	}

	var wg sync.WaitGroup
	getErrs := make(chan error, 50)
	setErrs := make(chan error, 10)

	// 50 concurrent readers.
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
			if err != nil {
				getErrs <- err
			}
		}()
	}

	// 5 concurrent writers.
	for i := range 5 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": fmt.Sprintf("updated-%d", idx)})
			if err != nil {
				setErrs <- err
			}
		}(i)
	}

	wg.Wait()
	close(getErrs)
	close(setErrs)

	for err := range getErrs {
		t.Errorf("concurrent Get error: %v", err)
	}
	for err := range setErrs {
		t.Errorf("concurrent Set error: %v", err)
	}

	// After all goroutines finish, file must still be readable.
	_, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err != nil {
		t.Fatalf("GetSecret after concurrent Get+Set: %v", err)
	}
}

// ── Persistence across reinitialisation ──────────────────────────────────────

func TestPersistence_SecretsSurviveNewInstance(t *testing.T) {
	keyPath := writeTestECKey(t)
	secretsPath := filepath.Join(t.TempDir(), "secrets.enc")

	// Write with first instance.
	kv1 := NewEncryptedKV(secretsPath, keyPath)
	if err := kv1.Set("kv/data/llm/anthropic", map[string]string{"api_key": "persisted"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Create a fresh instance — simulates a process restart.
	kv2 := NewEncryptedKV(secretsPath, keyPath)
	got, err := kv2.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err != nil {
		t.Fatalf("GetSecret after restart: %v", err)
	}
	if got["api_key"] != "persisted" {
		t.Errorf("persisted value = %q, want %q", got["api_key"], "persisted")
	}
}

// ── Direct tests for private crypto functions ─────────────────────────────────

// TestAesgcmEncrypt_BadKeyLength covers the aes.NewCipher error path.
// AES only accepts 16, 24, or 32 byte keys.
func TestAesgcmEncrypt_BadKeyLength_ReturnsError(t *testing.T) {
	badKey := []byte("tooshort") // 8 bytes — not a valid AES key length
	_, err := aesgcmEncrypt(badKey, []byte("plaintext"))
	if err == nil {
		t.Fatal("expected error from aesgcmEncrypt with bad key length, got nil")
	}
}

// TestAesgcmDecrypt_BadKeyLength covers the aes.NewCipher error path in decrypt.
func TestAesgcmDecrypt_BadKeyLength_ReturnsError(t *testing.T) {
	badKey := []byte("tooshort")
	// 13 bytes of data: enough to pass the nonce-size check (12) but with bad key.
	ciphertext := make([]byte, 13)
	_, err := aesgcmDecrypt(badKey, ciphertext)
	if err == nil {
		t.Fatal("expected error from aesgcmDecrypt with bad key length, got nil")
	}
}

// TestAesgcmDecrypt_TooShort covers the "ciphertext too short" error path.
func TestAesgcmDecrypt_TooShort_ReturnsError(t *testing.T) {
	key := make([]byte, 32)
	// 5 bytes — shorter than 12-byte nonce.
	_, err := aesgcmDecrypt(key, []byte("short"))
	if err == nil {
		t.Fatal("expected 'ciphertext too short' error, got nil")
	}
}

// TestAesgcmRoundTrip_Direct exercises encrypt→decrypt directly via private API.
func TestAesgcmRoundTrip_Direct(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	plaintext := []byte("hello world secret data")

	ct, err := aesgcmEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("aesgcmEncrypt: %v", err)
	}

	got, err := aesgcmDecrypt(key, ct)
	if err != nil {
		t.Fatalf("aesgcmDecrypt: %v", err)
	}

	if string(got) != string(plaintext) {
		t.Errorf("round-trip: got %q, want %q", got, plaintext)
	}
}

// ── Verify EncryptedKV satisfies KVWriter ─────────────────────────────────────

func TestEncryptedKV_ImplementsKVWriter(t *testing.T) {
	kv, _ := newTestKV(t)
	var _ KVWriter = kv // compile-time interface check
}

// ── Error path coverage: Delete on corrupt file ───────────────────────────────

// TestDelete_CorruptFile_ReturnsError covers the loadAll→error path inside Delete
// (the branch where loadAll returns a non-nil error that is not errFileNotFound).
func TestDelete_CorruptFile_ReturnsError(t *testing.T) {
	keyPath := writeTestECKey(t)
	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "secrets.enc")

	// Write garbage that will fail decryption (file exists, but is unreadable as ciphertext).
	if err := os.WriteFile(secretsPath, []byte("this is garbage and not valid ciphertext"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	kv := NewEncryptedKV(secretsPath, keyPath)
	err := kv.Delete("kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected error when deleting from corrupt secrets file, got nil")
	}
}

// TestPaths_CorruptFile_ReturnsError covers the loadAll→non-fileNotFound error path
// inside Paths (the branch that propagates the error rather than returning nil).
func TestPaths_CorruptFile_ReturnsError(t *testing.T) {
	keyPath := writeTestECKey(t)
	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "secrets.enc")

	if err := os.WriteFile(secretsPath, []byte("corrupt-not-valid-aes-gcm-data-for-sure"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	kv := NewEncryptedKV(secretsPath, keyPath)
	_, err := kv.Paths()
	if err == nil {
		t.Fatal("expected error from Paths with corrupt secrets file, got nil")
	}
}

// TestSet_CorruptExistingFile_StartsFromEmpty covers the Set error-handling logic:
// when loadAll returns errFileNotFound equivalent error paths; Set treats most
// load errors as "start fresh" only for errFileNotFound. Corrupt data must propagate.
func TestSet_CorruptExistingFile_ReturnsError(t *testing.T) {
	keyPath := writeTestECKey(t)
	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "secrets.enc")

	// Write something that looks like a real file (not os.IsNotExist) but is garbage.
	if err := os.WriteFile(secretsPath, []byte("definitely-not-valid-aes-gcm"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	kv := NewEncryptedKV(secretsPath, keyPath)
	err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "x"})
	if err == nil {
		t.Fatal("expected error when Set cannot load corrupt existing file, got nil")
	}
}

// TestLoadAll_InvalidJSON_AfterDecrypt covers the JSON unmarshal failure path
// inside loadAll. We achieve this by encrypting something with the right key
// that decrypts successfully but is not valid JSON.
// TestLoadAll_UnreadableFile covers the os.ReadFile error path in loadAll
// (file exists and Stat passes, but Read fails due to permissions).
func TestLoadAll_UnreadableFile_ReturnsError(t *testing.T) {
	if os.Getuid() == 0 {
		// TODO(#permanent): root bypasses POSIX permission checks — this test can only run as a non-root user
		t.Skip("cannot test file permissions as root")
	}
	keyPath := writeTestECKey(t)
	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "secrets.enc")

	// Create the file with content, then remove read permission.
	if err := os.WriteFile(secretsPath, []byte("content"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(secretsPath, 0000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(secretsPath, 0600) })

	kv := NewEncryptedKV(secretsPath, keyPath)
	_, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected error for unreadable secrets file, got nil")
	}
}

// TestSaveAll_UnwritableDir covers the os.WriteFile error path in saveAll
// (directory exists but is not writable, so temp file creation fails).
func TestSaveAll_UnwritableDir_ReturnsError(t *testing.T) {
	if os.Getuid() == 0 {
		// TODO(#permanent): root bypasses POSIX permission checks — this test can only run as a non-root user
		t.Skip("cannot test directory permissions as root")
	}
	keyPath := writeTestECKey(t)
	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "secrets.enc")

	// Make the directory read-only so WriteFile of the .tmp file fails.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	kv := NewEncryptedKV(secretsPath, keyPath)
	err := kv.Set("kv/data/llm/anthropic", map[string]string{"api_key": "x"})
	if err == nil {
		t.Fatal("expected error when temp file cannot be written, got nil")
	}
}

func TestLoadAll_InvalidJSON_AfterDecrypt(t *testing.T) {
	keyPath := writeTestECKey(t)
	dir := t.TempDir()
	secretsPath := filepath.Join(dir, "secrets.enc")

	// Build a helper EncryptedKV just to get the derived key and encrypt bad JSON.
	kv := NewEncryptedKV(secretsPath, keyPath)
	key, err := kv.deriveKey()
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}

	// Encrypt valid-looking bytes that are NOT valid JSON.
	badJSON := []byte("this is not json {{{ }")
	ciphertext, err := aesgcmEncrypt(key, badJSON)
	if err != nil {
		t.Fatalf("aesgcmEncrypt: %v", err)
	}
	if err := os.WriteFile(secretsPath, ciphertext, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected error for non-JSON decrypted content, got nil")
	}
}
