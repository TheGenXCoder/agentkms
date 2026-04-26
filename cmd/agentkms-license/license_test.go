package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// generateTestKeypair generates a fresh Ed25519 keypair for testing.
func generateTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test keypair: %v", err)
	}
	return pub, priv
}

// writeTestPrivKeyPEM writes a PKCS#8 PEM private key to a temp file and
// returns its path.
func writeTestPrivKeyPEM(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/private.pem"

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return path
}

// writeTestPubKeyPEM writes a SPKI PEM public key to a temp file and returns
// its path.
func writeTestPubKeyPEM(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/public.pem"

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return path
}

// buildTestManifest constructs a LicenseManifest for testing.
func buildTestManifest() LicenseManifest {
	now := time.Now().UTC().Truncate(time.Second)
	return LicenseManifest{
		LicenseID:     "550e8400-e29b-41d4-a716-446655440000",
		Customer:      "Acme Corp",
		Email:         "admin@acme.example",
		IssuedAt:      now,
		ExpiresAt:     now.Add(365 * 24 * time.Hour),
		Features:      []string{"rotation_orchestrator"},
		SchemaVersion: 1,
	}
}

// ── 1. TestManifestRoundTrip ──────────────────────────────────────────────────

func TestManifestRoundTrip(t *testing.T) {
	original := buildTestManifest()

	b, err := MarshalManifest(original)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}

	parsed, err := UnmarshalManifest(b)
	if err != nil {
		t.Fatalf("UnmarshalManifest: %v", err)
	}

	if parsed.LicenseID != original.LicenseID {
		t.Errorf("LicenseID mismatch: got %q, want %q", parsed.LicenseID, original.LicenseID)
	}
	if parsed.Customer != original.Customer {
		t.Errorf("Customer mismatch: got %q, want %q", parsed.Customer, original.Customer)
	}
	if parsed.Email != original.Email {
		t.Errorf("Email mismatch: got %q, want %q", parsed.Email, original.Email)
	}
	if !parsed.IssuedAt.Equal(original.IssuedAt) {
		t.Errorf("IssuedAt mismatch: got %v, want %v", parsed.IssuedAt, original.IssuedAt)
	}
	if !parsed.ExpiresAt.Equal(original.ExpiresAt) {
		t.Errorf("ExpiresAt mismatch: got %v, want %v", parsed.ExpiresAt, original.ExpiresAt)
	}
	if len(parsed.Features) != len(original.Features) {
		t.Errorf("Features length mismatch: got %d, want %d", len(parsed.Features), len(original.Features))
	} else if parsed.Features[0] != original.Features[0] {
		t.Errorf("Features[0] mismatch: got %q, want %q", parsed.Features[0], original.Features[0])
	}
	if parsed.SchemaVersion != original.SchemaVersion {
		t.Errorf("SchemaVersion mismatch: got %d, want %d", parsed.SchemaVersion, original.SchemaVersion)
	}
}

// TestManifestJSON verifies canonical JSON field ordering.
func TestManifestJSON(t *testing.T) {
	m := LicenseManifest{
		LicenseID:     "550e8400-e29b-41d4-a716-446655440000",
		Customer:      "Acme Corp",
		Email:         "admin@acme.example",
		IssuedAt:      time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC),
		Features:      []string{"rotation_orchestrator"},
		SchemaVersion: 1,
	}

	b, err := MarshalManifest(m)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}

	want := `{"license_id":"550e8400-e29b-41d4-a716-446655440000","customer":"Acme Corp","email":"admin@acme.example","issued_at":"2026-05-01T00:00:00Z","expires_at":"2027-05-01T00:00:00Z","features":["rotation_orchestrator"],"schema_version":1}`
	if string(b) != want {
		t.Errorf("canonical JSON mismatch:\ngot:  %s\nwant: %s", b, want)
	}
}

// ── 2. TestEncodeDecodeFile ───────────────────────────────────────────────────

func TestEncodeDecodeFile(t *testing.T) {
	_, priv := generateTestKeypair(t)
	m := buildTestManifest()

	manifestBytes, err := MarshalManifest(m)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}

	sig := ed25519.Sign(priv, manifestBytes)
	fileData := EncodeFile(manifestBytes, sig)

	// Decode should return the same manifest and signature bytes.
	m2, sig2, mb2, err := DecodeFile(fileData)
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	if !bytes.Equal(sig, sig2) {
		t.Errorf("signature bytes differ after round-trip")
	}
	if !bytes.Equal(manifestBytes, mb2) {
		t.Errorf("manifest bytes differ after round-trip")
	}
	if m2.LicenseID != m.LicenseID {
		t.Errorf("LicenseID differ after round-trip: got %q", m2.LicenseID)
	}
}

// ── 3. TestDecodeFile_TooLarge ────────────────────────────────────────────────

func TestDecodeFile_TooLarge(t *testing.T) {
	// Build a file that exceeds 4 KB.
	data := bytes.Repeat([]byte("A"), maxLicenseFileBytes+1)
	_, _, _, err := DecodeFile(data)
	if err == nil {
		t.Fatal("expected error for oversized input, got nil")
	}
	if !strings.Contains(err.Error(), "4 KB") {
		t.Errorf("expected 4 KB mention in error, got: %v", err)
	}
}

// ── 4. TestDecodeFile_NotTwoLines ─────────────────────────────────────────────

func TestDecodeFile_NotTwoLines(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"one line", []byte("onlyone\n")},
		{"three lines", []byte("a\nb\nc\n")},
		{"missing newline", []byte("noline")},
		{"empty first line", []byte("\nsecond\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := DecodeFile(tc.data)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.name)
			}
		})
	}
}

// ── 5. TestDecodeFile_BadBase64 ───────────────────────────────────────────────

func TestDecodeFile_BadBase64(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{
			"bad manifest base64",
			[]byte("!!!invalid!!!\nvalidenough\n"),
		},
		{
			"bad signature base64",
			// valid base64url manifest (just some valid JSON) but bad sig
			[]byte("eyJmb28iOiJiYXIifQ\n!!!invalid!!!\n"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := DecodeFile(tc.data)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.name)
			}
		})
	}
}

// ── 6. TestKeygen_RefusesOverwrite ────────────────────────────────────────────

func TestKeygen_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"

	// Create a dummy file at the private key path.
	if err := os.WriteFile(privPath, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	code := runKeygen([]string{
		"--private-key", privPath,
		"--public-key", pubPath,
	})
	if code == 0 {
		t.Fatal("expected non-zero exit when output file exists and --force not set")
	}
}

// ── 7. TestKeygen_FileModes ───────────────────────────────────────────────────

func TestKeygen_FileModes(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"

	code := runKeygen([]string{
		"--private-key", privPath,
		"--public-key", pubPath,
	})
	if code != 0 {
		t.Fatalf("keygen returned exit code %d", code)
	}

	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if privInfo.Mode().Perm() != 0o600 {
		t.Errorf("private key mode: got %04o, want 0600", privInfo.Mode().Perm())
	}

	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("stat public key: %v", err)
	}
	if pubInfo.Mode().Perm() != 0o644 {
		t.Errorf("public key mode: got %04o, want 0644", pubInfo.Mode().Perm())
	}
}

// ── 8. TestIssue_AndVerify_RoundTrip ─────────────────────────────────────────

func TestIssue_AndVerify_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"
	licPath := dir + "/test.lic"

	// keygen
	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}

	// issue
	code := runIssue([]string{
		"--private-key", privPath,
		"--customer", "Test Corp",
		"--email", "test@example.com",
		"--expires", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339),
		"--feature", "rotation_orchestrator",
		"--out", licPath,
	})
	if code != 0 {
		t.Fatalf("issue returned %d", code)
	}

	// verify
	code = runVerify([]string{
		"--license", licPath,
		"--public-key", pubPath,
	})
	if code != 0 {
		t.Fatalf("verify returned %d (expected 0)", code)
	}

	// Check .lic file mode.
	info, err := os.Stat(licPath)
	if err != nil {
		t.Fatalf("stat license file: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("license file mode: got %04o, want 0644", info.Mode().Perm())
	}
}

// ── 9. TestVerify_BadSignature ────────────────────────────────────────────────

func TestVerify_BadSignature(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"
	licPath := dir + "/test.lic"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}

	if code := runIssue([]string{
		"--private-key", privPath,
		"--customer", "Tamper Corp",
		"--email", "bad@example.com",
		"--expires", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339),
		"--feature", "rotation_orchestrator",
		"--out", licPath,
	}); code != 0 {
		t.Fatalf("issue returned %d", code)
	}

	// Tamper: read the file, decode it, flip a byte in the manifest, re-encode.
	data, err := os.ReadFile(licPath)
	if err != nil {
		t.Fatalf("read license: %v", err)
	}
	_, sig, manifestBytes, err := DecodeFile(data)
	if err != nil {
		t.Fatalf("decode license: %v", err)
	}
	// Flip one byte in the manifest bytes.
	manifestBytes[5] ^= 0xff
	tampered := EncodeFile(manifestBytes, sig)
	if err := os.WriteFile(licPath, tampered, 0o644); err != nil {
		t.Fatalf("write tampered license: %v", err)
	}

	code := runVerify([]string{"--license", licPath, "--public-key", pubPath})
	if code != 1 {
		t.Errorf("verify returned %d for tampered license (expected 1)", code)
	}
}

// ── 10. TestVerify_Expired ────────────────────────────────────────────────────

func TestVerify_Expired(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"
	licPath := dir + "/expired.lic"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}

	// Issue a license that expires in the past using --issued-at and --expires
	// in the past (both in the past, expires > issued_at).
	pastIssued := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	pastExpires := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)

	if code := runIssue([]string{
		"--private-key", privPath,
		"--customer", "Expired Corp",
		"--email", "expired@example.com",
		"--issued-at", pastIssued,
		"--expires", pastExpires,
		"--feature", "rotation_orchestrator",
		"--out", licPath,
	}); code != 0 {
		t.Fatalf("issue returned %d", code)
	}

	code := runVerify([]string{"--license", licPath, "--public-key", pubPath})
	if code != 2 {
		t.Errorf("verify returned %d for expired license (expected 2)", code)
	}
}

// ── 11. TestIssue_StdinPrivateKey ─────────────────────────────────────────────

func TestIssue_StdinPrivateKey(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"
	licPath := dir + "/stdin.lic"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}

	// Read the private key PEM from file to feed via stdin.
	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}

	// Redirect os.Stdin to a pipe containing the private key PEM.
	oldStdin := os.Stdin
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("create pipe: %v", pipeErr)
	}
	os.Stdin = r

	// Write PEM into pipe and close writer.
	go func() {
		_, _ = io.WriteString(w, string(privPEM))
		w.Close()
	}()

	code := runIssue([]string{
		"--private-key", "-",
		"--customer", "StdinTest Corp",
		"--email", "stdin@example.com",
		"--expires", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339),
		"--feature", "rotation_orchestrator",
		"--out", licPath,
	})

	os.Stdin = oldStdin // restore
	r.Close()

	if code != 0 {
		t.Fatalf("issue --private-key - returned %d", code)
	}

	// Verify the produced license.
	code = runVerify([]string{"--license", licPath, "--public-key", pubPath})
	if code != 0 {
		t.Fatalf("verify returned %d (expected 0) for stdin-key-issued license", code)
	}
}

// ── 12. TestInspect_PrintsWithoutVerification ─────────────────────────────────

func TestInspect_PrintsWithoutVerification(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"
	licPath := dir + "/inspect.lic"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}
	if code := runIssue([]string{
		"--private-key", privPath,
		"--customer", "Inspect Corp",
		"--email", "inspect@example.com",
		"--expires", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339),
		"--feature", "rotation_orchestrator",
		"--out", licPath,
	}); code != 0 {
		t.Fatalf("issue returned %d", code)
	}

	// Tamper with the license (invalid signature).
	data, err := os.ReadFile(licPath)
	if err != nil {
		t.Fatalf("read license: %v", err)
	}
	_, sig, manifestBytes, err := DecodeFile(data)
	if err != nil {
		t.Fatalf("decode license: %v", err)
	}
	manifestBytes[5] ^= 0xff
	tampered := EncodeFile(manifestBytes, sig)
	if err := os.WriteFile(licPath, tampered, 0o644); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	// inspect should exit 0 even on tampered file.
	code := runInspect([]string{"--license", licPath})
	if code != 0 {
		t.Errorf("inspect returned %d on tampered file (expected 0)", code)
	}
}

// ── Additional coverage tests ─────────────────────────────────────────────────

func TestNewUUID_Format(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		id, err := newUUID()
		if err != nil {
			t.Fatalf("newUUID: %v", err)
		}
		// Format: 8-4-4-4-12 hex chars with dashes.
		parts := strings.Split(id, "-")
		if len(parts) != 5 {
			t.Errorf("UUID %q: expected 5 dash-separated parts", id)
		}
		lengths := []int{8, 4, 4, 4, 12}
		for j, p := range parts {
			if len(p) != lengths[j] {
				t.Errorf("UUID %q part %d: expected length %d, got %d", id, j, lengths[j], len(p))
			}
		}
		// Verify version nibble = 4.
		if id[14] != '4' {
			t.Errorf("UUID %q: version nibble at index 14 expected '4', got %q", id, id[14])
		}
		// Verify variant bits (index 19 should be 8, 9, a, or b).
		v := id[19]
		if v != '8' && v != '9' && v != 'a' && v != 'b' {
			t.Errorf("UUID %q: variant nibble at index 19 expected 8/9/a/b, got %q", id, v)
		}
		if seen[id] {
			t.Errorf("UUID collision: %q generated twice", id)
		}
		seen[id] = true
	}
}

func TestPublicKeyFingerprint_Format(t *testing.T) {
	pub, _ := generateTestKeypair(t)
	fp := publicKeyFingerprint(pub)
	// Should be 16 pairs of hex digits separated by colons: "xx:xx:...:xx" (47 chars)
	parts := strings.Split(fp, ":")
	if len(parts) != 16 {
		t.Errorf("fingerprint %q: expected 16 colon-separated parts, got %d", fp, len(parts))
	}
	for _, p := range parts {
		if len(p) != 2 {
			t.Errorf("fingerprint part %q: expected 2 chars, got %d", p, len(p))
		}
		for _, c := range p {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("fingerprint part %q: non-lowercase-hex char %q", p, c)
			}
		}
	}
}

func TestEncodeFile_Format(t *testing.T) {
	manifest := []byte(`{"test":"value"}`)
	sig := make([]byte, 64)
	data := EncodeFile(manifest, sig)

	// Must end with exactly two newlines (one after line1, one after line2).
	if !bytes.HasSuffix(data, []byte{'\n'}) {
		t.Error("encoded file does not end with newline")
	}

	// Must have exactly one internal newline (between the two lines).
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
	if len(lines) != 2 {
		t.Errorf("expected 2 lines in encoded file, got %d", len(lines))
	}

	// No padding characters.
	if bytes.Contains(data, []byte("=")) {
		t.Error("encoded file contains padding '=' characters")
	}
}

func TestRunUnknownSubcommand(t *testing.T) {
	code := run([]string{"bogus"})
	if code == 0 {
		t.Error("expected non-zero exit for unknown subcommand")
	}
}

func TestRunHelp(t *testing.T) {
	code := run([]string{"--help"})
	if code != 0 {
		t.Errorf("--help returned %d, expected 0", code)
	}
	code = run([]string{"-h"})
	if code != 0 {
		t.Errorf("-h returned %d, expected 0", code)
	}
}

func TestRunNoArgs(t *testing.T) {
	code := run([]string{})
	if code == 0 {
		t.Error("expected non-zero exit with no arguments")
	}
}

// TestIssue_MissingRequiredFlags checks that missing required flags are caught.
func TestIssue_MissingRequiredFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing private-key", []string{"--customer", "A", "--email", "a@b.com", "--expires", "2099-01-01T00:00:00Z", "--feature", "f", "--out", "/tmp/x.lic"}},
		{"missing customer", []string{"--private-key", "/dev/null", "--email", "a@b.com", "--expires", "2099-01-01T00:00:00Z", "--feature", "f", "--out", "/tmp/x.lic"}},
		{"missing email", []string{"--private-key", "/dev/null", "--customer", "A", "--expires", "2099-01-01T00:00:00Z", "--feature", "f", "--out", "/tmp/x.lic"}},
		{"missing expires", []string{"--private-key", "/dev/null", "--customer", "A", "--email", "a@b.com", "--feature", "f", "--out", "/tmp/x.lic"}},
		{"missing feature", []string{"--private-key", "/dev/null", "--customer", "A", "--email", "a@b.com", "--expires", "2099-01-01T00:00:00Z", "--out", "/tmp/x.lic"}},
		{"missing out", []string{"--private-key", "/dev/null", "--customer", "A", "--email", "a@b.com", "--expires", "2099-01-01T00:00:00Z", "--feature", "f"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := runIssue(tc.args)
			if code == 0 {
				t.Errorf("expected non-zero exit for %q", tc.name)
			}
		})
	}
}

func TestVerify_MissingFlags(t *testing.T) {
	if code := runVerify([]string{"--license", "/tmp/x.lic"}); code == 0 {
		t.Error("expected non-zero exit when --public-key is missing")
	}
	if code := runVerify([]string{"--public-key", "/tmp/x.pem"}); code == 0 {
		t.Error("expected non-zero exit when --license is missing")
	}
}

func TestInspect_MissingFlag(t *testing.T) {
	if code := runInspect([]string{}); code == 0 {
		t.Error("expected non-zero exit when --license is missing")
	}
}

func TestKeygen_MissingFlags(t *testing.T) {
	if code := runKeygen([]string{"--private-key", "/tmp/priv.pem"}); code == 0 {
		t.Error("expected non-zero exit when --public-key is missing")
	}
	if code := runKeygen([]string{"--public-key", "/tmp/pub.pem"}); code == 0 {
		t.Error("expected non-zero exit when --private-key is missing")
	}
}

func TestKeygen_Force(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"

	// First generation.
	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("first keygen returned %d", code)
	}

	// Without --force should fail.
	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code == 0 {
		t.Error("expected failure without --force")
	}

	// With --force should succeed.
	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath, "--force"}); code != 0 {
		t.Errorf("keygen with --force returned %d", code)
	}
}

func TestInspect_Raw(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"
	licPath := dir + "/raw.lic"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}
	if code := runIssue([]string{
		"--private-key", privPath,
		"--customer", "Raw Corp",
		"--email", "raw@example.com",
		"--expires", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339),
		"--feature", "rotation_orchestrator",
		"--out", licPath,
	}); code != 0 {
		t.Fatalf("issue returned %d", code)
	}

	// Capture stdout.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := runInspect([]string{"--license", licPath, "--raw"})

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	r.Close()

	if code != 0 {
		t.Fatalf("inspect --raw returned %d", code)
	}

	out := buf.String()
	if !strings.Contains(out, "manifest:") {
		t.Errorf("--raw output missing 'manifest:' label:\n%s", out)
	}
	if !strings.Contains(out, "signature:") {
		t.Errorf("--raw output missing 'signature:' label:\n%s", out)
	}
}

func TestVerify_AtOverride(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"
	licPath := dir + "/at.lic"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}

	// Issue license that expires in 1 hour.
	in1h := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if code := runIssue([]string{
		"--private-key", privPath,
		"--customer", "AtTest Corp",
		"--email", "at@example.com",
		"--expires", in1h,
		"--feature", "rotation_orchestrator",
		"--out", licPath,
	}); code != 0 {
		t.Fatalf("issue returned %d", code)
	}

	// Verify at a time in the future (after expiry) should return 2.
	in2h := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339)
	code := runVerify([]string{
		"--license", licPath,
		"--public-key", pubPath,
		"--at", in2h,
	})
	if code != 2 {
		t.Errorf("verify --at (past expiry) returned %d, expected 2", code)
	}

	// Verify at a time in the past (before expiry) should return 0.
	past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	code = runVerify([]string{
		"--license", licPath,
		"--public-key", pubPath,
		"--at", past,
	})
	if code != 0 {
		t.Errorf("verify --at (before expiry) returned %d, expected 0", code)
	}
}

func TestIssue_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"
	licPath := dir + "/test.lic"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}

	issueArgs := []string{
		"--private-key", privPath,
		"--customer", "Dup Corp",
		"--email", "dup@example.com",
		"--expires", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339),
		"--feature", "rotation_orchestrator",
		"--out", licPath,
	}

	if code := runIssue(issueArgs); code != 0 {
		t.Fatalf("first issue returned %d", code)
	}
	// Second issue without --force should fail.
	if code := runIssue(issueArgs); code == 0 {
		t.Error("expected non-zero exit when output file exists and --force not set")
	}
	// With --force should succeed.
	if code := runIssue(append(issueArgs, "--force")); code != 0 {
		t.Errorf("issue --force returned non-zero")
	}
}

func TestVerify_SchemaVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"
	licPath := dir + "/badschema.lic"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}

	// Build a manifest with schema_version=99 and sign it manually.
	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	privKey, err := parsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	m := LicenseManifest{
		LicenseID:     "test-uuid",
		Customer:      "Schema Corp",
		Email:         "schema@example.com",
		IssuedAt:      time.Now().UTC().Add(-time.Hour),
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour),
		Features:      []string{"rotation_orchestrator"},
		SchemaVersion: 99,
	}
	manifestBytes, err := MarshalManifest(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sig := ed25519.Sign(privKey, manifestBytes)
	if err := os.WriteFile(licPath, EncodeFile(manifestBytes, sig), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	code := runVerify([]string{"--license", licPath, "--public-key", pubPath})
	if code != 1 {
		t.Errorf("verify with schema_version=99 returned %d, expected 1", code)
	}
}

func TestInspect_NonExistentFile(t *testing.T) {
	code := runInspect([]string{"--license", "/tmp/doesnotexist-agentkms-license-test.lic"})
	if code == 0 {
		t.Error("expected non-zero exit for non-existent license file")
	}
}

func TestVerify_NonExistentFiles(t *testing.T) {
	if code := runVerify([]string{"--license", "/tmp/nope.lic", "--public-key", "/tmp/nope.pem"}); code == 0 {
		t.Error("expected non-zero exit for non-existent license")
	}
}

func TestParsePrivateKey_NoPEMBlock(t *testing.T) {
	_, err := parsePrivateKey([]byte("not a pem block"))
	if err == nil {
		t.Error("expected error for non-PEM input")
	}
}

func TestParsePrivateKey_WrongType(t *testing.T) {
	// Encode something with wrong PEM type.
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})
	_, err := parsePrivateKey(pemBytes)
	if err == nil {
		t.Error("expected error for wrong PEM type")
	}
}

func TestParsePublicKey_NoPEMBlock(t *testing.T) {
	_, err := parsePublicKey([]byte("not a pem block"))
	if err == nil {
		t.Error("expected error for non-PEM input")
	}
}

func TestParsePublicKey_WrongType(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})
	_, err := parsePublicKey(pemBytes)
	if err == nil {
		t.Error("expected error for wrong PEM type")
	}
}

func TestUnmarshalManifest_BadJSON(t *testing.T) {
	_, err := UnmarshalManifest([]byte("{not valid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestUnmarshalManifest_BadIssuedAt(t *testing.T) {
	_, err := UnmarshalManifest([]byte(`{"license_id":"x","customer":"x","email":"x","issued_at":"notadate","expires_at":"2027-01-01T00:00:00Z","features":["f"],"schema_version":1}`))
	if err == nil {
		t.Error("expected error for invalid issued_at")
	}
}

func TestUnmarshalManifest_BadExpiresAt(t *testing.T) {
	_, err := UnmarshalManifest([]byte(`{"license_id":"x","customer":"x","email":"x","issued_at":"2026-01-01T00:00:00Z","expires_at":"notadate","features":["f"],"schema_version":1}`))
	if err == nil {
		t.Error("expected error for invalid expires_at")
	}
}

func TestIssue_ExpiresBeforeIssuedAt(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"
	licPath := dir + "/test.lic"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}

	// expires before issued_at.
	past := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	code := runIssue([]string{
		"--private-key", privPath,
		"--customer", "A",
		"--email", "a@b.com",
		"--expires", past,
		"--feature", "f",
		"--out", licPath,
	})
	if code == 0 {
		t.Error("expected non-zero exit when expires < issued_at")
	}
}

func TestIssue_InvalidExpires(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}

	code := runIssue([]string{
		"--private-key", privPath,
		"--customer", "A",
		"--email", "a@b.com",
		"--expires", "not-a-date",
		"--feature", "f",
		"--out", dir + "/test.lic",
	})
	if code == 0 {
		t.Error("expected non-zero exit for invalid --expires")
	}
}

func TestIssue_InvalidIssuedAt(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}

	code := runIssue([]string{
		"--private-key", privPath,
		"--customer", "A",
		"--email", "a@b.com",
		"--expires", "2099-01-01T00:00:00Z",
		"--issued-at", "not-a-date",
		"--feature", "f",
		"--out", dir + "/test.lic",
	})
	if code == 0 {
		t.Error("expected non-zero exit for invalid --issued-at")
	}
}

func TestIssue_NonExistentPrivateKey(t *testing.T) {
	code := runIssue([]string{
		"--private-key", "/tmp/doesnotexist-privkey.pem",
		"--customer", "A",
		"--email", "a@b.com",
		"--expires", "2099-01-01T00:00:00Z",
		"--feature", "f",
		"--out", "/tmp/x.lic",
	})
	if code == 0 {
		t.Error("expected non-zero exit for non-existent private key")
	}
}

func TestVerify_BadAtFormat(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"
	licPath := dir + "/test.lic"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		t.Fatalf("keygen returned %d", code)
	}
	if code := runIssue([]string{
		"--private-key", privPath,
		"--customer", "A",
		"--email", "a@b.com",
		"--expires", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339),
		"--feature", "f",
		"--out", licPath,
	}); code != 0 {
		t.Fatalf("issue returned %d", code)
	}

	code := runVerify([]string{
		"--license", licPath,
		"--public-key", pubPath,
		"--at", "not-a-date",
	})
	if code == 0 {
		t.Error("expected non-zero exit for invalid --at format")
	}
}

func TestRunHelp_Subcommand(t *testing.T) {
	code := run([]string{"help"})
	if code != 0 {
		t.Errorf("'help' subcommand returned %d, expected 0", code)
	}
}

// BenchmarkIssueAndVerify measures the issue+verify round-trip performance.
func BenchmarkIssueAndVerify(b *testing.B) {
	dir := b.TempDir()
	privPath := dir + "/priv.pem"
	pubPath := dir + "/pub.pem"

	if code := runKeygen([]string{"--private-key", privPath, "--public-key", pubPath}); code != 0 {
		b.Fatalf("keygen returned %d", code)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		licPath := fmt.Sprintf("%s/bench_%d.lic", dir, i)
		runIssue([]string{
			"--private-key", privPath,
			"--customer", "Bench Corp",
			"--email", "bench@example.com",
			"--expires", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339),
			"--feature", "rotation_orchestrator",
			"--out", licPath,
		})
		runVerify([]string{"--license", licPath, "--public-key", pubPath})
	}
}
