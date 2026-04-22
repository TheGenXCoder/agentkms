package plugin

// host_subprocess_test.go — failing tests for the real hashicorp/go-plugin
// subprocess host. These tests drive the implementation of Host.Start(),
// Host.Stop(), Host.StopAll(), and Host.IsRunning() with actual subprocess
// launch, handshake, and signature verification.
//
// ALL TESTS IN THIS FILE ARE EXPECTED TO FAIL until the implementation lands.
// Do not modify non-test code to make them pass.

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// stubBinaryPath returns the path to the compiled test-stub plugin binary.
// The binary must be built from internal/plugin/testdata/stub-validator/
// before these tests can pass. If the binary does not exist, the test is
// skipped with a clear message rather than failing obscurely.
func stubBinaryPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("testdata", "stub-validator", "agentkms-plugin-test-stub")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("test-stub binary not built — run: go build -o internal/plugin/testdata/stub-validator/agentkms-plugin-test-stub ./internal/plugin/testdata/stub-validator/")
	}
	return path
}

// makeVerifier generates a fresh Ed25519 key pair, signs the binary at path,
// writes the .sig sidecar, and returns a Verifier for the public key.
func makeVerifierAndSign(t *testing.T, binaryPath string) *Verifier {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	sig, err := signer.Sign(binaryPath)
	if err != nil {
		t.Fatalf("Sign(%q): %v", binaryPath, err)
	}
	if err := os.WriteFile(binaryPath+".sig", sig, 0o600); err != nil {
		t.Fatalf("write .sig: %v", err)
	}
	t.Cleanup(func() { os.Remove(binaryPath + ".sig") })

	v, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// TestHost_Start_LaunchesSubprocess verifies that Host.Start actually forks
// a subprocess using hashicorp/go-plugin and performs the handshake. After
// Start returns nil, IsRunning must be true and the plugin must respond to
// a Kind() gRPC call through the Registry.
//
// CURRENTLY FAILS: Host.Start() is a stub that returns nil without launching
// any subprocess.
func TestHost_Start_LaunchesSubprocess(t *testing.T) {
	binaryPath := stubBinaryPath(t)

	dir := t.TempDir()
	destName := "agentkms-plugin-test-stub"
	destPath := filepath.Join(dir, destName)
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read stub binary: %v", err)
	}
	if err := os.WriteFile(destPath, data, 0o755); err != nil {
		t.Fatalf("write stub to temp dir: %v", err)
	}

	h, err := NewHost(dir)
	if err != nil {
		t.Fatalf("NewHost(%q): %v", dir, err)
	}

	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover(): %v", err)
	}

	if err := h.Start("test-stub"); err != nil {
		t.Fatalf("Start('test-stub') returned unexpected error: %v", err)
	}
	defer h.StopAll()

	// EXPECT FAIL: IsRunning will return false because Start is a stub.
	if !h.IsRunning("test-stub") {
		t.Error("IsRunning('test-stub') returned false after Start, want true — Start() is not launching subprocess")
	}
}

// TestHost_Start_SignatureFailureBlocksLaunch verifies that Host.Start refuses
// to launch a plugin binary whose signature does not match. This requires a
// Verifier to be configured on the Host and a tampered binary.
//
// CURRENTLY FAILS: Host has no verifier field; Start() never calls Verify().
func TestHost_Start_SignatureFailureBlocksLaunch(t *testing.T) {
	binaryPath := stubBinaryPath(t)

	dir := t.TempDir()
	destName := "agentkms-plugin-test-stub"
	destPath := filepath.Join(dir, destName)

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read stub binary: %v", err)
	}
	if err := os.WriteFile(destPath, data, 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	// Generate a fresh key pair and sign a different binary — so the verifier
	// trusts a key but the .sig won't match this binary.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, _ := NewSigner(priv)
	// Sign a different payload to produce an invalid signature for destPath.
	bogusData := []byte("this is not the plugin binary")
	sig := ed25519.Sign(priv, bogusData)
	_ = signer // keep import alive
	if err := os.WriteFile(destPath+".sig", sig, 0o600); err != nil {
		t.Fatalf("write bad .sig: %v", err)
	}

	// Build a fresh verifier from a different key — so it will reject the sig.
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}
	verifier, err := NewVerifier(pub2)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// EXPECT FAIL: NewHost does not accept a verifier parameter yet.
	h, err := NewHostWithVerifier(dir, verifier)
	if err != nil {
		t.Fatalf("NewHostWithVerifier: %v", err)
	}

	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover(): %v", err)
	}

	err = h.Start("test-stub")
	if err == nil {
		t.Fatal("Start with mismatched signature: expected error (ErrUntrustedPlugin), got nil")
	}
}

// TestHost_Start_VerifierNilAllowsUnsigned verifies that when no verifier is
// configured on the Host, unsigned plugins are launched with a warning (not
// rejected). This enables test fixtures and development use.
//
// CURRENTLY FAILS: Host.Start() is a stub; subprocess never launches.
func TestHost_Start_VerifierNilAllowsUnsigned(t *testing.T) {
	binaryPath := stubBinaryPath(t)

	dir := t.TempDir()
	destPath := filepath.Join(dir, "agentkms-plugin-test-stub")
	data, _ := os.ReadFile(binaryPath)
	if err := os.WriteFile(destPath, data, 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	// No verifier — NewHost(dir) with nil verifier.
	h, err := NewHost(dir) // current signature; will need NewHostWithVerifier(dir, nil) or same
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover(): %v", err)
	}

	// EXPECT FAIL: Start is a stub, subprocess not launched.
	if err := h.Start("test-stub"); err != nil {
		t.Fatalf("Start with nil verifier and no .sig: unexpected error: %v", err)
	}
	defer h.StopAll()

	if !h.IsRunning("test-stub") {
		t.Error("IsRunning('test-stub') = false, want true — stub Start() does not actually launch")
	}
}

// TestHost_IsRunning_TrueAfterStart verifies IsRunning returns true for a
// plugin that was successfully started.
//
// CURRENTLY FAILS: IsRunning() always returns false.
func TestHost_IsRunning_TrueAfterStart(t *testing.T) {
	binaryPath := stubBinaryPath(t)

	dir := t.TempDir()
	destPath := filepath.Join(dir, "agentkms-plugin-test-stub")
	data, _ := os.ReadFile(binaryPath)
	_ = os.WriteFile(destPath, data, 0o755)

	h, _ := NewHost(dir)
	_, _ = h.Discover()

	if err := h.Start("test-stub"); err != nil {
		t.Skipf("Start failed (expected until implementation lands): %v", err)
	}
	defer h.StopAll()

	// EXPECT FAIL: IsRunning always false.
	if !h.IsRunning("test-stub") {
		t.Error("IsRunning('test-stub') = false after Start, want true")
	}
}

// TestHost_Stop_SetsIsRunningFalse verifies that Stop() terminates the
// subprocess and IsRunning returns false afterwards.
//
// CURRENTLY FAILS: Stop() is a no-op stub.
func TestHost_Stop_SetsIsRunningFalse(t *testing.T) {
	binaryPath := stubBinaryPath(t)

	dir := t.TempDir()
	destPath := filepath.Join(dir, "agentkms-plugin-test-stub")
	data, _ := os.ReadFile(binaryPath)
	_ = os.WriteFile(destPath, data, 0o755)

	h, _ := NewHost(dir)
	_, _ = h.Discover()

	if err := h.Start("test-stub"); err != nil {
		t.Skipf("Start failed (expected until implementation lands): %v", err)
	}

	if err := h.Stop("test-stub"); err != nil {
		t.Fatalf("Stop('test-stub') returned unexpected error: %v", err)
	}

	// EXPECT FAIL: IsRunning always false anyway; this test verifies the
	// transition true→false, which requires Start to work first.
	if h.IsRunning("test-stub") {
		t.Error("IsRunning('test-stub') = true after Stop, want false")
	}
}

// TestHost_StopAll_KillsAllSubprocesses verifies that StopAll terminates
// every running plugin subprocess.
//
// CURRENTLY FAILS: StopAll is a no-op.
func TestHost_StopAll_KillsAllSubprocesses(t *testing.T) {
	binaryPath := stubBinaryPath(t)

	dir := t.TempDir()
	for _, name := range []string{"agentkms-plugin-test-stub", "agentkms-plugin-test-stub-b"} {
		destPath := filepath.Join(dir, name)
		data, _ := os.ReadFile(binaryPath)
		_ = os.WriteFile(destPath, data, 0o755)
	}

	h, _ := NewHost(dir)
	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	started := 0
	for _, name := range []string{"test-stub", "test-stub-b"} {
		if err := h.Start(name); err == nil {
			started++
		}
	}
	if started == 0 {
		t.Skip("no plugins started (expected until implementation lands)")
	}

	h.StopAll()

	// EXPECT FAIL: IsRunning always false; this verifies real transition.
	for _, name := range []string{"test-stub", "test-stub-b"} {
		if h.IsRunning(name) {
			t.Errorf("IsRunning(%q) = true after StopAll, want false", name)
		}
	}
}

// TestHost_Start_AlreadyRunningIsNoop verifies that calling Start twice for
// the same plugin is idempotent — returns nil without launching a second
// subprocess.
//
// CURRENTLY FAILS: Start is a stub.
func TestHost_Start_AlreadyRunningIsNoop(t *testing.T) {
	binaryPath := stubBinaryPath(t)

	dir := t.TempDir()
	destPath := filepath.Join(dir, "agentkms-plugin-test-stub")
	data, _ := os.ReadFile(binaryPath)
	_ = os.WriteFile(destPath, data, 0o755)

	h, _ := NewHost(dir)
	_, _ = h.Discover()

	if err := h.Start("test-stub"); err != nil {
		t.Skipf("Start failed (expected until implementation lands): %v", err)
	}
	defer h.StopAll()

	// Second Start on an already-running plugin must be a no-op.
	// EXPECT FAIL: Start is a stub and does nothing, so this trivially passes
	// today — but once Start actually launches a subprocess, calling it twice
	// must NOT launch a second one.
	if err := h.Start("test-stub"); err != nil {
		t.Errorf("Start called twice: got error on second call, want nil (idempotent): %v", err)
	}
}

// TestHost_Start_RegistersValidatorInRegistry verifies that after Start,
// the plugin's ScopeValidator is available via registry.Lookup(kind).
//
// CURRENTLY FAILS: Start is a stub; no gRPC adapter is registered.
func TestHost_Start_RegistersValidatorInRegistry(t *testing.T) {
	binaryPath := stubBinaryPath(t)

	dir := t.TempDir()
	destPath := filepath.Join(dir, "agentkms-plugin-test-stub")
	data, _ := os.ReadFile(binaryPath)
	_ = os.WriteFile(destPath, data, 0o755)

	registry := NewRegistry()

	// EXPECT FAIL: NewHostWithRegistry does not exist yet.
	h, err := NewHostWithRegistry(dir, registry)
	if err != nil {
		t.Fatalf("NewHostWithRegistry: %v", err)
	}
	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if err := h.Start("test-stub"); err != nil {
		t.Skipf("Start failed (expected until implementation lands): %v", err)
	}
	defer h.StopAll()

	// The stub plugin returns Kind = "test-stub".
	// EXPECT FAIL: Lookup will return "not registered" because Start is a stub.
	v, err := registry.Lookup("test-stub")
	if err != nil {
		t.Fatalf("registry.Lookup('test-stub') after Start: %v", err)
	}
	if v == nil {
		t.Error("Lookup('test-stub') returned nil validator, want gRPC adapter")
	}
}

// TestHost_SignedBinary_Accepted verifies that a correctly signed plugin
// binary is accepted and launched.
//
// CURRENTLY FAILS: Host.Start() is a stub; no signature checking occurs.
func TestHost_SignedBinary_Accepted(t *testing.T) {
	binaryPath := stubBinaryPath(t)

	dir := t.TempDir()
	destPath := filepath.Join(dir, "agentkms-plugin-test-stub")
	data, _ := os.ReadFile(binaryPath)
	if err := os.WriteFile(destPath, data, 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	// Sign the binary with a fresh key and configure the host to trust it.
	verifier := makeVerifierAndSign(t, destPath)

	// EXPECT FAIL: NewHostWithVerifier does not exist.
	h, err := NewHostWithVerifier(dir, verifier)
	if err != nil {
		t.Fatalf("NewHostWithVerifier: %v", err)
	}
	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// EXPECT FAIL: Start is a stub.
	if err := h.Start("test-stub"); err != nil {
		t.Fatalf("Start with valid signature: unexpected error: %v", err)
	}
	defer h.StopAll()

	if !h.IsRunning("test-stub") {
		t.Error("IsRunning = false after Start with valid signature, want true")
	}
}
