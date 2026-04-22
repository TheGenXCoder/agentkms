//go:build plugin_integration

package plugin

// integration_test.go — end-to-end plugin integration tests.
//
// Build tag: plugin_integration
// These tests are excluded from the default `go test ./...` run because they
// require the test-stub binary to be built and (optionally) the Python plugin
// environment to be set up.
//
// To run:
//   go build -o internal/plugin/testdata/stub-validator/agentkms-plugin-test-stub \
//       ./internal/plugin/testdata/stub-validator/
//   go test -tags plugin_integration ./internal/plugin/... -v -run TestPluginIntegration
//
// ALL TESTS IN THIS FILE ARE EXPECTED TO FAIL until the implementation lands.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
)

// TestPluginIntegration_StartConnectValidate is the core end-to-end scenario:
//
//  1. Host discovers a plugin binary from testdata/
//  2. Host.Start() launches the subprocess via go-plugin handshake
//  3. Registry.Lookup("test-stub") returns a gRPC-backed ScopeValidator
//  4. Validate() is called on a well-formed scope and returns nil
//
// CURRENTLY FAILS: Host.Start() is a stub; no subprocess is launched;
// NewHostWithRegistry does not exist; gRPC adapters do not exist.
func TestPluginIntegration_StartConnectValidate(t *testing.T) {
	binaryPath := filepath.Join("testdata", "stub-validator", "agentkms-plugin-test-stub")
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Fatal("test-stub binary not found — build it first:\n  go build -o internal/plugin/testdata/stub-validator/agentkms-plugin-test-stub ./internal/plugin/testdata/stub-validator/")
	}

	dir := t.TempDir()
	destPath := filepath.Join(dir, "agentkms-plugin-test-stub")
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read stub binary: %v", err)
	}
	if err := os.WriteFile(destPath, data, 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	registry := NewRegistry()

	// EXPECT FAIL: NewHostWithRegistry does not exist.
	h, err := NewHostWithRegistry(dir, registry)
	if err != nil {
		t.Fatalf("NewHostWithRegistry: %v", err)
	}

	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// EXPECT FAIL: Start is a stub; subprocess not launched.
	if err := h.Start("test-stub"); err != nil {
		t.Fatalf("Start('test-stub'): %v", err)
	}
	t.Cleanup(func() { h.StopAll() })

	// EXPECT FAIL: Lookup returns error (nothing registered by stub Start).
	validator, err := registry.Lookup("test-stub")
	if err != nil {
		t.Fatalf("registry.Lookup('test-stub'): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scope := credentials.Scope{
		Kind: "test-stub",
		Params: map[string]any{
			"resource": "test-resource",
		},
	}

	// EXPECT FAIL: Validate will fail if validator is nil or if gRPC not connected.
	if err := validator.Validate(ctx, scope); err != nil {
		t.Errorf("Validate returned unexpected error: %v", err)
	}
}

// TestPluginIntegration_SignatureVerifiedOnLoad verifies the full signed-load
// path end-to-end:
//
//  1. Binary is signed with a freshly generated key
//  2. Host is configured with the matching Verifier
//  3. Start() succeeds and the plugin is reachable via gRPC
//
// CURRENTLY FAILS: NewHostWithVerifier does not exist; Start is a stub.
func TestPluginIntegration_SignatureVerifiedOnLoad(t *testing.T) {
	binaryPath := filepath.Join("testdata", "stub-validator", "agentkms-plugin-test-stub")
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Fatal("test-stub binary not found — build it first")
	}

	dir := t.TempDir()
	destPath := filepath.Join(dir, "agentkms-plugin-test-stub")
	data, _ := os.ReadFile(binaryPath)
	if err := os.WriteFile(destPath, data, 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	// Sign the binary and get back a verifier that trusts that key.
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
		t.Fatalf("Start with valid signature: %v", err)
	}
	t.Cleanup(func() { h.StopAll() })

	if !h.IsRunning("test-stub") {
		t.Error("IsRunning = false after signed Start, want true")
	}
}

// TestPluginIntegration_TamperedBinaryRejected verifies that a tampered
// binary (signature does not match binary contents) is rejected at Start time
// and does NOT launch a subprocess.
//
// CURRENTLY FAILS: NewHostWithVerifier does not exist; Start never checks sig.
func TestPluginIntegration_TamperedBinaryRejected(t *testing.T) {
	binaryPath := filepath.Join("testdata", "stub-validator", "agentkms-plugin-test-stub")
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Fatal("test-stub binary not found — build it first")
	}

	dir := t.TempDir()
	destPath := filepath.Join(dir, "agentkms-plugin-test-stub")
	data, _ := os.ReadFile(binaryPath)
	if err := os.WriteFile(destPath, data, 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	// Sign with a fresh key (produces a valid .sig for the original binary).
	verifier := makeVerifierAndSign(t, destPath)

	// Now tamper with the binary — append a null byte so the hash changes.
	f, err := os.OpenFile(destPath, os.O_APPEND|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatalf("open binary for tampering: %v", err)
	}
	if _, err := f.Write([]byte{0x00}); err != nil {
		f.Close()
		t.Fatalf("tamper binary: %v", err)
	}
	f.Close()

	// EXPECT FAIL: NewHostWithVerifier does not exist.
	h, err := NewHostWithVerifier(dir, verifier)
	if err != nil {
		t.Fatalf("NewHostWithVerifier: %v", err)
	}

	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// EXPECT FAIL: Start is a stub that returns nil without checking signatures.
	err = h.Start("test-stub")
	if err == nil {
		t.Fatal("Start with tampered binary: expected error, got nil — signature not being checked")
	}

	// The subprocess must NOT be running after a rejection.
	if h.IsRunning("test-stub") {
		t.Error("IsRunning = true after tampered-binary rejection, want false")
	}
}
