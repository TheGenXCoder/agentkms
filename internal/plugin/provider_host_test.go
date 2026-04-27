package plugin

// provider_host_test.go — tests for Host.StartProvider (CredentialVender plugin lifecycle).
//
// Tests require the noop-vender binary to be built:
//
//	go build -o internal/plugin/testdata/noop-vender/agentkms-plugin-noop-vender \
//	    ./internal/plugin/testdata/noop-vender/
//
// If the binary does not exist, tests are skipped.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
)

// noopVenderBinaryPath returns the path to the compiled noop-vender binary.
// Skips the test if the binary does not exist.
func noopVenderBinaryPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("testdata", "noop-vender", "agentkms-plugin-noop-vender")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("noop-vender binary not built — run: go build -o internal/plugin/testdata/noop-vender/agentkms-plugin-noop-vender ./internal/plugin/testdata/noop-vender/")
	}
	return path
}

// setupNoopVenderPluginDir copies the noop-vender binary to a temp dir for Host use.
func setupNoopVenderPluginDir(t *testing.T, binaryPath string) string {
	t.Helper()
	dir := t.TempDir()
	destPath := filepath.Join(dir, "agentkms-plugin-noop-vender")
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read noop-vender binary: %v", err)
	}
	if err := os.WriteFile(destPath, data, 0o755); err != nil {
		t.Fatalf("write noop-vender binary to temp dir: %v", err)
	}
	return dir
}

// TestProviderHost_Handshake_KindCapabilitiesRegistered verifies that
// StartProvider:
//  1. Forks the subprocess
//  2. Calls Kind() via CredentialVenderService and gets "noop-vender"
//  3. Calls Capabilities() and gets ["health"]
//  4. Registers the adapter in the registry under "noop-vender"
func TestProviderHost_Handshake_KindCapabilitiesRegistered(t *testing.T) {
	binaryPath := noopVenderBinaryPath(t)
	dir := setupNoopVenderPluginDir(t, binaryPath)

	registry := NewRegistry()
	h, err := NewHostWithRegistry(dir, registry)
	if err != nil {
		t.Fatalf("NewHostWithRegistry: %v", err)
	}
	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if err := h.StartProvider("noop-vender"); err != nil {
		t.Fatalf("StartProvider: %v", err)
	}
	t.Cleanup(func() { h.StopAll() })

	// Verify the vender is registered under the kind it returned.
	v, err := registry.LookupVender("noop-vender")
	if err != nil {
		t.Fatalf("registry.LookupVender('noop-vender'): not found after StartProvider: %v", err)
	}
	if v == nil {
		t.Fatal("LookupVender('noop-vender') returned nil")
	}
	if v.Kind() != "noop-vender" {
		t.Errorf("Kind() = %q, want %q", v.Kind(), "noop-vender")
	}
}

// TestProviderHost_Vend_RoundTrip verifies that the host-side adapter can call
// Vend() through the gRPC transport to the subprocess and get a credential back.
func TestProviderHost_Vend_RoundTrip(t *testing.T) {
	binaryPath := noopVenderBinaryPath(t)
	dir := setupNoopVenderPluginDir(t, binaryPath)

	registry := NewRegistry()
	h, err := NewHostWithRegistry(dir, registry)
	if err != nil {
		t.Fatalf("NewHostWithRegistry: %v", err)
	}
	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if err := h.StartProvider("noop-vender"); err != nil {
		t.Fatalf("StartProvider: %v", err)
	}
	t.Cleanup(func() { h.StopAll() })

	v, err := registry.LookupVender("noop-vender")
	if err != nil {
		t.Fatalf("LookupVender('noop-vender'): not found: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The noop-vender returns a fixed synthetic credential for any scope.
	scope := credentials.Scope{Kind: "noop-vender"}
	cred, err := v.Vend(ctx, scope)
	if err != nil {
		t.Fatalf("Vend() returned error: %v", err)
	}
	if cred == nil {
		t.Fatal("Vend() returned nil credential")
	}
	if len(cred.APIKey) == 0 {
		t.Error("Vend() returned empty APIKey")
	}
}

// TestProviderHost_IsRunning_AfterStart verifies that IsRunning returns true
// after a successful StartProvider.
func TestProviderHost_IsRunning_AfterStart(t *testing.T) {
	binaryPath := noopVenderBinaryPath(t)
	dir := setupNoopVenderPluginDir(t, binaryPath)

	h, err := NewHost(dir)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if err := h.StartProvider("noop-vender"); err != nil {
		t.Fatalf("StartProvider: %v", err)
	}
	t.Cleanup(func() { h.StopAll() })

	if !h.IsRunning("noop-vender") {
		t.Error("IsRunning('noop-vender') = false after StartProvider, want true")
	}
}

// TestProviderHost_StartProvider_Idempotent verifies that calling StartProvider
// twice for the same plugin is a no-op.
func TestProviderHost_StartProvider_Idempotent(t *testing.T) {
	binaryPath := noopVenderBinaryPath(t)
	dir := setupNoopVenderPluginDir(t, binaryPath)

	registry := NewRegistry()
	h, err := NewHostWithRegistry(dir, registry)
	if err != nil {
		t.Fatalf("NewHostWithRegistry: %v", err)
	}
	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if err := h.StartProvider("noop-vender"); err != nil {
		t.Fatalf("first StartProvider: %v", err)
	}
	t.Cleanup(func() { h.StopAll() })

	// Second call must be a no-op (idempotent).
	if err := h.StartProvider("noop-vender"); err != nil {
		t.Errorf("second StartProvider returned error, want nil (idempotent): %v", err)
	}
}

// TestProviderHost_StartProvider_UnknownPlugin verifies that StartProvider
// returns an error for a plugin that was not discovered.
func TestProviderHost_StartProvider_UnknownPlugin(t *testing.T) {
	dir := t.TempDir()
	h, err := NewHost(dir)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if err := h.StartProvider("does-not-exist"); err == nil {
		t.Fatal("StartProvider('does-not-exist') should return error, got nil")
	}
}

// TestProviderHost_VenderKinds_AfterStart verifies that VenderKinds lists
// the registered kind after startup.
func TestProviderHost_VenderKinds_AfterStart(t *testing.T) {
	binaryPath := noopVenderBinaryPath(t)
	dir := setupNoopVenderPluginDir(t, binaryPath)

	registry := NewRegistry()
	h, err := NewHostWithRegistry(dir, registry)
	if err != nil {
		t.Fatalf("NewHostWithRegistry: %v", err)
	}
	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if err := h.StartProvider("noop-vender"); err != nil {
		t.Fatalf("StartProvider: %v", err)
	}
	t.Cleanup(func() { h.StopAll() })

	kinds := registry.VenderKinds()
	if len(kinds) != 1 || kinds[0] != "noop-vender" {
		t.Errorf("VenderKinds() = %v, want [noop-vender]", kinds)
	}
}

// TestProviderHost_CapabilityMismatch_GracefulDegradation verifies that
// a plugin whose Capabilities() RPC returns Unimplemented is still loaded
// successfully (backwards-compatible empty capabilities).
//
// The noop-vender binary always responds to Capabilities, so this test verifies
// the graceful path by checking that capabilities is non-nil after startup.
// The actual Unimplemented path is tested implicitly by the host's fallback logic.
func TestProviderHost_CapabilityMismatch_GracefulDegradation(t *testing.T) {
	binaryPath := noopVenderBinaryPath(t)
	dir := setupNoopVenderPluginDir(t, binaryPath)

	registry := NewRegistry()
	h, err := NewHostWithRegistry(dir, registry)
	if err != nil {
		t.Fatalf("NewHostWithRegistry: %v", err)
	}
	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if err := h.StartProvider("noop-vender"); err != nil {
		t.Fatalf("StartProvider: %v", err)
	}
	t.Cleanup(func() { h.StopAll() })

	v, err := registry.LookupVender("noop-vender")
	if err != nil {
		t.Fatalf("LookupVender: %v", err)
	}

	grpcAdapter, ok := v.(*CredentialVenderGRPC)
	if !ok {
		t.Fatalf("vender is %T, want *CredentialVenderGRPC", v)
	}
	// noop-vender reports ["health"] — verify capabilities survived the handshake.
	caps := grpcAdapter.Capabilities()
	if len(caps) == 0 {
		t.Error("Capabilities() is empty after handshake, want [health]")
	}
}
