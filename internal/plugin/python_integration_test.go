//go:build plugin_python_integration

package plugin

// python_integration_test.go — end-to-end test verifying that the Python
// reference plugin can connect to the Go host over standard protobuf gRPC.
//
// Build tag: plugin_python_integration
//
// Prerequisites:
//   - Python 3.9+
//   - pip install grpcio grpcio-tools protobuf
//   - bash examples/plugins/python-honeytoken-validator/generate.sh
//
// To run:
//
//	go test -tags=plugin_python_integration -race -v \
//	    ./internal/plugin/... -run TestPythonPlugin
//
// The test skips cleanly (not fails) if Python or grpc is unavailable,
// so it is safe to run in CI with a simple check for the grpc dependency.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
	goplugin "github.com/hashicorp/go-plugin"
)

// TestPythonPlugin_ValidScopePassesValidation launches the Python honeytoken
// reference plugin as a subprocess via go-plugin, connects over standard
// protobuf gRPC, sends a valid Validate RPC, and asserts no error is returned.
//
// This test proves: wire format compatibility between Go host (protoc-generated
// stubs, standard protobuf binary encoding) and Python plugin (grpc_tools.protoc
// stubs, standard protobuf binary encoding).
func TestPythonPlugin_ValidScopePassesValidation(t *testing.T) {
	pythonBin := findPythonBin(t)
	pluginScript := filepath.Join("..", "..", "examples", "plugins", "python-honeytoken-validator", "plugin.py")
	if _, err := os.Stat(pluginScript); os.IsNotExist(err) {
		t.Skipf("python plugin not found at %s — run from repo root", pluginScript)
	}

	// Check that grpc is importable in the Python env.
	if !pythonHasGRPC(pythonBin) {
		// TODO(#0): skip until Python grpc dependency is available in CI — indefinite
		t.Skipf("Python grpc not available (pip install grpcio grpcio-tools protobuf); skipping Python interop test")
	}

	// Check that the generated stubs exist.
	stubDir := filepath.Join("..", "..", "examples", "plugins", "python-honeytoken-validator")
	pb2 := filepath.Join(stubDir, "plugin_pb2.py")
	if _, err := os.Stat(pb2); os.IsNotExist(err) {
		t.Skipf("Python gRPC stubs not generated — run: bash examples/plugins/python-honeytoken-validator/generate.sh")
	}

	// Build a go-plugin client that launches the Python script.
	dir := t.TempDir()
	// go-plugin requires Cmd to be the plugin binary; for Python we wrap it
	// in a script that sets PYTHONPATH so the generated stubs in stubDir are found.
	wrapperPath := filepath.Join(dir, "agentkms-plugin-honeytoken")
	wrapperContent := "#!/bin/sh\n" +
		"PYTHONPATH=" + stubDir + " exec " + pythonBin + " " + pluginScript + " \"$@\"\n"
	if err := os.WriteFile(wrapperPath, []byte(wrapperContent), 0o755); err != nil {
		t.Fatalf("write wrapper script: %v", err)
	}

	registry := NewRegistry()
	h, err := NewHostWithRegistry(dir, registry)
	if err != nil {
		t.Fatalf("NewHostWithRegistry: %v", err)
	}

	if _, err := h.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if err := h.Start("honeytoken"); err != nil {
		t.Fatalf("Start Python plugin: %v", err)
	}
	t.Cleanup(func() { h.StopAll() })

	validator, err := registry.Lookup("honeytoken")
	if err != nil {
		t.Fatalf("registry.Lookup('honeytoken'): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Valid honeytoken scope — name and purpose both present.
	validScope := credentials.Scope{
		Kind: "honeytoken",
		Params: map[string]any{
			"name":    "prod-anthropic-key-2026",
			"purpose": "detect unauthorized access to production LLM keys",
		},
	}

	if err := validator.Validate(ctx, validScope); err != nil {
		t.Errorf("Validate(valid honeytoken scope) returned unexpected error: %v", err)
	}

	// Invalid scope — name missing — should return a non-nil error.
	invalidScope := credentials.Scope{
		Kind: "honeytoken",
		Params: map[string]any{
			"purpose": "missing the name field",
		},
	}

	if err := validator.Validate(ctx, invalidScope); err == nil {
		t.Error("Validate(invalid honeytoken scope — missing name) returned nil, want error")
	}
}

// findPythonBin returns the path to a python3 or python binary, or skips the test.
func findPythonBin(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	// TODO(#0): skip until Python is available in CI — indefinite
	t.Skip("python3/python not found in PATH; skipping Python interop test")
	return ""
}

// pythonHasGRPC returns true if the given Python binary can import grpc.
func pythonHasGRPC(pythonBin string) bool {
	cmd := exec.Command(pythonBin, "-c", "import grpc")
	return cmd.Run() == nil
}

// makeVerifierAndSign is defined in signing_test.go — available to all
// build tags within this package.
//
// Declared here as a compile-time reminder that the function is required.
// If this file produces a "declared and not used" error, remove this comment.
var _ = (*goplugin.HandshakeConfig)(nil) // ensure goplugin imported for HandshakeConfig
