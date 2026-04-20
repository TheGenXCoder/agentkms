package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHost_Discover_FindsPluginBinaries verifies that Discover() finds
// binaries matching the agentkms-plugin-<name> naming convention.
func TestHost_Discover_FindsPluginBinaries(t *testing.T) {
	dir := t.TempDir()

	// Create fake plugin binaries.
	for _, name := range []string{"agentkms-plugin-foo", "agentkms-plugin-bar"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("failed to create fake binary %s: %v", name, err)
		}
	}

	h, err := NewHost(dir)
	if err != nil {
		t.Fatalf("NewHost(%q) returned error: %v", dir, err)
	}

	plugins, err := h.Discover()
	if err != nil {
		t.Fatalf("Discover() returned error: %v", err)
	}

	if len(plugins) != 2 {
		t.Fatalf("Discover() returned %d plugins, want 2", len(plugins))
	}

	names := map[string]bool{}
	for _, p := range plugins {
		names[p.Name] = true
	}
	if !names["foo"] {
		t.Errorf("expected plugin 'foo' in results, got %v", plugins)
	}
	if !names["bar"] {
		t.Errorf("expected plugin 'bar' in results, got %v", plugins)
	}
}

// TestHost_Discover_IgnoresNonPluginFiles verifies that files not matching
// the agentkms-plugin-<name> pattern are ignored.
func TestHost_Discover_IgnoresNonPluginFiles(t *testing.T) {
	dir := t.TempDir()

	files := []string{"agentkms-plugin-foo", "random-binary", "README.md"}
	for _, name := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("data"), 0o755); err != nil {
			t.Fatalf("failed to create file %s: %v", name, err)
		}
	}

	h, err := NewHost(dir)
	if err != nil {
		t.Fatalf("NewHost(%q) returned error: %v", dir, err)
	}

	plugins, err := h.Discover()
	if err != nil {
		t.Fatalf("Discover() returned error: %v", err)
	}

	if len(plugins) != 1 {
		t.Fatalf("Discover() returned %d plugins, want 1 (only agentkms-plugin-foo)", len(plugins))
	}
	if plugins[0].Name != "foo" {
		t.Errorf("expected plugin name 'foo', got %q", plugins[0].Name)
	}
}

// TestHost_Discover_EmptyDir verifies that an empty plugin directory
// returns an empty slice and no error.
func TestHost_Discover_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	h, err := NewHost(dir)
	if err != nil {
		t.Fatalf("NewHost(%q) returned error: %v", dir, err)
	}

	plugins, err := h.Discover()
	if err != nil {
		t.Fatalf("Discover() returned error: %v", err)
	}

	if plugins == nil {
		t.Fatal("Discover() returned nil, want empty slice")
	}
	if len(plugins) != 0 {
		t.Fatalf("Discover() returned %d plugins, want 0", len(plugins))
	}
}

// TestHost_Discover_DirNotExist verifies that a non-existent plugin
// directory causes an error.
func TestHost_Discover_DirNotExist(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")

	h, err := NewHost(dir)
	if err != nil {
		// Acceptable: error at NewHost time for non-existent dir.
		return
	}

	_, err = h.Discover()
	if err == nil {
		t.Fatal("Discover() on non-existent dir should return error, got nil")
	}
}

// TestHost_Start_UnknownPlugin verifies that starting a plugin that
// hasn't been discovered returns an error.
func TestHost_Start_UnknownPlugin(t *testing.T) {
	dir := t.TempDir()

	h, err := NewHost(dir)
	if err != nil {
		t.Fatalf("NewHost(%q) returned error: %v", dir, err)
	}

	err = h.Start("nonexistent")
	if err == nil {
		t.Fatal("Start('nonexistent') should return error, got nil")
	}
}

// TestHost_IsRunning_NotStarted verifies that IsRunning returns false
// for a plugin that hasn't been started.
func TestHost_IsRunning_NotStarted(t *testing.T) {
	dir := t.TempDir()

	// Create a plugin binary so it can be discovered.
	path := filepath.Join(dir, "agentkms-plugin-foo")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("failed to create fake binary: %v", err)
	}

	h, err := NewHost(dir)
	if err != nil {
		t.Fatalf("NewHost(%q) returned error: %v", dir, err)
	}

	if h.IsRunning("foo") {
		t.Error("IsRunning('foo') returned true before Start, want false")
	}
}

// TestHost_List_ReturnsDiscoveredPlugins verifies that after Discover(),
// List() returns the same set of plugins.
func TestHost_List_ReturnsDiscoveredPlugins(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{"agentkms-plugin-alpha", "agentkms-plugin-beta"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("failed to create fake binary %s: %v", name, err)
		}
	}

	h, err := NewHost(dir)
	if err != nil {
		t.Fatalf("NewHost(%q) returned error: %v", dir, err)
	}

	_, err = h.Discover()
	if err != nil {
		t.Fatalf("Discover() returned error: %v", err)
	}

	list := h.List()
	if len(list) != 2 {
		t.Fatalf("List() returned %d plugins, want 2", len(list))
	}

	names := map[string]bool{}
	for _, p := range list {
		names[p.Name] = true
	}
	if !names["alpha"] || !names["beta"] {
		t.Errorf("List() missing expected plugins, got %v", list)
	}
}

// TestHost_NewHost_InvalidDir verifies that NewHost returns an error
// when given a path that is a file, not a directory.
func TestHost_NewHost_InvalidDir(t *testing.T) {
	// Create a file where a directory is expected.
	f, err := os.CreateTemp(t.TempDir(), "not-a-dir")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	f.Close()

	_, err = NewHost(f.Name())
	if err == nil {
		t.Fatalf("NewHost(%q) should return error for file path, got nil", f.Name())
	}
}
