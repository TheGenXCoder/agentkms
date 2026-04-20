package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

// helper: create a fake plugin binary at the given path.
func createFakeBinary(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho plugin"), 0o755); err != nil {
		t.Fatalf("create fake binary: %v", err)
	}
}

func TestManager_Install_CopiesBinary(t *testing.T) {
	pluginDir := t.TempDir()
	srcDir := t.TempDir()

	srcPath := filepath.Join(srcDir, "agentkms-plugin-foo")
	createFakeBinary(t, srcPath)

	mgr := NewManager(pluginDir, NewRegistry())
	_, err := mgr.Install(srcPath)
	if err != nil {
		t.Fatalf("Install() unexpected error: %v", err)
	}

	destPath := filepath.Join(pluginDir, "agentkms-plugin-foo")
	if _, err := os.Stat(destPath); os.IsNotExist(err) {
		t.Fatalf("expected binary at %s, but it does not exist", destPath)
	}
}

func TestManager_Install_ReturnsMetadata(t *testing.T) {
	pluginDir := t.TempDir()
	srcDir := t.TempDir()

	srcPath := filepath.Join(srcDir, "agentkms-plugin-bar")
	createFakeBinary(t, srcPath)

	mgr := NewManager(pluginDir, NewRegistry())
	meta, err := mgr.Install(srcPath)
	if err != nil {
		t.Fatalf("Install() unexpected error: %v", err)
	}
	if meta == nil {
		t.Fatal("Install() returned nil PluginMeta")
	}
	if meta.Name != "bar" {
		t.Errorf("expected Name = %q, got %q", "bar", meta.Name)
	}
	expectedPath := filepath.Join(pluginDir, "agentkms-plugin-bar")
	if meta.Path != expectedPath {
		t.Errorf("expected Path = %q, got %q", expectedPath, meta.Path)
	}
}

func TestManager_Install_SourceNotExist(t *testing.T) {
	pluginDir := t.TempDir()

	mgr := NewManager(pluginDir, NewRegistry())
	_, err := mgr.Install("/nonexistent/path/agentkms-plugin-ghost")
	if err == nil {
		t.Fatal("expected error when source does not exist, got nil")
	}
}

func TestManager_Remove_DeletesBinary(t *testing.T) {
	pluginDir := t.TempDir()
	srcDir := t.TempDir()

	srcPath := filepath.Join(srcDir, "agentkms-plugin-baz")
	createFakeBinary(t, srcPath)

	mgr := NewManager(pluginDir, NewRegistry())
	_, err := mgr.Install(srcPath)
	if err != nil {
		t.Fatalf("Install() unexpected error: %v", err)
	}

	// Verify the binary was actually installed before testing removal.
	destPath := filepath.Join(pluginDir, "agentkms-plugin-baz")
	if _, err := os.Stat(destPath); os.IsNotExist(err) {
		t.Fatalf("precondition failed: binary not found at %s after Install()", destPath)
	}

	if err := mgr.Remove("baz"); err != nil {
		t.Fatalf("Remove() unexpected error: %v", err)
	}

	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Fatalf("expected binary at %s to be removed, but it still exists", destPath)
	}
}

func TestManager_Remove_NotInstalled(t *testing.T) {
	pluginDir := t.TempDir()

	mgr := NewManager(pluginDir, NewRegistry())
	err := mgr.Remove("nonexistent")
	if err == nil {
		t.Fatal("expected error when removing non-existent plugin, got nil")
	}
}

func TestManager_Installed_ListsAll(t *testing.T) {
	pluginDir := t.TempDir()
	srcDir := t.TempDir()

	mgr := NewManager(pluginDir, NewRegistry())

	for _, name := range []string{"agentkms-plugin-alpha", "agentkms-plugin-beta"} {
		srcPath := filepath.Join(srcDir, name)
		createFakeBinary(t, srcPath)
		if _, err := mgr.Install(srcPath); err != nil {
			t.Fatalf("Install(%s) unexpected error: %v", name, err)
		}
	}

	installed, err := mgr.Installed()
	if err != nil {
		t.Fatalf("Installed() unexpected error: %v", err)
	}
	if len(installed) != 2 {
		t.Fatalf("expected 2 installed plugins, got %d", len(installed))
	}

	names := map[string]bool{}
	for _, m := range installed {
		names[m.Name] = true
	}
	if !names["alpha"] {
		t.Error("expected plugin 'alpha' in installed list")
	}
	if !names["beta"] {
		t.Error("expected plugin 'beta' in installed list")
	}
}

func TestManager_Installed_EmptyDir(t *testing.T) {
	pluginDir := t.TempDir()

	mgr := NewManager(pluginDir, NewRegistry())
	installed, err := mgr.Installed()
	if err != nil {
		t.Fatalf("Installed() unexpected error: %v", err)
	}
	if installed == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(installed) != 0 {
		t.Fatalf("expected 0 installed plugins, got %d", len(installed))
	}
}
