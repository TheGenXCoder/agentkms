package credentials

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDevKVStore_GetSecret(t *testing.T) {
	s := NewDevKVStore()
	s.Set("kv/data/generic/forge/telegram", map[string]string{"token": "test-token"})

	got, err := s.GetSecret(context.Background(), "kv/data/generic/forge/telegram")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["token"] != "test-token" {
		t.Errorf("got token=%q, want %q", got["token"], "test-token")
	}
}

func TestDevKVStore_GetSecret_NotFound(t *testing.T) {
	s := NewDevKVStore()
	_, err := s.GetSecret(context.Background(), "kv/data/generic/missing")
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
}

func TestDevKVStore_ReturnsCopy(t *testing.T) {
	s := NewDevKVStore()
	s.Set("kv/data/generic/forge/telegram", map[string]string{"token": "original"})

	got, _ := s.GetSecret(context.Background(), "kv/data/generic/forge/telegram")
	got["token"] = "mutated"

	got2, _ := s.GetSecret(context.Background(), "kv/data/generic/forge/telegram")
	if got2["token"] != "original" {
		t.Errorf("mutation escaped: got %q, want %q", got2["token"], "original")
	}
}

func TestDevKVStore_SetGeneric(t *testing.T) {
	s := NewDevKVStore()
	s.SetGeneric("forge/telegram", map[string]string{"token": "tg-token"})

	got, err := s.GetSecret(context.Background(), "kv/data/generic/forge/telegram")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["token"] != "tg-token" {
		t.Errorf("got %q, want %q", got["token"], "tg-token")
	}
}

func TestDevKVStore_SetLLM(t *testing.T) {
	s := NewDevKVStore()
	s.SetLLM("anthropic", "sk-ant-test")

	got, err := s.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["api_key"] != "sk-ant-test" {
		t.Errorf("got %q, want %q", got["api_key"], "sk-ant-test")
	}
}

func TestNewDevKVStoreFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	data := devKVFile{
		"kv/data/generic/forge/telegram": {"token": "tg-from-file"},
		"kv/data/llm/anthropic":          {"api_key": "sk-from-file"},
	}
	raw, _ := json.Marshal(data)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}

	store, err := NewDevKVStoreFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSecret(context.Background(), "kv/data/generic/forge/telegram")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["token"] != "tg-from-file" {
		t.Errorf("got %q, want %q", got["token"], "tg-from-file")
	}

	got2, err := store.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2["api_key"] != "sk-from-file" {
		t.Errorf("got %q, want %q", got2["api_key"], "sk-from-file")
	}
}

func TestNewDevKVStoreFromFile_PermissionRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test file permissions as root")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := NewDevKVStoreFromFile(path)
	if err == nil {
		t.Fatal("expected error for 0644 permissions, got nil")
	}
}

func TestNewDevKVStoreFromFile_Missing(t *testing.T) {
	_, err := NewDevKVStoreFromFile("/nonexistent/path/secrets.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
