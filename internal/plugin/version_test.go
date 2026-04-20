package plugin

import (
	"strings"
	"testing"
)

// ---------- Test helpers ----------

func newTestPluginInfo(kind string, apiVersion int) PluginInfo {
	return PluginInfo{
		Kind:       kind,
		APIVersion: apiVersion,
		Name:       "test-plugin-" + kind,
		Version:    "0.1.0",
	}
}

// ---------- Tests ----------

func TestVersion_CurrentAPIVersion_Defined(t *testing.T) {
	if CurrentAPIVersion <= 0 {
		t.Fatalf("CurrentAPIVersion must be a positive integer, got %d", CurrentAPIVersion)
	}
}

func TestVersion_RegisterWithInfo_ValidVersion(t *testing.T) {
	r := NewRegistry()
	info := newTestPluginInfo("github-pat", CurrentAPIVersion)
	v := &mockScopeValidator{kind: "github-pat"}

	err := r.RegisterWithInfo(info, v)
	if err != nil {
		t.Fatalf("RegisterWithInfo with APIVersion=CurrentAPIVersion should succeed, got error: %v", err)
	}
}

func TestVersion_RegisterWithInfo_ZeroVersion(t *testing.T) {
	r := NewRegistry()
	info := newTestPluginInfo("github-pat", 0)
	v := &mockScopeValidator{kind: "github-pat"}

	err := r.RegisterWithInfo(info, v)
	if err == nil {
		t.Fatal("RegisterWithInfo with APIVersion=0 should return error, got nil")
	}
	if !strings.Contains(err.Error(), "did not declare") {
		t.Errorf("error should mention 'did not declare API version', got: %v", err)
	}
}

func TestVersion_RegisterWithInfo_TooNew(t *testing.T) {
	r := NewRegistry()
	info := newTestPluginInfo("github-pat", CurrentAPIVersion+1)
	v := &mockScopeValidator{kind: "github-pat"}

	err := r.RegisterWithInfo(info, v)
	if err == nil {
		t.Fatal("RegisterWithInfo with APIVersion > CurrentAPIVersion should return error, got nil")
	}
	if !strings.Contains(err.Error(), "newer") {
		t.Errorf("error should mention 'newer API version', got: %v", err)
	}
}

func TestVersion_RegisterWithInfo_TooOld(t *testing.T) {
	if CurrentAPIVersion <= 1 {
		t.Skip("CurrentAPIVersion is 1; cannot test outdated version without a version < 1")
	}
	r := NewRegistry()
	info := newTestPluginInfo("github-pat", CurrentAPIVersion-1)
	v := &mockScopeValidator{kind: "github-pat"}

	err := r.RegisterWithInfo(info, v)
	if err == nil {
		t.Fatal("RegisterWithInfo with APIVersion < CurrentAPIVersion should return error, got nil")
	}
	if !strings.Contains(err.Error(), "outdated") {
		t.Errorf("error should mention 'outdated API version', got: %v", err)
	}
}

func TestVersion_LookupInfo_ReturnsMetadata(t *testing.T) {
	r := NewRegistry()
	info := newTestPluginInfo("aws-sts", CurrentAPIVersion)
	v := &mockScopeValidator{kind: "aws-sts"}

	if err := r.RegisterWithInfo(info, v); err != nil {
		t.Fatalf("RegisterWithInfo failed: %v", err)
	}

	gotV, gotInfo, err := r.LookupInfo("aws-sts")
	if err != nil {
		t.Fatalf("LookupInfo returned unexpected error: %v", err)
	}
	if gotV != v {
		t.Errorf("LookupInfo returned wrong validator")
	}
	if gotInfo == nil {
		t.Fatal("LookupInfo returned nil PluginInfo")
	}
	if gotInfo.Kind != "aws-sts" {
		t.Errorf("PluginInfo.Kind = %q, want %q", gotInfo.Kind, "aws-sts")
	}
	if gotInfo.APIVersion != CurrentAPIVersion {
		t.Errorf("PluginInfo.APIVersion = %d, want %d", gotInfo.APIVersion, CurrentAPIVersion)
	}
	if gotInfo.Name != "test-plugin-aws-sts" {
		t.Errorf("PluginInfo.Name = %q, want %q", gotInfo.Name, "test-plugin-aws-sts")
	}
	if gotInfo.Version != "0.1.0" {
		t.Errorf("PluginInfo.Version = %q, want %q", gotInfo.Version, "0.1.0")
	}
}

func TestVersion_LookupInfo_NotFound(t *testing.T) {
	r := NewRegistry()

	_, _, err := r.LookupInfo("nonexistent")
	if err == nil {
		t.Fatal("LookupInfo should return error for unregistered kind, got nil")
	}
}

func TestVersion_Register_BackCompat(t *testing.T) {
	r := NewRegistry()
	v := &mockScopeValidator{kind: "github-pat"}

	// Legacy Register still works.
	if err := r.Register("github-pat", v); err != nil {
		t.Fatalf("Register returned unexpected error: %v", err)
	}

	// Can still Lookup via the original method.
	got, err := r.Lookup("github-pat")
	if err != nil {
		t.Fatalf("Lookup returned unexpected error: %v", err)
	}
	if got != v {
		t.Errorf("Lookup returned wrong validator after legacy Register")
	}

	// RegisterWithInfo for a different kind should also work in the same registry.
	info := newTestPluginInfo("aws-sts", CurrentAPIVersion)
	v2 := &mockScopeValidator{kind: "aws-sts"}
	if err := r.RegisterWithInfo(info, v2); err != nil {
		t.Fatalf("RegisterWithInfo failed alongside legacy Register: %v", err)
	}

	got2, err := r.Lookup("aws-sts")
	if err != nil {
		t.Fatalf("Lookup(aws-sts) returned unexpected error: %v", err)
	}
	if got2 != v2 {
		t.Errorf("Lookup(aws-sts) returned wrong validator")
	}
}
