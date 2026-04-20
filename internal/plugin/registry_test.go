package plugin

import (
	"context"
	"testing"

	"github.com/agentkms/agentkms/internal/credentials"
)

// mockScopeValidator is a test double for credentials.ScopeValidator.
type mockScopeValidator struct {
	kind string
}

func (m *mockScopeValidator) Kind() string { return m.kind }
func (m *mockScopeValidator) Validate(_ context.Context, _ credentials.Scope) error {
	return nil
}
func (m *mockScopeValidator) Narrow(_ context.Context, s credentials.Scope, _ credentials.ScopeBounds) (credentials.Scope, error) {
	return s, nil
}

func TestRegistry_Register_And_Lookup(t *testing.T) {
	r := NewRegistry()
	v := &mockScopeValidator{kind: "github-pat"}

	if err := r.Register("github-pat", v); err != nil {
		t.Fatalf("Register returned unexpected error: %v", err)
	}

	got, err := r.Lookup("github-pat")
	if err != nil {
		t.Fatalf("Lookup returned unexpected error: %v", err)
	}
	if got != v {
		t.Errorf("Lookup returned %v, want %v", got, v)
	}
}

func TestRegistry_Lookup_NotFound(t *testing.T) {
	r := NewRegistry()

	_, err := r.Lookup("nonexistent")
	if err == nil {
		t.Fatal("Lookup should return error for unregistered kind, got nil")
	}
}

func TestRegistry_Register_DuplicateKind(t *testing.T) {
	r := NewRegistry()
	v1 := &mockScopeValidator{kind: "github-pat"}
	v2 := &mockScopeValidator{kind: "github-pat"}

	if err := r.Register("github-pat", v1); err != nil {
		t.Fatalf("First Register returned unexpected error: %v", err)
	}

	err := r.Register("github-pat", v2)
	if err == nil {
		t.Fatal("Register should return error for duplicate kind, got nil")
	}
}

func TestRegistry_Kinds_ReturnsAll(t *testing.T) {
	r := NewRegistry()
	kinds := []string{"aws-sts", "github-pat", "gcp-token"}

	for _, k := range kinds {
		if err := r.Register(k, &mockScopeValidator{kind: k}); err != nil {
			t.Fatalf("Register(%q) returned unexpected error: %v", k, err)
		}
	}

	got := r.Kinds()
	if len(got) != 3 {
		t.Fatalf("Kinds() returned %d items, want 3", len(got))
	}

	// Check all expected kinds are present.
	have := make(map[string]bool)
	for _, k := range got {
		have[k] = true
	}
	for _, k := range kinds {
		if !have[k] {
			t.Errorf("Kinds() missing %q", k)
		}
	}
}

func TestRegistry_Kinds_Empty(t *testing.T) {
	r := NewRegistry()

	got := r.Kinds()
	if got == nil {
		t.Fatal("Kinds() returned nil, want empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("Kinds() returned %d items, want 0", len(got))
	}
}

func TestRegistry_Lookup_AfterMultipleRegistrations(t *testing.T) {
	r := NewRegistry()
	vAWS := &mockScopeValidator{kind: "aws-sts"}
	vGH := &mockScopeValidator{kind: "github-pat"}

	if err := r.Register("aws-sts", vAWS); err != nil {
		t.Fatalf("Register(aws-sts) returned unexpected error: %v", err)
	}
	if err := r.Register("github-pat", vGH); err != nil {
		t.Fatalf("Register(github-pat) returned unexpected error: %v", err)
	}

	gotAWS, err := r.Lookup("aws-sts")
	if err != nil {
		t.Fatalf("Lookup(aws-sts) returned unexpected error: %v", err)
	}
	if gotAWS != vAWS {
		t.Errorf("Lookup(aws-sts) returned wrong validator")
	}

	gotGH, err := r.Lookup("github-pat")
	if err != nil {
		t.Fatalf("Lookup(github-pat) returned unexpected error: %v", err)
	}
	if gotGH != vGH {
		t.Errorf("Lookup(github-pat) returned wrong validator")
	}
}
