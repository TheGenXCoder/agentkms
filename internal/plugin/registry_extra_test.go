package plugin

// registry_extra_test.go — failing tests for Registry expansion:
// RegisterAnalyzer, LookupAnalyzer, RegisterSerializer, LookupSerializer,
// RegisterVender, LookupVender, and the parallel Kinds() methods.
//
// ALL TESTS IN THIS FILE ARE EXPECTED TO FAIL because the Registry only
// has a validators map today. Do not modify non-test code to make them pass.

import (
	"context"
	"testing"

	"github.com/agentkms/agentkms/internal/credentials"
)

// ── Test doubles ─────────────────────────────────────────────────────────────

type mockScopeAnalyzer struct{ kind string }

func (m *mockScopeAnalyzer) Kind() string { return m.kind }
func (m *mockScopeAnalyzer) Analyze(_ context.Context, _ credentials.Scope) []credentials.ScopeAnomaly {
	return nil
}

type mockScopeSerializer struct{ kind string }

func (m *mockScopeSerializer) Kind() string { return m.kind }
func (m *mockScopeSerializer) ProviderRequest(_ context.Context, _ credentials.Scope) ([]byte, error) {
	return []byte(`{}`), nil
}

type mockCredentialVender struct{ kind string }

func (m *mockCredentialVender) Kind() string { return m.kind }
func (m *mockCredentialVender) Vend(_ context.Context, _ credentials.Scope) (*credentials.VendedCredential, error) {
	return &credentials.VendedCredential{}, nil
}

// ── ScopeAnalyzer tests ───────────────────────────────────────────────────────

// TestRegistry_RegisterAnalyzer_And_LookupAnalyzer verifies basic register
// and lookup round-trip for ScopeAnalyzer.
//
// CURRENTLY FAILS: RegisterAnalyzer undefined on *Registry.
func TestRegistry_RegisterAnalyzer_And_LookupAnalyzer(t *testing.T) {
	r := NewRegistry()
	a := &mockScopeAnalyzer{kind: "aws-sts"}

	// EXPECT COMPILE ERROR: RegisterAnalyzer not defined.
	if err := r.RegisterAnalyzer("aws-sts", a); err != nil {
		t.Fatalf("RegisterAnalyzer returned unexpected error: %v", err)
	}

	// EXPECT COMPILE ERROR: LookupAnalyzer not defined.
	got, err := r.LookupAnalyzer("aws-sts")
	if err != nil {
		t.Fatalf("LookupAnalyzer returned unexpected error: %v", err)
	}
	if got != a {
		t.Errorf("LookupAnalyzer returned %v, want %v", got, a)
	}
}

// TestRegistry_LookupAnalyzer_NotFound verifies that LookupAnalyzer returns
// an error for an unregistered kind.
//
// CURRENTLY FAILS: LookupAnalyzer not defined.
func TestRegistry_LookupAnalyzer_NotFound(t *testing.T) {
	r := NewRegistry()

	// EXPECT COMPILE ERROR.
	_, err := r.LookupAnalyzer("nonexistent")
	if err == nil {
		t.Fatal("LookupAnalyzer should return error for unregistered kind, got nil")
	}
}

// TestRegistry_RegisterAnalyzer_DuplicateKind verifies that registering the
// same Kind twice returns an error.
//
// CURRENTLY FAILS: RegisterAnalyzer not defined.
func TestRegistry_RegisterAnalyzer_DuplicateKind(t *testing.T) {
	r := NewRegistry()
	a1 := &mockScopeAnalyzer{kind: "github-pat"}
	a2 := &mockScopeAnalyzer{kind: "github-pat"}

	// EXPECT COMPILE ERROR.
	if err := r.RegisterAnalyzer("github-pat", a1); err != nil {
		t.Fatalf("first RegisterAnalyzer: %v", err)
	}

	err := r.RegisterAnalyzer("github-pat", a2)
	if err == nil {
		t.Fatal("second RegisterAnalyzer with same kind should return error, got nil")
	}
}

// TestRegistry_AnalyzerKinds_ReturnsAll verifies AnalyzerKinds returns all
// registered analyzer kinds.
//
// CURRENTLY FAILS: AnalyzerKinds not defined.
func TestRegistry_AnalyzerKinds_ReturnsAll(t *testing.T) {
	r := NewRegistry()
	kinds := []string{"aws-sts", "github-pat"}

	// EXPECT COMPILE ERROR.
	for _, k := range kinds {
		if err := r.RegisterAnalyzer(k, &mockScopeAnalyzer{kind: k}); err != nil {
			t.Fatalf("RegisterAnalyzer(%q): %v", k, err)
		}
	}

	got := r.AnalyzerKinds()
	if len(got) != 2 {
		t.Fatalf("AnalyzerKinds() returned %d items, want 2", len(got))
	}
}

// ── ScopeSerializer tests ─────────────────────────────────────────────────────

// TestRegistry_RegisterSerializer_And_LookupSerializer verifies basic
// register and lookup round-trip for ScopeSerializer.
//
// CURRENTLY FAILS: RegisterSerializer undefined on *Registry.
func TestRegistry_RegisterSerializer_And_LookupSerializer(t *testing.T) {
	r := NewRegistry()
	s := &mockScopeSerializer{kind: "aws-sts"}

	// EXPECT COMPILE ERROR.
	if err := r.RegisterSerializer("aws-sts", s); err != nil {
		t.Fatalf("RegisterSerializer returned unexpected error: %v", err)
	}

	got, err := r.LookupSerializer("aws-sts")
	if err != nil {
		t.Fatalf("LookupSerializer returned unexpected error: %v", err)
	}
	if got != s {
		t.Errorf("LookupSerializer returned %v, want %v", got, s)
	}
}

// TestRegistry_LookupSerializer_NotFound verifies that LookupSerializer
// returns an error for an unregistered kind.
//
// CURRENTLY FAILS: LookupSerializer not defined.
func TestRegistry_LookupSerializer_NotFound(t *testing.T) {
	r := NewRegistry()

	// EXPECT COMPILE ERROR.
	_, err := r.LookupSerializer("nonexistent")
	if err == nil {
		t.Fatal("LookupSerializer should return error for unregistered kind, got nil")
	}
}

// TestRegistry_SerializerKinds_ReturnsAll verifies SerializerKinds returns
// all registered serializer kinds.
//
// CURRENTLY FAILS: SerializerKinds not defined.
func TestRegistry_SerializerKinds_ReturnsAll(t *testing.T) {
	r := NewRegistry()

	// EXPECT COMPILE ERROR.
	for _, k := range []string{"aws-sts", "stripe"} {
		if err := r.RegisterSerializer(k, &mockScopeSerializer{kind: k}); err != nil {
			t.Fatalf("RegisterSerializer(%q): %v", k, err)
		}
	}

	got := r.SerializerKinds()
	if len(got) != 2 {
		t.Fatalf("SerializerKinds() returned %d items, want 2", len(got))
	}
}

// TestRegistry_RegisterSerializer_DuplicateKind verifies that duplicate
// serializer registration returns an error.
//
// CURRENTLY FAILS: RegisterSerializer not defined.
func TestRegistry_RegisterSerializer_DuplicateKind(t *testing.T) {
	r := NewRegistry()
	s1 := &mockScopeSerializer{kind: "aws-sts"}
	s2 := &mockScopeSerializer{kind: "aws-sts"}

	// EXPECT COMPILE ERROR.
	if err := r.RegisterSerializer("aws-sts", s1); err != nil {
		t.Fatalf("first RegisterSerializer: %v", err)
	}
	err := r.RegisterSerializer("aws-sts", s2)
	if err == nil {
		t.Fatal("second RegisterSerializer with same kind should return error, got nil")
	}
}

// ── CredentialVender tests ────────────────────────────────────────────────────

// TestRegistry_RegisterVender_And_LookupVender verifies basic register and
// lookup round-trip for CredentialVender.
//
// CURRENTLY FAILS: CredentialVender interface not defined in credentials pkg;
// RegisterVender not defined on *Registry.
func TestRegistry_RegisterVender_And_LookupVender(t *testing.T) {
	r := NewRegistry()
	v := &mockCredentialVender{kind: "aws-sts"}

	// EXPECT COMPILE ERROR: CredentialVender interface and RegisterVender undefined.
	if err := r.RegisterVender("aws-sts", v); err != nil {
		t.Fatalf("RegisterVender returned unexpected error: %v", err)
	}

	got, err := r.LookupVender("aws-sts")
	if err != nil {
		t.Fatalf("LookupVender returned unexpected error: %v", err)
	}
	if got != v {
		t.Errorf("LookupVender returned %v, want %v", got, v)
	}
}

// TestRegistry_LookupVender_NotFound verifies that LookupVender returns an
// error for an unregistered kind.
//
// CURRENTLY FAILS: LookupVender not defined.
func TestRegistry_LookupVender_NotFound(t *testing.T) {
	r := NewRegistry()

	// EXPECT COMPILE ERROR.
	_, err := r.LookupVender("nonexistent")
	if err == nil {
		t.Fatal("LookupVender should return error for unregistered kind, got nil")
	}
}

// TestRegistry_AllTypesCoexist verifies that registering a validator,
// analyzer, serializer, and vender for the same Kind is legal — each map
// is independent.
//
// CURRENTLY FAILS: three of the four registration methods don't exist.
func TestRegistry_AllTypesCoexist(t *testing.T) {
	r := NewRegistry()
	kind := "github-pat"

	// EXPECT COMPILE ERRORS on all but Register.
	if err := r.Register(kind, &mockScopeValidator{kind: kind}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.RegisterAnalyzer(kind, &mockScopeAnalyzer{kind: kind}); err != nil {
		t.Fatalf("RegisterAnalyzer: %v", err)
	}
	if err := r.RegisterSerializer(kind, &mockScopeSerializer{kind: kind}); err != nil {
		t.Fatalf("RegisterSerializer: %v", err)
	}
	if err := r.RegisterVender(kind, &mockCredentialVender{kind: kind}); err != nil {
		t.Fatalf("RegisterVender: %v", err)
	}

	// Each lookup must succeed independently.
	if _, err := r.Lookup(kind); err != nil {
		t.Errorf("Lookup: %v", err)
	}
	if _, err := r.LookupAnalyzer(kind); err != nil {
		t.Errorf("LookupAnalyzer: %v", err)
	}
	if _, err := r.LookupSerializer(kind); err != nil {
		t.Errorf("LookupSerializer: %v", err)
	}
	if _, err := r.LookupVender(kind); err != nil {
		t.Errorf("LookupVender: %v", err)
	}
}
