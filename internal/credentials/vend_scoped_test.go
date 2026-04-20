package credentials_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/pkg/identity"
)

// ── mock ScopeValidator ──────────────────────────────────────────────────────

type mockValidator struct {
	kind        string
	validateErr error
	narrowScope credentials.Scope
	narrowErr   error

	// captured args for assertions
	narrowCalledWith struct {
		requested credentials.Scope
		bounds    credentials.ScopeBounds
	}
}

func (m *mockValidator) Kind() string { return m.kind }

func (m *mockValidator) Validate(_ context.Context, _ credentials.Scope) error {
	return m.validateErr
}

func (m *mockValidator) Narrow(_ context.Context, requested credentials.Scope, bounds credentials.ScopeBounds) (credentials.Scope, error) {
	m.narrowCalledWith.requested = requested
	m.narrowCalledWith.bounds = bounds
	return m.narrowScope, m.narrowErr
}

// ── helpers ──────────────────────────────────────────────────────────────────

func baseRequest(kind string) credentials.VendRequest {
	return credentials.VendRequest{
		Identity:     identity.Identity{CallerID: "agent-1"},
		AgentSession: "sess-abc",
		DesiredScope: credentials.Scope{
			Kind: kind,
			TTL:  30 * time.Minute,
			Params: map[string]any{
				"provider": "anthropic",
				"model":    "claude-4",
			},
		},
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestScopedVender_UnknownKind(t *testing.T) {
	sv := credentials.NewScopedVender() // no validators registered

	req := baseRequest("unknown")
	_, err := sv.VendScoped(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for unknown scope kind, got nil")
	}
	if !strings.Contains(err.Error(), "unknown scope kind") {
		t.Errorf("error should mention 'unknown scope kind', got: %v", err)
	}
}

func TestScopedVender_ValidateRejects(t *testing.T) {
	valErr := errors.New("scope params invalid: model not allowed")
	mv := &mockValidator{
		kind:        "llm-session",
		validateErr: valErr,
	}
	sv := credentials.NewScopedVender(mv)

	req := baseRequest("llm-session")
	_, err := sv.VendScoped(context.Background(), req)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !errors.Is(err, valErr) {
		t.Errorf("expected wrapped valErr, got: %v", err)
	}
}

func TestScopedVender_NarrowApplied(t *testing.T) {
	narrowedTTL := 15 * time.Minute
	narrowedScope := credentials.Scope{
		Kind:   "llm-session",
		TTL:    narrowedTTL,
		Params: map[string]any{"provider": "anthropic", "model": "claude-4"},
	}
	mv := &mockValidator{
		kind:        "llm-session",
		validateErr: nil,
		narrowScope: narrowedScope,
	}
	sv := credentials.NewScopedVender(mv)

	req := baseRequest("llm-session")
	req.DesiredScope.TTL = 60 * time.Minute // ask for 60, get narrowed to 15

	result, err := sv.VendScoped(context.Background(), req)
	if err != nil {
		t.Fatalf("VendScoped: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.EffectiveScope.TTL != narrowedTTL {
		t.Errorf("EffectiveScope.TTL = %v, want %v", result.EffectiveScope.TTL, narrowedTTL)
	}
}

func TestScopedVender_EmptyKindFallsBackToLLMSession(t *testing.T) {
	mv := &mockValidator{
		kind: "llm-session",
		narrowScope: credentials.Scope{
			Kind: "llm-session",
			TTL:  30 * time.Minute,
		},
	}
	sv := credentials.NewScopedVender(mv)

	req := baseRequest("") // empty Kind = back-compat
	result, err := sv.VendScoped(context.Background(), req)
	if err != nil {
		t.Fatalf("VendScoped with empty Kind: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for empty Kind (should fall back to llm-session)")
	}
	if result.EffectiveScope.Kind != "llm-session" {
		t.Errorf("EffectiveScope.Kind = %q, want %q", result.EffectiveScope.Kind, "llm-session")
	}
}

func TestScopedVender_ScopeHashInResult(t *testing.T) {
	effectiveScope := credentials.Scope{
		Kind:      "llm-session",
		TTL:       30 * time.Minute,
		IssuedAt:  time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 4, 16, 12, 30, 0, 0, time.UTC),
		Params:    map[string]any{"provider": "anthropic"},
	}
	mv := &mockValidator{
		kind:        "llm-session",
		narrowScope: effectiveScope,
	}
	sv := credentials.NewScopedVender(mv)

	req := baseRequest("llm-session")
	result, err := sv.VendScoped(context.Background(), req)
	if err != nil {
		t.Fatalf("VendScoped: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.ScopeHash == "" {
		t.Fatal("ScopeHash must be non-empty")
	}
	// The hash must match the canonical ScopeHash of the effective scope.
	expected := credentials.ScopeHash(result.EffectiveScope)
	if result.ScopeHash != expected {
		t.Errorf("ScopeHash = %q, want %q", result.ScopeHash, expected)
	}
}

func TestScopedVender_RegisterMultipleValidators(t *testing.T) {
	mvLLM := &mockValidator{
		kind: "llm-session",
		narrowScope: credentials.Scope{
			Kind: "llm-session",
			TTL:  30 * time.Minute,
		},
	}
	mvAWS := &mockValidator{
		kind: "aws-sts",
		narrowScope: credentials.Scope{
			Kind: "aws-sts",
			TTL:  15 * time.Minute,
		},
	}
	sv := credentials.NewScopedVender(mvLLM, mvAWS)

	// Route to llm-session
	req1 := baseRequest("llm-session")
	r1, err := sv.VendScoped(context.Background(), req1)
	if err != nil {
		t.Fatalf("VendScoped(llm-session): %v", err)
	}
	if r1 == nil || r1.EffectiveScope.Kind != "llm-session" {
		t.Errorf("expected llm-session result, got %+v", r1)
	}

	// Route to aws-sts
	req2 := baseRequest("aws-sts")
	r2, err := sv.VendScoped(context.Background(), req2)
	if err != nil {
		t.Fatalf("VendScoped(aws-sts): %v", err)
	}
	if r2 == nil || r2.EffectiveScope.Kind != "aws-sts" {
		t.Errorf("expected aws-sts result, got %+v", r2)
	}
}
