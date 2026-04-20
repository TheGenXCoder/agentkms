package credentials_test

// Tests for the built-in llm-session ScopeValidator (B1 Step 3).
//
// These tests define the acceptance criteria for the LLMSessionValidator.
// They are expected to FAIL until the validator is fully implemented.

import (
	"context"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
)

// ── Kind ────────────────────────────────────────────────────────────────────

func TestLLMValidator_Kind(t *testing.T) {
	v := &credentials.LLMSessionValidator{}
	if got := v.Kind(); got != "llm-session" {
		t.Errorf("Kind() = %q, want %q", got, "llm-session")
	}
}

// ── Validate ────────────────────────────────────────────────────────────────

func TestLLMValidator_Validate_ValidScope(t *testing.T) {
	v := &credentials.LLMSessionValidator{}
	s := credentials.Scope{
		Kind:   "llm-session",
		Params: map[string]any{"provider": "anthropic"},
		TTL:    30 * time.Minute,
	}
	if err := v.Validate(context.Background(), s); err != nil {
		t.Errorf("Validate() returned unexpected error: %v", err)
	}
}

func TestLLMValidator_Validate_WrongKind(t *testing.T) {
	v := &credentials.LLMSessionValidator{}
	s := credentials.Scope{
		Kind:   "aws-sts",
		Params: map[string]any{"provider": "anthropic"},
		TTL:    30 * time.Minute,
	}
	if err := v.Validate(context.Background(), s); err == nil {
		t.Error("Validate() should reject scope with wrong Kind")
	}
}

func TestLLMValidator_Validate_MissingProvider(t *testing.T) {
	v := &credentials.LLMSessionValidator{}
	s := credentials.Scope{
		Kind:   "llm-session",
		Params: map[string]any{},
		TTL:    30 * time.Minute,
	}
	if err := v.Validate(context.Background(), s); err == nil {
		t.Error("Validate() should reject scope without provider param")
	}
}

func TestLLMValidator_Validate_UnsupportedProvider(t *testing.T) {
	v := &credentials.LLMSessionValidator{}
	s := credentials.Scope{
		Kind:   "llm-session",
		Params: map[string]any{"provider": "nonexistent"},
		TTL:    30 * time.Minute,
	}
	if err := v.Validate(context.Background(), s); err == nil {
		t.Error("Validate() should reject unsupported provider")
	}
}

func TestLLMValidator_Validate_TTLTooLong(t *testing.T) {
	v := &credentials.LLMSessionValidator{}
	s := credentials.Scope{
		Kind:   "llm-session",
		Params: map[string]any{"provider": "openai"},
		TTL:    90 * time.Minute, // exceeds 60m CredentialTTL
	}
	if err := v.Validate(context.Background(), s); err == nil {
		t.Error("Validate() should reject TTL > CredentialTTL (60m)")
	}
}

func TestLLMValidator_Validate_ZeroTTL(t *testing.T) {
	v := &credentials.LLMSessionValidator{}
	s := credentials.Scope{
		Kind:   "llm-session",
		Params: map[string]any{"provider": "openai"},
		TTL:    0,
	}
	if err := v.Validate(context.Background(), s); err == nil {
		t.Error("Validate() should reject zero TTL")
	}
}

// ── Narrow ──────────────────────────────────────────────────────────────────

func TestLLMValidator_Narrow_TTLCapped(t *testing.T) {
	v := &credentials.LLMSessionValidator{}
	requested := credentials.Scope{
		Kind:   "llm-session",
		Params: map[string]any{"provider": "openai"},
		TTL:    2 * time.Hour,
	}
	bounds := credentials.ScopeBounds{
		MaxTTL: 30 * time.Minute,
	}

	got, err := v.Narrow(context.Background(), requested, bounds)
	if err != nil {
		t.Fatalf("Narrow() unexpected error: %v", err)
	}
	if got.TTL != 30*time.Minute {
		t.Errorf("Narrow() TTL = %v, want %v", got.TTL, 30*time.Minute)
	}
}

func TestLLMValidator_Narrow_TTLWithinBounds(t *testing.T) {
	v := &credentials.LLMSessionValidator{}
	requested := credentials.Scope{
		Kind:   "llm-session",
		Params: map[string]any{"provider": "openai"},
		TTL:    15 * time.Minute,
	}
	bounds := credentials.ScopeBounds{
		MaxTTL: time.Hour,
	}

	got, err := v.Narrow(context.Background(), requested, bounds)
	if err != nil {
		t.Fatalf("Narrow() unexpected error: %v", err)
	}
	if got.TTL != 15*time.Minute {
		t.Errorf("Narrow() TTL = %v, want %v (should stay within bounds)", got.TTL, 15*time.Minute)
	}
}

func TestLLMValidator_Narrow_ProviderMismatch(t *testing.T) {
	v := &credentials.LLMSessionValidator{}
	requested := credentials.Scope{
		Kind:   "llm-session",
		Params: map[string]any{"provider": "anthropic"},
		TTL:    30 * time.Minute,
	}
	bounds := credentials.ScopeBounds{
		MaxParams: map[string]any{"provider": "openai"},
	}

	_, err := v.Narrow(context.Background(), requested, bounds)
	if err == nil {
		t.Error("Narrow() should return error when requested provider conflicts with bounds")
	}
}

func TestLLMValidator_Narrow_NoBounds(t *testing.T) {
	v := &credentials.LLMSessionValidator{}
	requested := credentials.Scope{
		Kind:   "llm-session",
		Params: map[string]any{"provider": "anthropic"},
		TTL:    45 * time.Minute,
	}
	bounds := credentials.ScopeBounds{} // empty bounds

	got, err := v.Narrow(context.Background(), requested, bounds)
	if err != nil {
		t.Fatalf("Narrow() unexpected error: %v", err)
	}
	if got.TTL != 45*time.Minute {
		t.Errorf("Narrow() TTL = %v, want %v (no bounds should leave TTL unchanged)", got.TTL, 45*time.Minute)
	}
	if got.Kind != "llm-session" {
		t.Errorf("Narrow() Kind = %q, want %q", got.Kind, "llm-session")
	}
	if got.IssuedAt.IsZero() {
		t.Error("Narrow() should populate IssuedAt")
	}
	if got.ExpiresAt.IsZero() {
		t.Error("Narrow() should populate ExpiresAt")
	}
	if !got.ExpiresAt.After(got.IssuedAt) {
		t.Errorf("Narrow() ExpiresAt (%v) should be after IssuedAt (%v)", got.ExpiresAt, got.IssuedAt)
	}
}
