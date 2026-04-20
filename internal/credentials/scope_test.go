package credentials_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
)

func TestScope_JSONRoundTrip(t *testing.T) {
	s := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"repositories": []any{"acmecorp/legacy-tool"},
			"permissions":  map[string]any{"contents": "write", "pull_requests": "write"},
		},
		TTL:       8 * time.Hour,
		IssuedAt:  time.Date(2026, 4, 13, 15, 20, 4, 0, time.UTC),
		ExpiresAt: time.Date(2026, 4, 13, 23, 20, 4, 0, time.UTC),
	}

	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got credentials.Scope
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Kind != s.Kind {
		t.Errorf("Kind = %q, want %q", got.Kind, s.Kind)
	}
	if got.TTL != s.TTL {
		t.Errorf("TTL = %v, want %v", got.TTL, s.TTL)
	}
	if !got.IssuedAt.Equal(s.IssuedAt) {
		t.Errorf("IssuedAt = %v, want %v", got.IssuedAt, s.IssuedAt)
	}
	if !got.ExpiresAt.Equal(s.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, s.ExpiresAt)
	}
}

func TestScopeHash_Deterministic(t *testing.T) {
	s := credentials.Scope{
		Kind:      "aws-sts",
		Params:    map[string]any{"role_arn": "arn:aws:iam::123:role/deploy"},
		TTL:       15 * time.Minute,
		IssuedAt:  time.Date(2026, 4, 13, 15, 20, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 4, 13, 15, 35, 0, 0, time.UTC),
	}

	h1 := credentials.ScopeHash(s)
	h2 := credentials.ScopeHash(s)

	if h1 != h2 {
		t.Errorf("non-deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(h1))
	}
}

func TestScopeHash_DifferentScopes_DifferentHashes(t *testing.T) {
	base := credentials.Scope{
		Kind:      "github-pat",
		Params:    map[string]any{"repositories": []any{"repo-a"}},
		TTL:       time.Hour,
		IssuedAt:  time.Date(2026, 4, 13, 15, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 4, 13, 16, 0, 0, 0, time.UTC),
	}

	different := base
	different.Params = map[string]any{"repositories": []any{"repo-b"}}

	h1 := credentials.ScopeHash(base)
	h2 := credentials.ScopeHash(different)

	if h1 == h2 {
		t.Error("different scopes produced same hash")
	}
}

func TestScopeHash_ParamOrderIrrelevant(t *testing.T) {
	s1 := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"alpha": "first",
			"beta":  "second",
			"gamma": "third",
		},
		TTL:       time.Hour,
		IssuedAt:  time.Date(2026, 4, 13, 15, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 4, 13, 16, 0, 0, 0, time.UTC),
	}

	// Same params, constructed in different insertion order.
	s2 := credentials.Scope{
		Kind: "github-pat",
		Params: map[string]any{
			"gamma": "third",
			"alpha": "first",
			"beta":  "second",
		},
		TTL:       time.Hour,
		IssuedAt:  time.Date(2026, 4, 13, 15, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 4, 13, 16, 0, 0, 0, time.UTC),
	}

	h1 := credentials.ScopeHash(s1)
	h2 := credentials.ScopeHash(s2)

	if h1 != h2 {
		t.Errorf("param insertion order affected hash: %q vs %q", h1, h2)
	}
}

func TestVendRequest_ZeroDesiredScope_IsBackCompat(t *testing.T) {
	// Empty Kind signals legacy llm-session vend.
	req := credentials.VendRequest{}
	if req.DesiredScope.Kind != "" {
		t.Errorf("zero-value VendRequest should have empty Kind, got %q", req.DesiredScope.Kind)
	}
}
