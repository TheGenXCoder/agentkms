package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
)

func TestDelegate_ValidRequest_Returns200WithScopedToken(t *testing.T) {
	svc, handler, _ := newTestStackWithPolicy(t, policy.Policy{
		Version: "1.0",
		Rules: []policy.Rule{
			{
				ID:     "allow-sign",
				Effect: policy.EffectAllow,
				Match: policy.Match{
					Operations: []policy.Operation{"sign"},
					KeyIDs:     []string{"key-1"},
				},
			},
		},
	})
	cert := makeTestCert(t, "primary-agent")
	parentTokenStr := sessionToken(t, handler, cert.Cert)
	parentTok, _ := svc.Validate(parentTokenStr)

	reqBody, _ := json.Marshal(map[string]any{
		"scopes":      []string{"sign:key-1"},
		"ttl_seconds": 300,
	})
	w := httptest.NewRecorder()

	// Use the postWithToken helper from auth_test.go
	r := postWithToken(t, "/auth/delegate", cert.Cert, parentTokenStr)
	r.Body = io.NopCloser(bytes.NewReader(reqBody))
	
	// Manually inject token since we are calling handler directly without middleware in this test
	r = withToken(r, parentTok)

	handler.Delegate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	resp := decodeSession(t, w.Body)
	scopedTokenStr, ok := resp["token"].(string)
	if !ok || scopedTokenStr == "" {
		t.Fatal("response missing 'token'")
	}

	// Verify the scoped token
	scopedTok, err := svc.Validate(scopedTokenStr)
	if err != nil {
		t.Fatalf("Validate scoped token: %v", err)
	}

	if len(scopedTok.Identity.Scopes) != 1 || scopedTok.Identity.Scopes[0] != "sign:key-1" {
		t.Errorf("Scopes = %v, want [sign:key-1]", scopedTok.Identity.Scopes)
	}
}

func TestDelegate_UnauthorizedScope_Returns403(t *testing.T) {
	// Policy only allows sign:key-1
	svc, handler, _ := newTestStackWithPolicy(t, policy.Policy{
		Version: "1.0",
		Rules: []policy.Rule{
			{
				ID:     "allow-sign-key-1",
				Effect: policy.EffectAllow,
				Match: policy.Match{
					Operations: []policy.Operation{"sign"},
					KeyIDs:     []string{"key-1"},
				},
			},
		},
	})
	cert := makeTestCert(t, "primary-agent")
	parentTokenStr := sessionToken(t, handler, cert.Cert)
	parentTok, _ := svc.Validate(parentTokenStr)

	// Requesting sign:key-2 which is NOT allowed by policy
	reqBody, _ := json.Marshal(map[string]any{
		"scopes": []string{"sign:key-2"},
	})
	w := httptest.NewRecorder()
	r := withToken(postWithToken(t, "/auth/delegate", cert.Cert, parentTokenStr), parentTok)
	r.Body = io.NopCloser(bytes.NewReader(reqBody))

	handler.Delegate(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 Forbidden", w.Code)
	}
}

func TestDelegate_ScopeEnforcementInPolicyEngine(t *testing.T) {
	eng := policy.New(policy.Policy{
		Version: "1.0",
		Rules: []policy.Rule{
			{
				ID:     "allow-all",
				Effect: policy.EffectAllow,
				Match:  policy.Match{}, // Matches everything
			},
		},
	})

	// Identity with restricted scope
	id := identity.Identity{
		CallerID: "sub-agent",
		TeamID:   "team-1",
		Scopes:   []string{"sign:key-1"},
	}

	// 1. Allowed operation within scope
	dec1 := eng.Evaluate(id, "sign", "key-1")
	if !dec1.Allow {
		t.Errorf("Expected sign:key-1 to be allowed, got deny: %s", dec1.DenyReason)
	}

	// 2. Denied operation (wrong operation)
	dec2 := eng.Evaluate(id, "encrypt", "key-1")
	if dec2.Allow {
		t.Error("Expected encrypt:key-1 to be denied (out of scope)")
	}

	// 3. Denied operation (wrong resource)
	dec3 := eng.Evaluate(id, "sign", "key-2")
	if dec3.Allow {
		t.Error("Expected sign:key-2 to be denied (out of scope)")
	}
}

// ── Test Helpers ─────────────────────────────────────────────────────────────

func newTestStackWithPolicy(t *testing.T, p policy.Policy) (*auth.TokenService, *api.AuthHandler, *nullAuditor) {
	t.Helper()
	rl := auth.NewRevocationList()
	svc, err := auth.NewTokenService(rl)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}
	auditor := &nullAuditor{}
	eng := policy.New(p)
	handler := api.NewAuthHandler(svc, auditor, policy.AsEngineI(eng), "test")
	return svc, handler, auditor
}
