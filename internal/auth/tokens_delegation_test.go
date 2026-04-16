package auth_test

// Coverage for IssueDelegated (sub-agent token scoping) and
// IssueBootstrapToken (device-recovery bootstrap).  Both were at 0%
// coverage before these tests landed, which was masked by a latent
// bug in scripts/quality_check.sh that caused the 85% security
// threshold never to be applied.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/pkg/identity"
)

// ── IssueDelegated ────────────────────────────────────────────────────────────

func TestTokenService_IssueDelegated_RoundTrip(t *testing.T) {
	svc := newTestService(t)
	parent := testIdentity("parent-fp-aabbccdd")

	scopes := []string{"read:secrets", "sign:artifacts"}
	ttl := 5 * time.Minute

	tokenStr, tok, err := svc.IssueDelegated(parent, ttl, scopes)
	if err != nil {
		t.Fatalf("IssueDelegated: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("IssueDelegated returned empty string")
	}
	if tok == nil {
		t.Fatal("IssueDelegated returned nil Token")
	}

	// Returned Token must carry the delegated scopes.
	if len(tok.Identity.Scopes) != len(scopes) {
		t.Fatalf("Identity.Scopes len = %d, want %d", len(tok.Identity.Scopes), len(scopes))
	}
	for i, s := range scopes {
		if tok.Identity.Scopes[i] != s {
			t.Errorf("Identity.Scopes[%d] = %q, want %q", i, tok.Identity.Scopes[i], s)
		}
	}

	// Token must validate and round-trip all delegated claims.
	got, err := svc.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.Identity.CallerID != parent.CallerID {
		t.Errorf("CallerID = %q, want %q", got.Identity.CallerID, parent.CallerID)
	}
	if got.Identity.TeamID != parent.TeamID {
		t.Errorf("TeamID = %q, want %q", got.Identity.TeamID, parent.TeamID)
	}
	if got.Identity.CertFingerprint != parent.CertFingerprint {
		t.Errorf("CertFingerprint = %q, want %q", got.Identity.CertFingerprint, parent.CertFingerprint)
	}
	if len(got.Identity.Scopes) != len(scopes) {
		t.Fatalf("validated Scopes len = %d, want %d", len(got.Identity.Scopes), len(scopes))
	}
	for i, s := range scopes {
		if got.Identity.Scopes[i] != s {
			t.Errorf("validated Scopes[%d] = %q, want %q", i, got.Identity.Scopes[i], s)
		}
	}
}

func TestTokenService_IssueDelegated_TTLRespected(t *testing.T) {
	svc := newTestService(t)
	parent := testIdentity("parent-fp")

	ttl := 2 * time.Minute
	_, tok, err := svc.IssueDelegated(parent, ttl, []string{"scope:x"})
	if err != nil {
		t.Fatalf("IssueDelegated: %v", err)
	}

	// ExpiresAt − IssuedAt should approximately equal ttl.
	got := tok.ExpiresAt.Sub(tok.IssuedAt)
	if got < ttl-time.Second || got > ttl+time.Second {
		t.Errorf("ttl = %v, want within 1s of %v", got, ttl)
	}
}

func TestTokenService_IssueDelegated_UniqueJTI(t *testing.T) {
	svc := newTestService(t)
	parent := testIdentity("parent-fp")

	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		_, tok, err := svc.IssueDelegated(parent, time.Minute, []string{"scope:x"})
		if err != nil {
			t.Fatalf("IssueDelegated #%d: %v", i, err)
		}
		if _, dup := seen[tok.JTI]; dup {
			t.Fatalf("duplicate JTI across delegated issuances: %q", tok.JTI)
		}
		seen[tok.JTI] = struct{}{}
	}
}

func TestTokenService_IssueDelegated_DoesNotMutateParent(t *testing.T) {
	svc := newTestService(t)
	parent := testIdentity("parent-fp")
	parent.Scopes = []string{"original:scope"}

	_, _, err := svc.IssueDelegated(parent, time.Minute, []string{"delegated:scope"})
	if err != nil {
		t.Fatalf("IssueDelegated: %v", err)
	}

	// The delegated issuance must not mutate the parent Identity's Scopes.
	if len(parent.Scopes) != 1 || parent.Scopes[0] != "original:scope" {
		t.Errorf("parent Scopes mutated: %v", parent.Scopes)
	}
}

func TestTokenService_IssueDelegated_EmptyScopes(t *testing.T) {
	// Empty scope list is valid — represents a delegated token with no
	// permissions, used for identity assertion only.
	svc := newTestService(t)
	parent := testIdentity("parent-fp")

	tokenStr, tok, err := svc.IssueDelegated(parent, time.Minute, []string{})
	if err != nil {
		t.Fatalf("IssueDelegated with empty scopes: %v", err)
	}
	if len(tok.Identity.Scopes) != 0 {
		t.Errorf("empty scopes produced %d scopes", len(tok.Identity.Scopes))
	}

	// Round-trip: validated token must also have zero scopes.
	got, err := svc.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(got.Identity.Scopes) != 0 {
		t.Errorf("validated token has %d scopes, want 0", len(got.Identity.Scopes))
	}
}

func TestTokenService_IssueDelegated_TokenStringLeaksNoKeyMaterial(t *testing.T) {
	svc := newTestService(t)
	parent := testIdentity("parent-fp")

	tokenStr, _, err := svc.IssueDelegated(parent, time.Minute, []string{"scope:x"})
	if err != nil {
		t.Fatalf("IssueDelegated: %v", err)
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 2 {
		t.Fatalf("token format: got %d segments, want 2", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	for _, bad := range []string{"signingKey", "signing_key", "private", "secret"} {
		if strings.Contains(string(payload), bad) {
			t.Errorf("delegated token payload leaks forbidden string %q", bad)
		}
	}
}

// ── IssueBootstrapToken ───────────────────────────────────────────────────────
//
// Bootstrap tokens are deliberately missing team/certFP claims — they are
// consumed by a separate enrollment handler during device-recovery, before
// the caller has a certificate bound to their identity.  Standard
// TokenService.Validate() rejects them because of the missing claims; that
// is by design.  These tests decode the payload directly to verify
// issuance semantics.

type bootstrapPayload struct {
	JTI       string   `json:"jti"`
	Subject   string   `json:"sub"`
	Role      string   `json:"role"`
	Scopes    []string `json:"scp"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

func decodeBootstrapPayload(t *testing.T, tokenStr string) bootstrapPayload {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 2 {
		t.Fatalf("bootstrap token format: got %d segments, want 2", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decoding bootstrap payload: %v", err)
	}
	var p bootstrapPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshalling bootstrap payload: %v", err)
	}
	return p
}

func TestTokenService_IssueBootstrapToken_RoundTrip(t *testing.T) {
	svc := newTestService(t)
	callerID := "recovering-user@platform-team"

	tokenStr, err := svc.IssueBootstrapToken(callerID)
	if err != nil {
		t.Fatalf("IssueBootstrapToken: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("IssueBootstrapToken returned empty string")
	}

	p := decodeBootstrapPayload(t, tokenStr)

	if p.Subject != callerID {
		t.Errorf("Subject = %q, want %q", p.Subject, callerID)
	}
	if p.Role != string(identity.RoleDeveloper) {
		t.Errorf("Role = %q, want %q", p.Role, identity.RoleDeveloper)
	}
	if len(p.Scopes) != 1 || p.Scopes[0] != "enroll:self" {
		t.Errorf("Scopes = %v, want [enroll:self]", p.Scopes)
	}
	ttl := time.Duration(p.ExpiresAt-p.IssuedAt) * time.Second
	if ttl < auth.RecoveryTokenTTL-time.Second || ttl > auth.RecoveryTokenTTL+time.Second {
		t.Errorf("bootstrap ttl = %v, want within 1s of %v", ttl, auth.RecoveryTokenTTL)
	}
	if p.JTI == "" {
		t.Error("bootstrap JTI is empty")
	}
}

func TestTokenService_IssueBootstrapToken_EmptyCallerID(t *testing.T) {
	svc := newTestService(t)
	// Bootstrap with empty caller — IssueBootstrapToken itself doesn't
	// reject (the enroll handler is authoritative).  Exercise the path
	// so we don't silently regress on the subject propagation.
	tokenStr, err := svc.IssueBootstrapToken("")
	if err != nil {
		t.Fatalf("IssueBootstrapToken empty callerID: %v", err)
	}
	p := decodeBootstrapPayload(t, tokenStr)
	if p.Subject != "" {
		t.Errorf("empty-caller bootstrap Subject = %q, want empty", p.Subject)
	}
}

func TestTokenService_IssueBootstrapToken_UniqueJTIs(t *testing.T) {
	svc := newTestService(t)

	seen := make(map[string]struct{}, 50)
	for i := 0; i < 50; i++ {
		tokenStr, err := svc.IssueBootstrapToken("user@team")
		if err != nil {
			t.Fatalf("IssueBootstrapToken #%d: %v", i, err)
		}
		p := decodeBootstrapPayload(t, tokenStr)
		if _, dup := seen[p.JTI]; dup {
			t.Fatalf("duplicate JTI across bootstrap tokens: %q", p.JTI)
		}
		seen[p.JTI] = struct{}{}
	}
}
