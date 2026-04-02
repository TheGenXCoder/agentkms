package auth

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentkms/agentkms/pkg/identity"
)

// ── Fixtures ──────────────────────────────────────────────────────────────────

func newTestStore(t *testing.T) *TokenStore {
	t.Helper()
	ts, err := NewTokenStore()
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	return ts
}

func testIdentity() *identity.Identity {
	return &identity.Identity{
		CallerID:   "bert@dev",
		TeamID:     "dev-team",
		Role:       identity.RoleDeveloper,
		SPIFFEID:   "spiffe://agentkms.local/dev/developer/bert",
		CertSerial: "deadbeef",
	}
}

// ── 1. Happy-path ─────────────────────────────────────────────────────────────

func TestTokenStore_Issue_Validate_HappyPath(t *testing.T) {
	ts := newTestStore(t)
	id := testIdentity()

	tokenStr, tok, err := ts.Issue(id)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("Issue returned empty token string")
	}
	if tok.CallerID != id.CallerID {
		t.Fatalf("Issue CallerID: want %q, got %q", id.CallerID, tok.CallerID)
	}
	if tok.TeamID != id.TeamID {
		t.Fatalf("Issue TeamID: want %q, got %q", id.TeamID, tok.TeamID)
	}
	if tok.SessionID == "" {
		t.Fatal("Issue returned empty SessionID")
	}
	if tok.TokenID == "" {
		t.Fatal("Issue returned empty TokenID")
	}
	if tok.ExpiresAt.Before(time.Now().UTC().Add(14 * time.Minute)) {
		t.Fatalf("token expires too soon: %v", tok.ExpiresAt)
	}

	// Validate succeeds with matching mTLS caller.
	validated, err := ts.Validate(tokenStr, id.CallerID, nil)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if validated.CallerID != id.CallerID {
		t.Fatalf("Validate CallerID: want %q, got %q", id.CallerID, validated.CallerID)
	}
	if validated.TokenID != tok.TokenID {
		t.Fatal("Validate TokenID mismatch")
	}
}

func TestTokenStore_Validate_EmptyMTLSCallerID_SkipsBindingCheck(t *testing.T) {
	// When mtlsCallerID is empty (e.g., test environment without TLS),
	// the connection-binding check is skipped.
	ts := newTestStore(t)
	tokenStr, _, err := ts.Issue(testIdentity())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = ts.Validate(tokenStr, "", nil) // empty = skip binding check
	if err != nil {
		t.Fatalf("Validate with empty mtlsCallerID: %v", err)
	}
}

func TestTokenStore_Issue_TwoTokens_HaveDifferentIDs(t *testing.T) {
	ts := newTestStore(t)
	id := testIdentity()

	str1, tok1, err := ts.Issue(id)
	if err != nil {
		t.Fatalf("Issue 1: %v", err)
	}
	str2, tok2, err := ts.Issue(id)
	if err != nil {
		t.Fatalf("Issue 2: %v", err)
	}
	if str1 == str2 {
		t.Fatal("two Issue calls returned identical token strings")
	}
	if tok1.TokenID == tok2.TokenID {
		t.Fatal("two Issue calls returned identical TokenIDs")
	}
	if tok1.SessionID == tok2.SessionID {
		t.Fatal("two Issue calls returned identical SessionIDs")
	}
}

// ── 2. Token revocation ───────────────────────────────────────────────────────

func TestTokenStore_Revoke_BlocksSubsequentValidate(t *testing.T) {
	ts := newTestStore(t)
	tokenStr, _, err := ts.Issue(testIdentity())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Token should validate before revocation.
	if _, err := ts.Validate(tokenStr, "", nil); err != nil {
		t.Fatalf("Validate before revoke: %v", err)
	}

	if err := ts.Revoke(tokenStr); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Token must be rejected after revocation.
	_, err = ts.Validate(tokenStr, "", nil)
	if err == nil {
		t.Fatal("Validate after revoke: expected error, got nil")
	}
	// Error is the generic "invalid token" message (oracle-prevention: callers
	// must not distinguish revoked from expired or bad-signature).
	if err.Error() != "auth: invalid token" {
		t.Fatalf("expected generic 'auth: invalid token' error after revocation, got: %v", err)
	}
}

func TestTokenStore_Revoke_InvalidToken_ReturnsError(t *testing.T) {
	ts := newTestStore(t)

	err := ts.Revoke("not.a.valid.token")
	if err == nil {
		t.Fatal("Revoke of invalid token: expected error, got nil")
	}
}

// ── 3. ADVERSARIAL — connection binding ───────────────────────────────────────

func TestAdversarial_Validate_WrongMTLSCallerID_Rejected(t *testing.T) {
	ts := newTestStore(t)
	tokenStr, _, err := ts.Issue(testIdentity()) // CallerID = "bert@dev"
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// A different mTLS identity tries to replay this token.
	_, err = ts.Validate(tokenStr, "attacker@dev", nil)
	if err == nil {
		t.Fatal("ADVERSARIAL: token validated for wrong mTLS caller — connection binding bypassed")
	}
	// Error is the generic "invalid token" message (oracle-prevention: callers
	// must not distinguish connection-binding failures from other failures).
	if err.Error() != "auth: invalid token" {
		t.Fatalf("expected generic 'auth: invalid token' on binding failure, got: %v", err)
	}
}

func TestAdversarial_Validate_TamperedMAC_Rejected(t *testing.T) {
	ts := newTestStore(t)
	tokenStr, _, err := ts.Issue(testIdentity())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Flip a byte in the MAC portion (after the separator dot).
	dotIdx := strings.Index(tokenStr, ".")
	if dotIdx < 0 {
		t.Fatal("token has no dot separator")
	}
	macBytes := []byte(tokenStr[dotIdx+1:])
	macBytes[0] ^= 0xFF
	tampered := tokenStr[:dotIdx+1] + string(macBytes)

	_, err = ts.Validate(tampered, "", nil)
	if err == nil {
		t.Fatal("ADVERSARIAL: tampered MAC accepted")
	}
}

func TestAdversarial_Validate_TamperedPayload_Rejected(t *testing.T) {
	ts := newTestStore(t)
	tokenStr, _, err := ts.Issue(testIdentity())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Flip a byte in the payload portion (before the separator dot).
	dotIdx := strings.Index(tokenStr, ".")
	if dotIdx < 0 {
		t.Fatal("token has no dot separator")
	}
	payloadBytes := []byte(tokenStr[:dotIdx])
	payloadBytes[0] ^= 0xFF
	tampered := string(payloadBytes) + tokenStr[dotIdx:]

	_, err = ts.Validate(tampered, "", nil)
	if err == nil {
		t.Fatal("ADVERSARIAL: tampered payload accepted")
	}
}

func TestAdversarial_Validate_TokenFromDifferentStore_Rejected(t *testing.T) {
	// A token signed by store1 must not be accepted by store2 (different keys).
	store1 := newTestStore(t)
	store2 := newTestStore(t)

	tokenStr, _, err := store1.Issue(testIdentity())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = store2.Validate(tokenStr, "", nil)
	if err == nil {
		t.Fatal("ADVERSARIAL: token from store1 accepted by store2 — key isolation failed")
	}
}

func TestAdversarial_Validate_EmptyString_Rejected(t *testing.T) {
	ts := newTestStore(t)
	_, err := ts.Validate("", "", nil)
	if err == nil {
		t.Fatal("empty token string accepted")
	}
}

func TestAdversarial_Validate_ArbitraryStrings_Rejected(t *testing.T) {
	ts := newTestStore(t)
	cases := []string{
		"not-a-token",
		"a.b",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.INVALID",
		".",
		"..",
		strings.Repeat("a", 5000) + "." + strings.Repeat("b", 5000),
	}
	for _, bad := range cases {
		_, err := ts.Validate(bad, "", nil)
		if err == nil {
			maxLen := len(bad)
			if maxLen > 40 {
				maxLen = 40
			}
			t.Errorf("arbitrary string %q accepted as valid token", bad[:maxLen])
		}
	}
}

func TestAdversarial_TokenString_DoesNotContainSigningKey(t *testing.T) {
	ts := newTestStore(t)
	tokenStr, _, err := ts.Issue(testIdentity())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// The raw signing key bytes must not appear in the token string.
	if strings.Contains(tokenStr, string(ts.signingKey)) {
		t.Fatal("ADVERSARIAL: token string contains raw signing key bytes")
	}
}

// ── 4. PurgeExpired ───────────────────────────────────────────────────────────

func TestTokenStore_PurgeExpired_RemovesExpiredEntries(t *testing.T) {
	ts := newTestStore(t)
	tokenStr, _, err := ts.Issue(testIdentity())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := ts.Revoke(tokenStr); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Backdate the revocation expiry to simulate a token that has expired.
	ts.mu.Lock()
	for id := range ts.revoked {
		ts.revoked[id] = time.Now().UTC().Add(-1 * time.Hour)
	}
	ts.mu.Unlock()

	ts.PurgeExpired()

	ts.mu.RLock()
	n := len(ts.revoked)
	ts.mu.RUnlock()

	if n != 0 {
		t.Fatalf("expected 0 revoked entries after purge, got %d", n)
	}
}

// ── 5. Concurrency ────────────────────────────────────────────────────────────

func TestTokenStore_Concurrent_IssueValidateRevoke(t *testing.T) {
	ts := newTestStore(t)
	id := testIdentity()

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			tokenStr, _, err := ts.Issue(id)
			if err != nil {
				errs <- fmt.Errorf("Issue: %w", err)
				return
			}
			if _, err := ts.Validate(tokenStr, "", nil); err != nil {
				errs <- fmt.Errorf("Validate before revoke: %w", err)
				return
			}
			if err := ts.Revoke(tokenStr); err != nil {
				errs <- fmt.Errorf("Revoke: %w", err)
				return
			}
			// Validate after revoke must fail.
			_, err = ts.Validate(tokenStr, "", nil)
			if err == nil {
				errs <- errors.New("token still valid after revoke")
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent error: %v", err)
	}
}
