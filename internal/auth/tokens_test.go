package auth_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/pkg/identity"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func newTestService(t *testing.T) *auth.TokenService {
	t.Helper()
	svc, err := auth.NewTokenService(auth.NewRevocationList())
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}
	return svc
}

func testIdentity(certFP string) *identity.Identity {
	return &identity.Identity{
		CallerID:        "bert@platform-team",
		TeamID:          "platform-team",
		Role:            identity.RoleDeveloper,
		SPIFFEID:        "spiffe://agentkms.org/team/platform-team/identity/bert",
		CertFingerprint: certFP,
	}
}

// ── Issue and Validate ────────────────────────────────────────────────────────

func TestTokenService_IssueAndValidate_RoundTrip(t *testing.T) {
	svc := newTestService(t)
	id := testIdentity("aabbccdd")

	tokenStr, issued, err := svc.Issue(id)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("Issue returned empty token string")
	}
	if issued == nil {
		t.Fatal("Issue returned nil Token")
	}

	got, err := svc.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if got.Identity.CallerID != id.CallerID {
		t.Errorf("CallerID = %q, want %q", got.Identity.CallerID, id.CallerID)
	}
	if got.Identity.TeamID != id.TeamID {
		t.Errorf("TeamID = %q, want %q", got.Identity.TeamID, id.TeamID)
	}
	if got.Identity.Role != id.Role {
		t.Errorf("Role = %q, want %q", got.Identity.Role, id.Role)
	}
	if got.Identity.SPIFFEID != id.SPIFFEID {
		t.Errorf("SPIFFEID = %q, want %q", got.Identity.SPIFFEID, id.SPIFFEID)
	}
	if got.Identity.CertFingerprint != id.CertFingerprint {
		t.Errorf("CertFingerprint = %q, want %q", got.Identity.CertFingerprint, id.CertFingerprint)
	}
	if got.JTI == "" {
		t.Error("JTI is empty")
	}
	if got.JTI != issued.JTI {
		t.Errorf("Validate JTI = %q, Issue JTI = %q — mismatch", got.JTI, issued.JTI)
	}
}

func TestTokenService_TTL_ApproximatelyCorrect(t *testing.T) {
	svc := newTestService(t)
	id := testIdentity("fp1")

	before := time.Now().UTC()
	_, tok, err := svc.Issue(id)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	after := time.Now().UTC()

	// ExpiresAt should be ~15 minutes from now.
	minExp := before.Add(auth.TokenTTL)
	maxExp := after.Add(auth.TokenTTL)

	if tok.ExpiresAt.Before(minExp) {
		t.Errorf("ExpiresAt %v is before expected minimum %v", tok.ExpiresAt, minExp)
	}
	if tok.ExpiresAt.After(maxExp) {
		t.Errorf("ExpiresAt %v is after expected maximum %v", tok.ExpiresAt, maxExp)
	}
}

func TestTokenService_EachIssueHasUniqueJTI(t *testing.T) {
	svc := newTestService(t)
	id := testIdentity("fp1")
	seen := make(map[string]bool)

	for range 20 {
		_, tok, err := svc.Issue(id)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[tok.JTI] {
			t.Fatalf("duplicate JTI issued: %q", tok.JTI)
		}
		seen[tok.JTI] = true
	}
}

// ── Expiry ────────────────────────────────────────────────────────────────────

func TestTokenService_Validate_ExpiredToken(t *testing.T) {
	// Issue a token at T=0.  Then advance the service clock past the 15-minute
	// TTL and validate — must return ErrTokenInvalid.
	//
	// The clock is shared via a pointer so that advancing it between Issue and
	// Validate affects the same TokenService instance (same signing key).
	clockTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nowFunc := func() time.Time { return clockTime }

	svc, err := auth.NewTokenServiceWithClock(auth.NewRevocationList(), nowFunc)
	if err != nil {
		t.Fatalf("NewTokenServiceWithClock: %v", err)
	}

	// Issue at T=0.
	tokenStr, _, err := svc.Issue(testIdentity("fp-expiry"))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Still valid at T+14min (one minute before expiry).
	clockTime = clockTime.Add(14 * time.Minute)
	if _, err := svc.Validate(tokenStr); err != nil {
		t.Fatalf("Validate at T+14min (should still be valid): %v", err)
	}

	// Expired at T+20min (five minutes past TTL).
	clockTime = clockTime.Add(6 * time.Minute) // total T+20min
	_, err = svc.Validate(tokenStr)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for expired token at T+20min, got: %v", err)
	}
}

// ── Adversarial: signature tampering ──────────────────────────────────────────

func TestTokenService_Validate_TamperedPayload_FlippedBit(t *testing.T) {
	svc := newTestService(t)
	tokenStr, _, err := svc.Issue(testIdentity("fp1"))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Flip one bit in the payload segment (before the ".").
	parts := strings.SplitN(tokenStr, ".", 2)
	payload := []byte(parts[0])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + "." + parts[1]

	_, err = svc.Validate(tampered)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for tampered payload, got: %v", err)
	}
}

func TestTokenService_Validate_TamperedMAC(t *testing.T) {
	svc := newTestService(t)
	tokenStr, _, err := svc.Issue(testIdentity("fp1"))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Flip a bit in the last character of the base64url-encoded MAC.
	//
	// We use XOR 0x04 (not 0x01) because the last base64url char of a 32-byte
	// HMAC-SHA256 encodes exactly 4 meaningful bits + 2 zero padding bits (the
	// 6-bit value is always a multiple of 4).  XOR 0x01 flips only the low
	// ASCII bit, which for digits '0','4','8' maps to a new char ('1','5','9')
	// whose decoded nibble is identical — the HMAC comparison passes and the
	// test becomes a false negative.  XOR 0x04 always changes a meaningful
	// decoded bit regardless of which of the 16 possible last-char values the
	// random HMAC happens to produce.
	dotIdx := strings.LastIndexByte(tokenStr, '.')
	mac := []byte(tokenStr[dotIdx+1:])
	mac[len(mac)-1] ^= 0x04
	tampered := tokenStr[:dotIdx+1] + string(mac)

	_, err = svc.Validate(tampered)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for tampered MAC, got: %v", err)
	}
}

func TestTokenService_Validate_SwappedSegments(t *testing.T) {
	svc := newTestService(t)
	tokenStr, _, err := svc.Issue(testIdentity("fp1"))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	parts := strings.SplitN(tokenStr, ".", 2)
	// Swap payload and MAC.
	swapped := parts[1] + "." + parts[0]

	_, err = svc.Validate(swapped)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for swapped segments, got: %v", err)
	}
}

func TestTokenService_Validate_NoSeparator(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.Validate("thisisnotavalidtoken")
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for token with no separator, got: %v", err)
	}
}

func TestTokenService_Validate_EmptyString(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.Validate("")
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for empty string, got: %v", err)
	}
}

func TestTokenService_Validate_GarbageBase64(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.Validate("!@#$%^&*().")
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for garbage base64, got: %v", err)
	}
}

func TestTokenService_Validate_TokenFromDifferentKey(t *testing.T) {
	// A token signed by svc1 must not be accepted by svc2.
	svc1 := newTestService(t)
	svc2 := newTestService(t)

	tokenStr, _, err := svc1.Issue(testIdentity("fp1"))
	if err != nil {
		t.Fatalf("Issue on svc1: %v", err)
	}

	_, err = svc2.Validate(tokenStr)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for token from different key, got: %v", err)
	}
}

func TestTokenService_Validate_ValidPayloadNewMAC(t *testing.T) {
	// An attacker who extracts the payload (it's base64-encoded JSON, not
	// encrypted) cannot produce a valid MAC without the key.
	svc := newTestService(t)
	tokenStr, _, err := svc.Issue(testIdentity("fp1"))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Take the valid payload and attach a random MAC.
	parts := strings.SplitN(tokenStr, ".", 2)
	fakeMAC := base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // 32 zero bytes
	attack := parts[0] + "." + fakeMAC

	_, err = svc.Validate(attack)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for valid payload + fake MAC, got: %v", err)
	}
}

func TestTokenService_Validate_MissingRequiredClaims(t *testing.T) {
	// Use IssueWithOverriddenClaimsForTest (export_test.go) to produce tokens
	// with valid HMACs but empty required claim fields.  This directly tests
	// the required-claims check in verify(), which is unreachable via Issue()
	// because Issue() always produces non-empty jti/sub/cfp/team.
	svc := newTestService(t)
	id := testIdentity("fp1")

	cases := []struct {
		name           string
		jti, sub, team, cfp string
	}{
		{"empty_jti",  "",         "sub@team",      "platform-team", "fp1"},
		{"empty_sub",  "test-jti", "",              "platform-team", "fp1"},
		{"empty_cfp",  "test-jti", "sub@team",      "platform-team", ""},
		{"empty_team", "test-jti", "sub@team",      "",              "fp1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokenStr, err := svc.IssueWithOverriddenClaimsForTest(
				tc.jti, tc.sub, tc.team, tc.cfp, id)
			if err != nil {
				t.Fatalf("IssueWithOverriddenClaimsForTest: %v", err)
			}
			_, err = svc.Validate(tokenStr)
			if !errors.Is(err, auth.ErrTokenInvalid) {
				t.Errorf("expected ErrTokenInvalid for %s, got: %v", tc.name, err)
			}
		})
	}
}

// ── Revocation ────────────────────────────────────────────────────────────────

func TestTokenService_Revoke_ValidToken(t *testing.T) {
	svc := newTestService(t)
	tokenStr, _, err := svc.Issue(testIdentity("fp1"))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Before revocation: must be valid.
	if _, err := svc.Validate(tokenStr); err != nil {
		t.Fatalf("Validate before revocation failed: %v", err)
	}

	// Revoke.
	tok, err := svc.Revoke(tokenStr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if tok == nil {
		t.Fatal("Revoke returned nil Token")
	}
	if tok.Identity.CallerID != "bert@platform-team" {
		t.Errorf("Revoke returned wrong identity: %+v", tok.Identity)
	}

	// After revocation: must return ErrTokenRevoked.
	_, err = svc.Validate(tokenStr)
	if !errors.Is(err, auth.ErrTokenRevoked) {
		t.Errorf("Validate after revocation: expected ErrTokenRevoked, got: %v", err)
	}
}

func TestTokenService_Revoke_InvalidSignature(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.Revoke("garbage.garbage")
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("Revoke with garbage token: expected ErrTokenInvalid, got: %v", err)
	}
}

func TestTokenService_Revoke_Idempotent(t *testing.T) {
	svc := newTestService(t)
	tokenStr, _, err := svc.Issue(testIdentity("fp1"))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := svc.Revoke(tokenStr); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	// Second revoke: the token is already in the revocation list; verify()
	// still succeeds (it only checks the signature), so Revoke should succeed.
	if _, err := svc.Revoke(tokenStr); err != nil {
		t.Fatalf("second Revoke (idempotent): %v", err)
	}
}

func TestTokenService_Revoke_DoesNotAffectOtherTokens(t *testing.T) {
	svc := newTestService(t)
	tok1, _, err := svc.Issue(testIdentity("fp1"))
	if err != nil {
		t.Fatalf("Issue tok1: %v", err)
	}
	tok2, _, err := svc.Issue(testIdentity("fp2"))
	if err != nil {
		t.Fatalf("Issue tok2: %v", err)
	}

	if _, err := svc.Revoke(tok1); err != nil {
		t.Fatalf("Revoke tok1: %v", err)
	}

	// tok2 should still be valid.
	if _, err := svc.Validate(tok2); err != nil {
		t.Errorf("Validate tok2 after revoking tok1: %v", err)
	}
}

// ── No key material in errors or tokens ───────────────────────────────────────

func TestTokenService_TokenStringContainsNoKeyMaterial(t *testing.T) {
	svc := newTestService(t)
	tokenStr, _, err := svc.Issue(testIdentity("aabbccdd"))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Decode the payload to confirm no key-like fields are present.
	parts := strings.SplitN(tokenStr, ".", 2)
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decoding token payload: %v", err)
	}

	payloadStr := string(payload)

	// These strings must never appear in the token payload.
	forbidden := []string{"signingKey", "signing_key", "private", "secret"}
	for _, bad := range forbidden {
		if strings.Contains(payloadStr, bad) {
			t.Errorf("token payload contains forbidden string %q", bad)
		}
	}
}
