package auth_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/pkg/identity"
	"github.com/agentkms/agentkms/pkg/tlsutil"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// noopHandler is a handler that records whether it was called.
type noopHandler struct {
	called bool
	token  *auth.Token
}

func (h *noopHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.token = auth.TokenFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

// requestWithTokenAndCert creates a request with:
//   - Authorization: Bearer <tokenStr> header
//   - TLS state containing cert as the verified client certificate
func requestWithTokenAndCert(t *testing.T, tokenStr string, cert *x509.Certificate) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "/auth/refresh", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	if tokenStr != "" {
		r.Header.Set("Authorization", "Bearer "+tokenStr)
	}
	if cert != nil {
		r.TLS = &tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{cert}},
		}
	}
	return r
}

// issueTokenForCert issues a session token bound to the fingerprint of the
// provided certificate.
func issueTokenForCert(t *testing.T, svc *auth.TokenService, cert *x509.Certificate, cn string) string {
	t.Helper()
	// Extract identity from a fake request carrying this cert.
	r := requestWithCert(t, cert)
	id, err := auth.ExtractIdentity(r)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	// Override CallerID in case CN was generated differently.
	_ = cn

	tokenStr, _, err := svc.Issue(id)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tokenStr
}

// ── RequireToken tests ────────────────────────────────────────────────────────

func TestRequireToken_ValidToken_PassesThrough(t *testing.T) {
	svc := newTestService(t)
	cert := mustClientCert(t, testCA, "bert@platform-team")

	tokenStr := issueTokenForCert(t, svc, cert.Cert, "bert@platform-team")

	handler := &noopHandler{}
	mw := auth.RequireToken(svc)(handler)

	w := httptest.NewRecorder()
	r := requestWithTokenAndCert(t, tokenStr, cert.Cert)
	mw.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !handler.called {
		t.Error("inner handler was not called for valid token")
	}
	if handler.token == nil {
		t.Error("Token not stored in context for valid token")
	}
	if handler.token.Identity.CallerID != "bert@platform-team" {
		t.Errorf("context token CallerID = %q, want %q", handler.token.Identity.CallerID, "bert@platform-team")
	}
}

func TestRequireToken_NoAuthorizationHeader(t *testing.T) {
	svc := newTestService(t)
	cert := mustClientCert(t, testCA, "bert@platform-team")

	handler := &noopHandler{}
	mw := auth.RequireToken(svc)(handler)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/refresh", nil)
	r.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{cert.Cert}},
	}
	// No Authorization header.

	mw.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if handler.called {
		t.Error("inner handler was called — should have been rejected at middleware")
	}
}

func TestRequireToken_WrongAuthScheme(t *testing.T) {
	svc := newTestService(t)
	cert := mustClientCert(t, testCA, "bert@platform-team")

	tokenStr := issueTokenForCert(t, svc, cert.Cert, "bert@platform-team")

	handler := &noopHandler{}
	mw := auth.RequireToken(svc)(handler)

	w := httptest.NewRecorder()
	r := requestWithTokenAndCert(t, "", cert.Cert)
	r.Header.Set("Authorization", "Token "+tokenStr) // "Token" instead of "Bearer"
	mw.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for wrong auth scheme", w.Code)
	}
}

func TestRequireToken_InvalidTokenString(t *testing.T) {
	svc := newTestService(t)
	cert := mustClientCert(t, testCA, "bert@platform-team")

	handler := &noopHandler{}
	mw := auth.RequireToken(svc)(handler)

	w := httptest.NewRecorder()
	r := requestWithTokenAndCert(t, "this-is-not-a-valid-token", cert.Cert)
	mw.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for invalid token", w.Code)
	}
}

func TestRequireToken_TamperedPayload(t *testing.T) {
	svc := newTestService(t)
	cert := mustClientCert(t, testCA, "bert@platform-team")
	tokenStr := issueTokenForCert(t, svc, cert.Cert, "bert@platform-team")

	// Flip the last byte of the payload segment.
	dotIdx := len(tokenStr) - 1
	for i := len(tokenStr) - 1; i >= 0; i-- {
		if tokenStr[i] == '.' {
			dotIdx = i
			break
		}
	}
	payload := []byte(tokenStr[:dotIdx])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + tokenStr[dotIdx:]

	handler := &noopHandler{}
	mw := auth.RequireToken(svc)(handler)

	w := httptest.NewRecorder()
	r := requestWithTokenAndCert(t, tampered, cert.Cert)
	mw.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for tampered token", w.Code)
	}
}

func TestRequireToken_RevokedToken(t *testing.T) {
	svc := newTestService(t)
	cert := mustClientCert(t, testCA, "bert@platform-team")
	tokenStr := issueTokenForCert(t, svc, cert.Cert, "bert@platform-team")

	if _, err := svc.Revoke(tokenStr); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	handler := &noopHandler{}
	mw := auth.RequireToken(svc)(handler)

	w := httptest.NewRecorder()
	r := requestWithTokenAndCert(t, tokenStr, cert.Cert)
	mw.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for revoked token", w.Code)
	}
}

func TestRequireToken_CertMismatch_ReplayAttack(t *testing.T) {
	// Token issued for cert A, request presents cert B.
	// This simulates a token replay attack from a different connection.
	svc := newTestService(t)
	certA := mustClientCert(t, testCA, "bert@platform-team")
	certB := mustClientCert(t, testCA, "alice@platform-team")

	// Issue token bound to certA.
	tokenStr := issueTokenForCert(t, svc, certA.Cert, "bert@platform-team")

	handler := &noopHandler{}
	mw := auth.RequireToken(svc)(handler)

	w := httptest.NewRecorder()
	// Request presents certB, not certA.
	r := requestWithTokenAndCert(t, tokenStr, certB.Cert)
	mw.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for cert mismatch (replay attack)", w.Code)
	}
	if handler.called {
		t.Error("inner handler was called despite cert fingerprint mismatch")
	}
}

func TestRequireToken_NoTLSState_Rejected(t *testing.T) {
	// A request that somehow reaches the middleware without TLS must be rejected.
	// This is a defence-in-depth check: mTLS is enforced at the server level,
	// but if the middleware is accidentally applied to a plaintext endpoint,
	// we still reject.
	svc := newTestService(t)

	// We can't easily issue a token without a cert, so we use a direct identity.
	rl := auth.NewRevocationList()
	svc2, _ := auth.NewTokenService(rl)
	fakeFP := "deadbeef"
	id := &identity.Identity{
		CallerID:        "bert@platform-team",
		TeamID:          "platform-team",
		Role:            identity.RoleDeveloper,
		CertFingerprint: fakeFP,
	}
	tokenStr, _, err := svc2.Issue(id)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_ = svc // not used; test uses svc2 to issue and validate
	handler := &noopHandler{}
	mw := auth.RequireToken(svc2)(handler)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/refresh", nil)
	r.Header.Set("Authorization", "Bearer "+tokenStr)
	// r.TLS is nil — no TLS state.

	mw.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for request with no TLS state", w.Code)
	}
}

// ── ExtractBearerToken tests ──────────────────────────────────────────────────

func TestExtractBearerToken_ValidHeader(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer mytoken123")

	got := auth.ExtractBearerToken(r)
	if got != "mytoken123" {
		t.Errorf("ExtractBearerToken = %q, want %q", got, "mytoken123")
	}
}

func TestExtractBearerToken_MissingHeader(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	if got := auth.ExtractBearerToken(r); got != "" {
		t.Errorf("ExtractBearerToken = %q, want empty string", got)
	}
}

func TestExtractBearerToken_WrongScheme(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	if got := auth.ExtractBearerToken(r); got != "" {
		t.Errorf("ExtractBearerToken = %q, want empty string for Basic auth", got)
	}
}

func TestExtractBearerToken_EmptyBearerValue(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer    ") // whitespace only
	if got := auth.ExtractBearerToken(r); got != "" {
		t.Errorf("ExtractBearerToken = %q, want empty string for whitespace-only token", got)
	}
}

// ── TokenFromContext tests ────────────────────────────────────────────────────

func TestTokenFromContext_NotPresent(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	tok := auth.TokenFromContext(r.Context())
	if tok != nil {
		t.Errorf("TokenFromContext = %+v, want nil for context without token", tok)
	}
}

// ── Error response format tests ───────────────────────────────────────────────

func TestRequireToken_ErrorResponseIsJSON(t *testing.T) {
	svc := newTestService(t)
	handler := &noopHandler{}
	mw := auth.RequireToken(svc)(handler)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/", nil)
	mw.ServeHTTP(w, r)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if w.Body.Len() == 0 {
		t.Error("empty response body for 401")
	}
}

func TestRequireToken_ErrorDoesNotLeakTokenDetails(t *testing.T) {
	svc := newTestService(t)
	cert := mustClientCert(t, testCA, "bert@platform-team")
	tokenStr := issueTokenForCert(t, svc, cert.Cert, "bert@platform-team")

	// Revoke token, then try to use it.
	svc.Revoke(tokenStr) //nolint:errcheck

	handler := &noopHandler{}
	mw := auth.RequireToken(svc)(handler)

	w := httptest.NewRecorder()
	r := requestWithTokenAndCert(t, tokenStr, cert.Cert)
	mw.ServeHTTP(w, r)

	body := w.Body.String()
	// Error body must not say "revoked" or "ErrTokenRevoked" (oracle attack).
	for _, forbidden := range []string{"revoked", "ErrToken", "jti", "fingerprint"} {
		if contains(body, forbidden) {
			t.Errorf("error response body contains %q — potential oracle leak: %s", forbidden, body)
		}
	}
}

// ── helper ────────────────────────────────────────────────────────────────────

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Ensure errors from different adversarial paths don't expose more info.
var _ = errors.Is // imported for adversarial token test helpers

// certValidity is a helper for creating test certs with standard 1-hour TTL.
var _ = tlsutil.LeafOptions{Validity: time.Hour} // keep import live
