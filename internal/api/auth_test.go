package api_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
	"github.com/agentkms/agentkms/pkg/tlsutil"
)

// ── Test infrastructure ───────────────────────────────────────────────────────

var authTestCA = func() *tlsutil.CertBundle {
	ca, err := tlsutil.GenerateSelfSignedCA(tlsutil.CAOptions{
		CN:       "Auth Test CA",
		Org:      "test",
		Validity: time.Hour,
	})
	if err != nil {
		panic("authTestCA: " + err.Error())
	}
	return ca
}()

// nullAuditor discards all events and records them for inspection.
type nullAuditor struct {
	events []audit.AuditEvent
}

func (a *nullAuditor) Log(_ context.Context, ev audit.AuditEvent) error {
	a.events = append(a.events, ev)
	return nil
}
func (a *nullAuditor) Flush(_ context.Context) error { return nil }

// newTestStack builds a TokenService + AuthHandler with a null auditor.
func newTestStack(t *testing.T) (*auth.TokenService, *api.AuthHandler, *nullAuditor) {
	t.Helper()
	rl := auth.NewRevocationList()
	svc, err := auth.NewTokenService(rl)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}
	auditor := &nullAuditor{}
	handler := api.NewAuthHandler(svc, auditor, policy.DenyAllEngine{}, "test")
	return svc, handler, auditor
}

// makeTestCert generates a developer client cert signed by authTestCA.
func makeTestCert(t *testing.T, cn string) *tlsutil.CertBundle {
	t.Helper()
	cert, err := tlsutil.GenerateLeafCert(authTestCA, tlsutil.LeafOptions{
		CN:           cn,
		Org:          "platform-team",
		OrgUnit:      "developer",
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Validity:     time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}
	return cert
}

// postWithCert creates a POST request with the cert in TLS state.
func postWithCert(t *testing.T, path string, cert *x509.Certificate) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if cert != nil {
		r.TLS = &tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{cert}},
		}
	}
	return r
}

// postWithToken creates a POST request with cert + Authorization: Bearer header.
func postWithToken(t *testing.T, path string, cert *x509.Certificate, token string) *http.Request {
	t.Helper()
	r := postWithCert(t, path, cert)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// decodeSession decodes a session response body from the recorder.
func decodeSession(t *testing.T, body io.Reader) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(body).Decode(&m); err != nil {
		t.Fatalf("decoding session response: %v", err)
	}
	return m
}

// doSession calls Session and returns the response recorder.
func doSession(t *testing.T, handler *api.AuthHandler, cert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	handler.Session(w, postWithCert(t, "/auth/session", cert))
	return w
}

// sessionToken calls Session, asserts 200, and returns the token string.
func sessionToken(t *testing.T, handler *api.AuthHandler, cert *x509.Certificate) string {
	t.Helper()
	w := doSession(t, handler, cert)
	if w.Code != http.StatusOK {
		t.Fatalf("Session: status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeSession(t, w.Body)
	tok, ok := resp["token"].(string)
	if !ok || tok == "" {
		t.Fatal("Session response missing 'token'")
	}
	return tok
}

// withToken injects tok into the context using the test helper.
// This simulates what RequireToken middleware does before calling handlers.
func withToken(r *http.Request, tok *auth.Token) *http.Request {
	ctx := auth.InjectTokenForTest(r.Context(), tok)
	return r.WithContext(ctx)
}

// ── POST /auth/session tests ──────────────────────────────────────────────────

func TestSession_ValidCert_Returns200WithToken(t *testing.T) {
	_, handler, _ := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	w := doSession(t, handler, cert.Cert)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	resp := decodeSession(t, w.Body)
	if tok, ok := resp["token"].(string); !ok || tok == "" {
		t.Fatal("response missing or empty 'token' field")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", resp["token_type"])
	}
	if expiresIn, ok := resp["expires_in"].(float64); !ok || expiresIn != 900 {
		t.Errorf("expires_in = %v, want 900", resp["expires_in"])
	}
	if sid, ok := resp["session_id"].(string); !ok || sid == "" {
		t.Error("missing or empty session_id")
	}
}

func TestSession_ContentTypeIsJSON(t *testing.T) {
	_, handler, _ := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	w := doSession(t, handler, cert.Cert)

	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestSession_NoCert_Returns401(t *testing.T) {
	_, handler, _ := newTestStack(t)

	w := doSession(t, handler, nil) // nil → no TLS state set

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for missing client cert", w.Code)
	}
}

func TestSession_NoTLSState_Returns401(t *testing.T) {
	_, handler, _ := newTestStack(t)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/session", nil)
	// r.TLS is nil.
	handler.Session(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for plaintext (non-TLS) request", w.Code)
	}
}

func TestSession_WrongMethod_Returns405(t *testing.T) {
	_, handler, _ := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			w := httptest.NewRecorder()
			r, _ := http.NewRequest(method, "/auth/session", nil)
			r.TLS = &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert.Cert}},
			}
			handler.Session(w, r)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: status = %d, want 405", method, w.Code)
			}
		})
	}
}

func TestSession_IssuedTokenPassesValidate(t *testing.T) {
	svc, handler, _ := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	tokenStr := sessionToken(t, handler, cert.Cert)

	tok, err := svc.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate on Session-issued token: %v", err)
	}
	if tok.Identity.CallerID != "bert@platform-team" {
		t.Errorf("CallerID = %q, want bert@platform-team", tok.Identity.CallerID)
	}
}

func TestSession_AuditEventWritten(t *testing.T) {
	_, handler, auditor := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	doSession(t, handler, cert.Cert)

	if len(auditor.events) == 0 {
		t.Fatal("no audit events written")
	}
	ev := auditor.events[0]
	if ev.Operation != audit.OperationAuth {
		t.Errorf("audit.Operation = %q, want %q", ev.Operation, audit.OperationAuth)
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("audit.Outcome = %q, want %q", ev.Outcome, audit.OutcomeSuccess)
	}
	if ev.CallerID != "bert@platform-team" {
		t.Errorf("audit.CallerID = %q, want bert@platform-team", ev.CallerID)
	}
	if ev.AgentSession == "" {
		t.Error("audit.AgentSession (session_id) is empty")
	}
}

func TestSession_RevokedCert_Returns401(t *testing.T) {
	_, handler, auditor := newTestStack(t)
	cert := makeTestCert(t, "revoked@platform-team")

	// Setup revocation checker
	checker := auth.NewCertRevocationChecker()
	// Create a dummy CRL with this cert's serial number
	crlDER, err := tlsutil.GenerateCRL(authTestCA, []x509.RevocationListEntry{
		{
			SerialNumber:   cert.Cert.SerialNumber,
			RevocationTime: time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	if err := checker.UpdateFromCRL(crlDER); err != nil {
		t.Fatalf("UpdateFromCRL: %v", err)
	}

	handler.SetPKI(nil, checker) // nil PKI client for this test

	w := doSession(t, handler, cert.Cert)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for revoked cert", w.Code)
	}
	if !strings.Contains(w.Body.String(), "revoked") {
		t.Errorf("body = %q, want mention of revocation", w.Body.String())
	}

	// Verify audit log
	if len(auditor.events) == 0 {
		t.Fatal("no audit events written for revoked cert")
	}
	ev := auditor.events[0]
	if ev.Operation != audit.OperationAuth {
		t.Errorf("audit.Operation = %q, want %q", ev.Operation, audit.OperationAuth)
	}
	if ev.DenyReason != "client certificate revoked" {
		t.Errorf("audit.DenyReason = %q, want 'client certificate revoked'", ev.DenyReason)
	}
}

// ── POST /auth/refresh tests ──────────────────────────────────────────────────

func TestRefresh_ValidToken_Returns200WithNewToken(t *testing.T) {
	svc, handler, _ := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	oldTokenStr := sessionToken(t, handler, cert.Cert)
	oldTok, _ := svc.Validate(oldTokenStr)

	w := httptest.NewRecorder()
	r := withToken(postWithToken(t, "/auth/refresh", cert.Cert, oldTokenStr), oldTok)
	handler.Refresh(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Refresh: status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeSession(t, w.Body)
	newTokenStr, ok := resp["token"].(string)
	if !ok || newTokenStr == "" {
		t.Fatal("Refresh response missing 'token'")
	}
	if newTokenStr == oldTokenStr {
		t.Error("Refresh returned the same token — expected a fresh one")
	}
	// New token must be validatable.
	if _, err := svc.Validate(newTokenStr); err != nil {
		t.Errorf("new token from Refresh fails Validate: %v", err)
	}
}

func TestRefresh_OldTokenIsRevoked(t *testing.T) {
	svc, handler, _ := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	oldTokenStr := sessionToken(t, handler, cert.Cert)
	oldTok, _ := svc.Validate(oldTokenStr)

	w := httptest.NewRecorder()
	r := withToken(postWithToken(t, "/auth/refresh", cert.Cert, oldTokenStr), oldTok)
	handler.Refresh(w, r)

	// Old token must now be revoked.
	if _, err := svc.Validate(oldTokenStr); err == nil {
		t.Error("old token still valid after Refresh — expected it to be revoked")
	}
}

func TestRefresh_ExpiresIn900(t *testing.T) {
	svc, handler, _ := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	oldTokenStr := sessionToken(t, handler, cert.Cert)
	oldTok, _ := svc.Validate(oldTokenStr)

	w := httptest.NewRecorder()
	r := withToken(postWithToken(t, "/auth/refresh", cert.Cert, oldTokenStr), oldTok)
	handler.Refresh(w, r)

	resp := decodeSession(t, w.Body)
	if expiresIn, ok := resp["expires_in"].(float64); !ok || expiresIn != 900 {
		t.Errorf("expires_in = %v, want 900", resp["expires_in"])
	}
}

func TestRefresh_WrongMethod_Returns405(t *testing.T) {
	_, handler, _ := newTestStack(t)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/auth/refresh", nil)
	handler.Refresh(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestRefresh_NoContextToken_Returns401(t *testing.T) {
	_, handler, _ := newTestStack(t)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/refresh", nil)
	// No token in context — simulates middleware misconfiguration.
	handler.Refresh(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when token missing from context", w.Code)
	}
}

// ── POST /auth/revoke tests ───────────────────────────────────────────────────

func TestRevoke_ValidToken_Returns204(t *testing.T) {
	svc, handler, _ := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	tokenStr := sessionToken(t, handler, cert.Cert)
	tok, _ := svc.Validate(tokenStr)

	w := httptest.NewRecorder()
	r := withToken(postWithToken(t, "/auth/revoke", cert.Cert, tokenStr), tok)
	handler.Revoke(w, r)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
}

func TestRevoke_TokenInvalidatedAfterRevoke(t *testing.T) {
	svc, handler, _ := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	tokenStr := sessionToken(t, handler, cert.Cert)
	tok, _ := svc.Validate(tokenStr)

	w := httptest.NewRecorder()
	r := withToken(postWithToken(t, "/auth/revoke", cert.Cert, tokenStr), tok)
	handler.Revoke(w, r)

	if _, err := svc.Validate(tokenStr); err == nil {
		t.Error("token still valid after Revoke endpoint called")
	}
}

func TestRevoke_NoContextToken_Returns204(t *testing.T) {
	// Revoke must return 204 regardless — no oracle.
	_, handler, _ := newTestStack(t)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/revoke", nil)
	handler.Revoke(w, r)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (no oracle)", w.Code)
	}
}

func TestRevoke_WrongMethod_Returns405(t *testing.T) {
	_, handler, _ := newTestStack(t)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/auth/revoke", nil)
	handler.Revoke(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestRevoke_AuditEventWritten(t *testing.T) {
	svc, handler, auditor := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	tokenStr := sessionToken(t, handler, cert.Cert)
	tok, _ := svc.Validate(tokenStr)

	w := httptest.NewRecorder()
	r := withToken(postWithToken(t, "/auth/revoke", cert.Cert, tokenStr), tok)
	handler.Revoke(w, r)

	var revokeEv *audit.AuditEvent
	for i := range auditor.events {
		if auditor.events[i].Operation == audit.OperationRevoke {
			ev := auditor.events[i]
			revokeEv = &ev
			break
		}
	}
	if revokeEv == nil {
		t.Fatal("no revoke audit event found")
	}
	if revokeEv.Outcome != audit.OutcomeSuccess {
		t.Errorf("revoke audit.Outcome = %q, want success", revokeEv.Outcome)
	}
	if revokeEv.CallerID != "bert@platform-team" {
		t.Errorf("revoke audit.CallerID = %q, want bert@platform-team", revokeEv.CallerID)
	}
}

// ── Security: no key material in responses ────────────────────────────────────

func TestSession_ResponseContainsNoKeyMaterial(t *testing.T) {
	_, handler, _ := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	w := doSession(t, handler, cert.Cert)
	body := w.Body.String()

	for _, bad := range []string{"signingKey", "signing_key", "privateKey", "aesKey", "ecPrivKey", "-----BEGIN"} {
		if strings.Contains(body, bad) {
			t.Errorf("session response body contains forbidden string %q", bad)
		}
	}
}

func TestRevoke_Returns204ForBothValidAndInvalidScenarios(t *testing.T) {
	// The response must be identical (204) whether the token was valid or not,
	// to prevent an attacker from probing token validity via this endpoint.
	_, handler, _ := newTestStack(t)

	responses := make([]int, 0, 2)

	// Case 1: no token in context.
	w1 := httptest.NewRecorder()
	r1, _ := http.NewRequest(http.MethodPost, "/auth/revoke", nil)
	handler.Revoke(w1, r1)
	responses = append(responses, w1.Code)

	// Case 2: valid token context.
	svc2, handler2, _ := newTestStack(t)
	cert2 := makeTestCert(t, "bert@platform-team")
	tokenStr2 := sessionToken(t, handler2, cert2.Cert)
	tok2, _ := svc2.Validate(tokenStr2)
	w2 := httptest.NewRecorder()
	r2 := withToken(postWithToken(t, "/auth/revoke", cert2.Cert, tokenStr2), tok2)
	handler2.Revoke(w2, r2)
	responses = append(responses, w2.Code)

	for i, code := range responses {
		if code != http.StatusNoContent {
			t.Errorf("case %d: status = %d, want 204", i+1, code)
		}
	}
}

// ── Full middleware integration ────────────────────────────────────────────────

// TestRefreshRevoke_WithMiddleware runs the full middleware + handler stack
// end-to-end to verify that RequireToken correctly gates /auth/refresh and
// /auth/revoke.
func TestRefreshRevoke_WithMiddleware(t *testing.T) {
	svc, handler, _ := newTestStack(t)
	cert := makeTestCert(t, "bert@platform-team")

	// Build middleware-wrapped handlers.
	refreshH := auth.RequireToken(svc)(http.HandlerFunc(handler.Refresh))
	revokeH := auth.RequireToken(svc)(http.HandlerFunc(handler.Revoke))

	// Get a valid token.
	tokenStr := sessionToken(t, handler, cert.Cert)

	// ── Refresh with valid token ───────────────────────────────────────────
	w1 := httptest.NewRecorder()
	r1 := postWithToken(t, "/auth/refresh", cert.Cert, tokenStr)
	refreshH.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("middleware+Refresh: status = %d, body = %s", w1.Code, w1.Body.String())
	}
	newTokenStr := decodeSession(t, w1.Body)["token"].(string)

	// ── Revoke the new token with valid token ──────────────────────────────
	w2 := httptest.NewRecorder()
	r2 := postWithToken(t, "/auth/revoke", cert.Cert, newTokenStr)
	revokeH.ServeHTTP(w2, r2)
	if w2.Code != http.StatusNoContent {
		t.Fatalf("middleware+Revoke: status = %d", w2.Code)
	}

	// ── Refresh with revoked token must fail at middleware ─────────────────
	w3 := httptest.NewRecorder()
	r3 := postWithToken(t, "/auth/refresh", cert.Cert, newTokenStr)
	refreshH.ServeHTTP(w3, r3)
	if w3.Code != http.StatusUnauthorized {
		t.Errorf("refresh with revoked token: status = %d, want 401", w3.Code)
	}
}
// ── POST /auth/delegate tests ─────────────────────────────────────────────────

// mockPolicyEngine implements policy.EngineI for testing.
type mockPolicyEngine struct {
	allow bool
}

func (m *mockPolicyEngine) Evaluate(ctx context.Context, id identity.Identity, operation string, keyID string) (policy.Decision, error) {
	if m.allow {
		return policy.Decision{Allow: true}, nil
	}
	return policy.Decision{Allow: false, DenyReason: "mock deny"}, nil
}
func (m *mockPolicyEngine) GetPolicy() policy.Policy { return policy.Policy{} }
func (m *mockPolicyEngine) Reload(p policy.Policy) error { return nil }

func newTestStackWithMockPolicy(t *testing.T, allow bool) (*auth.TokenService, *api.AuthHandler, *nullAuditor) {
	t.Helper()
	rl := auth.NewRevocationList()
	svc, err := auth.NewTokenService(rl)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}
	auditor := &nullAuditor{}
	handler := api.NewAuthHandler(svc, auditor, &mockPolicyEngine{allow: allow}, "test")
	return svc, handler, auditor
}

func TestDelegate_Valid_Returns200WithToken(t *testing.T) {
	svc, handler, _ := newTestStackWithMockPolicy(t, true)
	cert := makeTestCert(t, "bert@platform-team")

	// sessionToken uses the handler which now has a mockPolicyEngine
	parentTokStr := sessionToken(t, handler, cert.Cert)
	parentTok, _ := svc.Validate(parentTokStr)

	reqBody := `{"scopes": ["sign:key-123"], "ttl_seconds": 300}`
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/delegate", strings.NewReader(reqBody))
	r.Header.Set("Content-Type", "application/json")
	r = withToken(r, parentTok)
	
	handler.Delegate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Delegate: status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeSession(t, w.Body)
	tok, ok := resp["token"].(string)
	if !ok || tok == "" {
		t.Fatal("Delegate response missing 'token'")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", resp["token_type"])
	}
	if expiresIn, ok := resp["expires_in"].(float64); !ok || expiresIn != 300 {
		t.Errorf("expires_in = %v, want 300", resp["expires_in"])
	}
	if sid, ok := resp["session_id"].(string); !ok || sid == "" {
		t.Error("missing or empty session_id")
	}

	// Validate the new token.
	newTok, err := svc.Validate(tok)
	if err != nil {
		t.Fatalf("Validate delegated token: %v", err)
	}
	if len(newTok.Identity.Scopes) != 1 || newTok.Identity.Scopes[0] != "sign:key-123" {
		t.Errorf("delegated scopes = %v, want [sign:key-123]", newTok.Identity.Scopes)
	}
}

func TestDelegate_WrongMethod_Returns405(t *testing.T) {
	_, handler, _ := newTestStack(t)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/auth/delegate", nil)
	handler.Delegate(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestDelegate_NoToken_Returns401(t *testing.T) {
	_, handler, _ := newTestStack(t)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/delegate", strings.NewReader(`{"scopes": ["sign:key-123"]}`))
	handler.Delegate(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestDelegate_InvalidJSON_Returns400(t *testing.T) {
	svc, handler, _ := newTestStackWithMockPolicy(t, true)
	cert := makeTestCert(t, "bert@platform-team")
	parentTokStr := sessionToken(t, handler, cert.Cert)
	parentTok, _ := svc.Validate(parentTokStr)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/delegate", strings.NewReader(`{invalid`))
	r = withToken(r, parentTok)
	handler.Delegate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestDelegate_NoScopes_Returns400(t *testing.T) {
	svc, handler, _ := newTestStackWithMockPolicy(t, true)
	cert := makeTestCert(t, "bert@platform-team")
	parentTokStr := sessionToken(t, handler, cert.Cert)
	parentTok, _ := svc.Validate(parentTokStr)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/delegate", strings.NewReader(`{"scopes": []}`))
	r = withToken(r, parentTok)
	handler.Delegate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestDelegate_InvalidScopeFormat_Returns400(t *testing.T) {
	svc, handler, _ := newTestStackWithMockPolicy(t, true)
	cert := makeTestCert(t, "bert@platform-team")
	parentTokStr := sessionToken(t, handler, cert.Cert)
	parentTok, _ := svc.Validate(parentTokStr)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/delegate", strings.NewReader(`{"scopes": ["invalid_format"]}`))
	r = withToken(r, parentTok)
	handler.Delegate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestDelegate_PolicyDeny_Returns403(t *testing.T) {
	svc, handler, _ := newTestStackWithMockPolicy(t, false) // false -> denies everything
	cert := makeTestCert(t, "bert@platform-team")
	
	// Wait, we need the parent token to be issued! sessionToken will succeed if mockPolicyEngine isn't involved in issuance?
	// Oh, Session doesn't evaluate policy, it just authenticates the cert. Let's check!
	parentTokStr := sessionToken(t, handler, cert.Cert)
	parentTok, _ := svc.Validate(parentTokStr)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/delegate", strings.NewReader(`{"scopes": ["sign:key-123"]}`))
	r = withToken(r, parentTok)
	handler.Delegate(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}
func TestRevokeCertificate_PKINotConfigured(t *testing.T) {
	_, handler, _ := newTestStack(t)
	// Do not set PKI
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/certificate/revoke", bytes.NewReader([]byte(`{"serial_number": "123"}`)))
	handler.RevokeCertificate(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", w.Code)
	}
}

func TestRevokeCertificate_WrongMethod(t *testing.T) {
	_, handler, _ := newTestStack(t)
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/auth/certificate/revoke", nil)
	handler.RevokeCertificate(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestCRL_PKINotConfigured(t *testing.T) {
	_, handler, _ := newTestStack(t)
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/auth/certificate/crl", nil)
	handler.CRL(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", w.Code)
	}
}

func TestCRL_WrongMethod(t *testing.T) {
	_, handler, _ := newTestStack(t)
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/auth/certificate/crl", nil)
	handler.CRL(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAuthMiddleware_ExposedPublic(t *testing.T) {
	rl := auth.NewRevocationList()
	ts, _ := auth.NewTokenService(rl)
	srv := api.NewServer(backend.NewDevBackend(), &capturingAuditor{}, policy.AllowAllEngine{}, ts, "dev")

	// AuthMiddleware is the exported wrapper — just call it and verify it returns a non-nil handler.
	handler := srv.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	if handler == nil {
		t.Fatal("AuthMiddleware returned nil")
	}
}
