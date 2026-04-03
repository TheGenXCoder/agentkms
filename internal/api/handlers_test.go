package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
)

// ── Test infrastructure ───────────────────────────────────────────────────────

// nopAuditor implements audit.Auditor without any side effects.
type nopAuditor struct{}

func (n *nopAuditor) Log(_ context.Context, _ audit.AuditEvent) error { return nil }
func (n *nopAuditor) Flush(_ context.Context) error                   { return nil }

// captureAuditor records every audit event for later inspection.
type captureAuditor struct {
	events []audit.AuditEvent
}

func (c *captureAuditor) Log(_ context.Context, ev audit.AuditEvent) error {
	c.events = append(c.events, ev)
	return nil
}
func (c *captureAuditor) Flush(_ context.Context) error { return nil }

// testServer builds a fully configured Server with a dev backend and an
// allow-all policy.  Returns the server, the token store, and the dev backend.
func testServer(t *testing.T) (*Server, *auth.TokenStore, *backend.DevBackend) {
	t.Helper()

	b := backend.NewDevBackend()
	if err := b.CreateKey("test/signing-key", backend.AlgorithmES256, "dev-team"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if err := b.CreateKey("test/enc-key", backend.AlgorithmAES256GCM, "dev-team"); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	ts, err := auth.NewTokenStore()
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}

	pf := &policy.PolicyFile{
		Version:     1,
		Environment: "dev",
		Rules: []policy.Rule{{
			ID:          "allow-all",
			Identities:  []string{"*"},
			Teams:       []string{"*"},
			Operations:  []string{"*"},
			KeyPrefixes: []string{""},
			Effect:      policy.EffectAllow,
		}},
	}
	eng := policy.NewEngine(pf)

	srv := NewServer(Config{
		Backend:     b,
		Auditor:     &nopAuditor{},
		Tokens:      ts,
		Policy:      eng,
		Environment: "dev",
	})
	return srv, ts, b
}

// testToken issues a token for the default test identity.
// The returned string is ready for use as a Bearer token.
func testToken(t *testing.T, ts *auth.TokenStore) string {
	t.Helper()
	id := &identity.Identity{
		CallerID: "bert@dev",
		TeamID:   "dev-team",
		Role:     identity.RoleDeveloper,
	}
	tokenStr, _, err := ts.Issue(id)
	if err != nil {
		t.Fatalf("Issue token: %v", err)
	}
	return tokenStr
}

// doRequest executes a request against srv.Handler() and returns the response.
func doRequest(srv *Server, method, path, body, token string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// payloadHash returns a "sha256:<hex>" string for the given message.
func payloadHash(msg string) string {
	h := sha256.Sum256([]byte(msg))
	return fmt.Sprintf("sha256:%x", h)
}

// ── Health check ──────────────────────────────────────────────────────────────

func TestHandleHealthz(t *testing.T) {
	srv, _, _ := testServer(t)
	w := doRequest(srv, "GET", "/healthz", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", w.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("healthz: parse response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("healthz: want status=ok, got %q", resp["status"])
	}
}

// ── Auth: /auth/session ───────────────────────────────────────────────────────

func TestHandleAuthSession_NoCert_Unauthorized(t *testing.T) {
	srv, _, _ := testServer(t)
	// No TLS state — r.TLS is nil; identity extraction should fail.
	req := httptest.NewRequest("POST", "/auth/session", nil)
	// Do not set r.TLS — simulates a connection without a client cert.
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", w.Code, w.Body.String())
	}
}

// ── Auth: requireToken middleware ─────────────────────────────────────────────

func TestRequireToken_MissingHeader_401(t *testing.T) {
	srv, _, _ := testServer(t)
	w := doRequest(srv, "GET", "/keys", "", "") // no Authorization header
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestRequireToken_WrongScheme_401(t *testing.T) {
	srv, _, _ := testServer(t)
	req := httptest.NewRequest("GET", "/keys", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // wrong scheme
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestRequireToken_ExpiredToken_401(t *testing.T) {
	srv, ts, _ := testServer(t)
	tokenStr, _, err := ts.Issue(&identity.Identity{CallerID: "bert@dev", TeamID: "dev-team"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Revoke immediately to simulate "used-up" token.
	_ = ts.Revoke(tokenStr)

	w := doRequest(srv, "GET", "/keys", "", tokenStr)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: want 401, got %d", w.Code)
	}
}

func TestRequireToken_TamperedToken_401(t *testing.T) {
	srv, ts, _ := testServer(t)
	tokenStr := testToken(t, ts)

	// Tamper with the MAC portion.
	dotIdx := strings.Index(tokenStr, ".")
	mac := []byte(tokenStr[dotIdx+1:])
	mac[0] ^= 0xFF
	tampered := tokenStr[:dotIdx+1] + string(mac)

	w := doRequest(srv, "GET", "/keys", "", tampered)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("tampered token: want 401, got %d", w.Code)
	}
}

func TestRequireToken_ArbitraryString_401(t *testing.T) {
	srv, _, _ := testServer(t)
	for _, bad := range []string{"not-a-token", "a.b", "eyJhb...", "."} {
		w := doRequest(srv, "GET", "/keys", "", bad)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("bad token %q: want 401, got %d", bad, w.Code)
		}
	}
}

// ── POST /sign/{key-id...} ────────────────────────────────────────────────────

func TestHandleSign_HappyPath(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	body := fmt.Sprintf(`{"payload_hash":"%s","algorithm":"ES256"}`, payloadHash("hello"))
	w := doRequest(srv, "POST", "/sign/test/signing-key", body, token)
	if w.Code != http.StatusOK {
		t.Fatalf("sign: want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp signResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Signature == "" {
		t.Fatal("sign: empty signature in response")
	}
	if resp.KeyVersion != 1 {
		t.Fatalf("sign: want key_version=1, got %d", resp.KeyVersion)
	}
	// Verify signature is valid base64.
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		t.Fatalf("signature is not valid base64: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("decoded signature is empty")
	}
}

func TestHandleSign_MissingPayloadHash_400(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	body := `{"algorithm":"ES256"}` // missing payload_hash
	w := doRequest(srv, "POST", "/sign/test/signing-key", body, token)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleSign_WrongHashFormat_400(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	for _, bad := range []string{
		`{"payload_hash":"notahash","algorithm":"ES256"}`,
		`{"payload_hash":"sha256:tooshort","algorithm":"ES256"}`,
		`{"payload_hash":"md5:deadbeef","algorithm":"ES256"}`,
	} {
		w := doRequest(srv, "POST", "/sign/test/signing-key", bad, token)
		if w.Code != http.StatusBadRequest {
			t.Errorf("bad hash %q: want 400, got %d", bad, w.Code)
		}
	}
}

func TestHandleSign_InvalidAlgorithm_400(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	body := fmt.Sprintf(`{"payload_hash":"%s","algorithm":"AES256GCM"}`, payloadHash("x"))
	w := doRequest(srv, "POST", "/sign/test/signing-key", body, token)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("encryption algorithm for sign: want 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleSign_KeyNotFound_404(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	body := fmt.Sprintf(`{"payload_hash":"%s","algorithm":"ES256"}`, payloadHash("x"))
	w := doRequest(srv, "POST", "/sign/nonexistent/key", body, token)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing key: want 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleSign_PolicyDeny_403(t *testing.T) {
	// Build a server with a deny-all policy.
	b := backend.NewDevBackend()
	_ = b.CreateKey("test/key", backend.AlgorithmES256, "dev-team")
	ts, _ := auth.NewTokenStore()
	pf := &policy.PolicyFile{
		Version: 1,
		Rules:   []policy.Rule{}, // empty = deny all
	}
	srv := NewServer(Config{
		Backend:     b,
		Auditor:     &nopAuditor{},
		Tokens:      ts,
		Policy:      policy.NewEngine(pf),
		Environment: "dev",
	})

	id := &identity.Identity{CallerID: "bert@dev", TeamID: "dev-team"}
	tokenStr, _, _ := ts.Issue(id)

	body := fmt.Sprintf(`{"payload_hash":"%s","algorithm":"ES256"}`, payloadHash("x"))
	req := httptest.NewRequest("POST", "/sign/test/key", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("deny-all policy: want 403, got %d: %s", w.Code, w.Body.String())
	}
}

// ── ADVERSARIAL: response structure and content checks ────────────────────────
//
// Key-material exposure at the backend level is covered exhaustively in
// internal/backend/dev_test.go (F-08 adversarial suite).  Here we verify
// the API contract: responses have correct structure, PEM headers never
// appear, and plaintext is not echoed by /encrypt.

func TestAdversarial_SignResponse_NoPEMHeaders(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	body := fmt.Sprintf(`{"payload_hash":"%s","algorithm":"ES256"}`, payloadHash("adversarial"))
	w := doRequest(srv, "POST", "/sign/test/signing-key", body, token)
	if w.Code != http.StatusOK {
		t.Fatalf("sign: %d %s", w.Code, w.Body.String())
	}

	responseBody := w.Body.String()

	// PEM headers must never appear in API responses.
	if strings.Contains(responseBody, "-----BEGIN") || strings.Contains(responseBody, "-----END") {
		t.Fatal("ADVERSARIAL: sign response contains PEM header")
	}
	// Response must be valid JSON with exactly the expected fields.
	var resp signResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("sign response is not valid JSON: %v", err)  
	}
	if resp.Signature == "" {
		t.Fatal("sign response missing signature")
	}
	if resp.KeyVersion < 1 {
		t.Fatal("sign response missing key_version")
	}
}

func TestAdversarial_EncryptResponse_NoPlaintextEcho(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	originalData := []byte("adversarial plaintext — must not appear in encrypt response")
	plaintext := base64.StdEncoding.EncodeToString(originalData)
	body := fmt.Sprintf(`{"plaintext":%q}`, plaintext)
	w := doRequest(srv, "POST", "/encrypt/test/enc-key", body, token)
	if w.Code != http.StatusOK {
		t.Fatalf("encrypt: %d %s", w.Code, w.Body.String())
	}

	responseBody := w.Body.Bytes()

	// Response must not echo back the raw plaintext.
	if bytes.Contains(responseBody, originalData) {
		t.Fatal("ADVERSARIAL: encrypt response echoes unencrypted plaintext")
	}
	// PEM headers must not appear.
	if strings.Contains(string(responseBody), "-----BEGIN") {
		t.Fatal("ADVERSARIAL: encrypt response contains PEM header")
	}
}

// ── POST /encrypt + POST /decrypt roundtrip ───────────────────────────────────

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	original := []byte("roundtrip test — sensitive payload")
	plaintextB64 := base64.StdEncoding.EncodeToString(original)

	// Encrypt
	encBody := fmt.Sprintf(`{"plaintext":%q}`, plaintextB64)
	wEnc := doRequest(srv, "POST", "/encrypt/test/enc-key", encBody, token)
	if wEnc.Code != http.StatusOK {
		t.Fatalf("encrypt: %d %s", wEnc.Code, wEnc.Body.String())
	}
	var encResp encryptResponse
	if err := json.Unmarshal(wEnc.Body.Bytes(), &encResp); err != nil {
		t.Fatalf("parse encrypt response: %v", err)
	}

	// Decrypt
	decBody := fmt.Sprintf(`{"ciphertext":%q}`, encResp.Ciphertext)
	wDec := doRequest(srv, "POST", "/decrypt/test/enc-key", decBody, token)
	if wDec.Code != http.StatusOK {
		t.Fatalf("decrypt: %d %s", wDec.Code, wDec.Body.String())
	}
	var decResp decryptResponse
	if err := json.Unmarshal(wDec.Body.Bytes(), &decResp); err != nil {
		t.Fatalf("parse decrypt response: %v", err)
	}

	recovered, err := base64.StdEncoding.DecodeString(decResp.Plaintext)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	if string(recovered) != string(original) {
		t.Fatalf("plaintext mismatch: want %q, got %q", original, recovered)
	}
}

// ── GET /keys ─────────────────────────────────────────────────────────────────

func TestHandleListKeys_ReturnsBothKeys(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	w := doRequest(srv, "GET", "/keys", "", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list_keys: %d %s", w.Code, w.Body.String())
	}

	var resp listKeysResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Keys) < 2 {
		t.Fatalf("expected >= 2 keys, got %d", len(resp.Keys))
	}
	// Verify metadata fields are present and sane.
	for _, k := range resp.Keys {
		if k.KeyID == "" {
			t.Error("key_id must not be empty")
		}
		if k.Algorithm == "" {
			t.Error("algorithm must not be empty")
		}
		if k.Version < 1 {
			t.Errorf("key %s: version must be >= 1, got %d", k.KeyID, k.Version)
		}
		if k.CreatedAt == "" {
			t.Error("created_at must not be empty")
		}
	}
}

func TestAdversarial_ListKeys_NoKeyMetadataLeaks(t *testing.T) {
	// Verify the list_keys response is valid JSON with expected structure only.
	// Key-material absence at the backend level is covered by F-08 in dev_test.go.
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	w := doRequest(srv, "GET", "/keys", "", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list_keys: %d %s", w.Code, w.Body.String())
	}

	respStr := w.Body.String()

	// PEM headers must never appear in a metadata listing.
	if strings.Contains(respStr, "-----BEGIN") || strings.Contains(respStr, "-----END") {
		t.Fatal("ADVERSARIAL: list_keys response contains PEM header — possible key material leak")
	}
	// Valid JSON structure.
	var resp listKeysResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("list_keys response is not valid JSON: %v", err)
	}
}

// ── POST /keys (create key) ───────────────────────────────────────────────────

func TestHandleCreateKey_DevMode_Success(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	body := `{"key_id":"new/signing-key","algorithm":"ES256","team_id":"dev-team"}`
	w := doRequest(srv, "POST", "/keys", body, token)
	if w.Code != http.StatusCreated {
		t.Fatalf("create_key: want 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreateKey_MissingKeyID_400(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	body := `{"algorithm":"ES256","team_id":"dev-team"}` // no key_id
	w := doRequest(srv, "POST", "/keys", body, token)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing key_id: want 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreateKey_DuplicateKey_Conflict(t *testing.T) {
	srv, ts, _ := testServer(t)
	token := testToken(t, ts)

	body := `{"key_id":"test/signing-key","algorithm":"ES256","team_id":"dev-team"}` // already exists
	w := doRequest(srv, "POST", "/keys", body, token)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate key: want 409, got %d: %s", w.Code, w.Body.String())
	}
}

// ── Audit logging ─────────────────────────────────────────────────────────────

func TestAuditEvent_SignOperation_LoggedCorrectly(t *testing.T) {
	aB := backend.NewDevBackend()
	_ = aB.CreateKey("audit/key", backend.AlgorithmES256, "dev-team")
	ts, _ := auth.NewTokenStore()
	pf := &policy.PolicyFile{
		Version: 1,
		Rules: []policy.Rule{{
			ID:          "allow-all",
			Identities:  []string{"*"},
			Teams:       []string{"*"},
			Operations:  []string{"*"},
			KeyPrefixes: []string{""},
			Effect:      policy.EffectAllow,
		}},
	}
	cap := &captureAuditor{}
	srv := NewServer(Config{
		Backend:     aB,
		Auditor:     cap,
		Tokens:      ts,
		Policy:      policy.NewEngine(pf),
		Environment: "dev",
	})

	id := &identity.Identity{CallerID: "bert@dev", TeamID: "dev-team"}
	tokenStr, _, _ := ts.Issue(id)

	body := fmt.Sprintf(`{"payload_hash":"%s","algorithm":"ES256"}`, payloadHash("audited"))
	req := httptest.NewRequest("POST", "/sign/audit/key", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("sign: %d %s", w.Code, w.Body.String())
	}
	if len(cap.events) == 0 {
		t.Fatal("no audit events logged")
	}
	ev := cap.events[0]
	if ev.Operation != audit.OperationSign {
		t.Errorf("operation: want %q, got %q", audit.OperationSign, ev.Operation)
	}
	if ev.CallerID != "bert@dev" {
		t.Errorf("caller_id: want %q, got %q", "bert@dev", ev.CallerID)
	}
	if ev.KeyID != "audit/key" {
		t.Errorf("key_id: want %q, got %q", "audit/key", ev.KeyID)
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("outcome: want %q, got %q", audit.OutcomeSuccess, ev.Outcome)
	}
	if ev.PayloadHash == "" {
		t.Error("payload_hash must be recorded in audit event")
	}
	if ev.EventID == "" {
		t.Error("event_id must be set")
	}
	// ADVERSARIAL: audit event must not contain PEM headers or key-like fields.
	evJSON, _ := json.Marshal(ev)
	if bytes.Contains(evJSON, []byte("-----BEGIN")) {
		t.Fatal("ADVERSARIAL: audit event JSON contains PEM header")
	}
}

// TestAuditEvent_EncryptOperation_PayloadHashFormat verifies that the encrypt
// handler writes a properly formatted "sha256:<hex>" payload hash — never the
// raw plaintext — into the audit event.
func TestAuditEvent_EncryptOperation_PayloadHashFormat(t *testing.T) {
	aB := backend.NewDevBackend()
	_ = aB.CreateKey("audit/enc-key", backend.AlgorithmAES256GCM, "dev-team")
	ts, _ := auth.NewTokenStore()
	pf := &policy.PolicyFile{
		Version: 1,
		Rules: []policy.Rule{{
			ID:          "allow-all",
			Identities:  []string{"*"},
			Teams:       []string{"*"},
			Operations:  []string{"*"},
			KeyPrefixes: []string{""},
			Effect:      policy.EffectAllow,
		}},
	}
	cap := &captureAuditor{}
	srv := NewServer(Config{
		Backend:     aB,
		Auditor:     cap,
		Tokens:      ts,
		Policy:      policy.NewEngine(pf),
		Environment: "dev",
	})

	id := &identity.Identity{CallerID: "bert@dev", TeamID: "dev-team"}
	tokenStr, _, _ := ts.Issue(id)

	original := []byte("plaintext that must not appear in audit")
	plaintextB64 := base64.StdEncoding.EncodeToString(original)
	body := fmt.Sprintf(`{"plaintext":%q}`, plaintextB64)
	req := httptest.NewRequest("POST", "/encrypt/audit/enc-key", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("encrypt: %d %s", w.Code, w.Body.String())
	}
	if len(cap.events) == 0 {
		t.Fatal("no audit events logged")
	}
	ev := cap.events[0]
	if ev.Operation != audit.OperationEncrypt {
		t.Errorf("operation: want %q, got %q", audit.OperationEncrypt, ev.Operation)
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("outcome: want %q, got %q", audit.OutcomeSuccess, ev.Outcome)
	}
	// CRITICAL: PayloadHash must use the canonical "sha256:<hex>" format.
	if !strings.HasPrefix(ev.PayloadHash, "sha256:") {
		t.Errorf("REGRESSION: encrypt audit PayloadHash must start with \"sha256:\", got %q", ev.PayloadHash)
	}
	if len(ev.PayloadHash) != len("sha256:")+64 {
		t.Errorf("REGRESSION: encrypt audit PayloadHash length wrong, got %q", ev.PayloadHash)
	}
	// ADVERSARIAL: audit event must not contain the plaintext.
	evJSON, _ := json.Marshal(ev)
	if bytes.Contains(evJSON, original) {
		t.Fatal("ADVERSARIAL: audit event JSON contains plaintext")
	}
}

func TestAuditEvent_DeniedOperation_RecordsDenyReason(t *testing.T) {
	b := backend.NewDevBackend()
	ts, _ := auth.NewTokenStore()
	pf := &policy.PolicyFile{Version: 1, Rules: []policy.Rule{}} // deny all
	cap := &captureAuditor{}
	srv := NewServer(Config{
		Backend:     b,
		Auditor:     cap,
		Tokens:      ts,
		Policy:      policy.NewEngine(pf),
		Environment: "dev",
	})

	id := &identity.Identity{CallerID: "bert@dev", TeamID: "dev-team"}
	tokenStr, _, _ := ts.Issue(id)

	body := fmt.Sprintf(`{"payload_hash":"%s","algorithm":"ES256"}`, payloadHash("x"))
	req := httptest.NewRequest("POST", "/sign/any/key", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	if len(cap.events) == 0 {
		t.Fatal("no audit events logged")
	}
	ev := cap.events[0]
	if ev.Outcome != audit.OutcomeDenied {
		t.Errorf("outcome: want %q, got %q", audit.OutcomeDenied, ev.Outcome)
	}
	if ev.DenyReason == "" {
		t.Error("deny_reason must be non-empty for denied operations")
	}
}
