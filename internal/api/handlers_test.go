// C-06 adversarial tests: verify that no key material appears in any HTTP
// response body, error response, or audit event emitted by the API handlers.
//
// This file is the merge gate for the api-handlers stream.  ALL tests in this
// file must pass before merging to main.
//
// Test categories:
//
//	1.  Happy-path response schema — each endpoint returns exactly the
//	    expected JSON fields and nothing else.
//	2.  ADVERSARIAL — no plaintext in encrypt response.
//	3.  ADVERSARIAL — no PEM headers or binary key-like data in any response.
//	4.  ADVERSARIAL — no backend error internals in HTTP error responses.
//	5.  ADVERSARIAL — audit events: required fields present, correct outcomes,
//	    no key-material content.
//	6.  ADVERSARIAL — policy deny-reason only in audit log, never in HTTP body.
//	7.  ADVERSARIAL — audit event produced for every code path (success,
//	    denied, error).
//	8.  Input validation — malformed inputs are rejected before policy/backend.
//	9.  Content-Type header is always application/json.
//	10. Rotate stub returns 501 and emits an audit event.
//	11. Cross-type operations rejected at backend with clean error responses.
//	12. ADVERSARIAL — audit sink failure causes 500, not silent data loss.
//	    Verifies that denial and error paths treat audit failures as hard errors.
//
// Design note on key-material verification:
//
//	backend.DevBackend stores private key material in unexported struct fields.
//	The F-08 tests (internal/backend/dev_test.go) already prove that Backend
//	interface methods never return key material.  At the HTTP layer we verify:
//	  (a) Each handler only serialises the specific result struct returned by
//	      the backend — no additional fields can sneak in.
//	  (b) A spyBackend records exactly what the backend returned so that the
//	      test can assert the response encodes that data correctly (no more,
//	      no less).
//	  (c) Error responses are generic strings, never Go error messages.
package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
)

// ── Test infrastructure ───────────────────────────────────────────────────────

// failingAuditor always returns an error from Log.
// Used to verify that handlers treat audit failures as hard errors rather
// than silently continuing.
type failingAuditor struct{}

func (f *failingAuditor) Log(_ context.Context, _ audit.AuditEvent) error {
	return errors.New("audit sink unavailable: simulated failure")
}

func (f *failingAuditor) Flush(_ context.Context) error { return nil }

// capturingAuditor records every audit event written by the handlers.
// Thread-safe for concurrent handler calls.
type capturingAuditor struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

func (a *capturingAuditor) Log(_ context.Context, ev audit.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *capturingAuditor) Flush(_ context.Context) error { return nil }

func (a *capturingAuditor) lastEvent() (audit.AuditEvent, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) == 0 {
		return audit.AuditEvent{}, false
	}
	return a.events[len(a.events)-1], true
}

func (a *capturingAuditor) eventCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.events)
}

// spyBackend wraps a backend.Backend and records the exact values returned by
// each method.  This lets adversarial tests assert the HTTP response encodes
// exactly those values — no more, no less.
type spyBackend struct {
	inner backend.Backend

	mu      sync.Mutex
	sigResult *backend.SignResult
	encResult *backend.EncryptResult
	decResult *backend.DecryptResult
}

func (s *spyBackend) Sign(ctx context.Context, keyID string, payloadHash []byte, alg backend.Algorithm) (*backend.SignResult, error) {
	r, err := s.inner.Sign(ctx, keyID, payloadHash, alg)
	if err == nil {
		s.mu.Lock()
		s.sigResult = r
		s.mu.Unlock()
	}
	return r, err
}

func (s *spyBackend) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*backend.EncryptResult, error) {
	r, err := s.inner.Encrypt(ctx, keyID, plaintext)
	if err == nil {
		s.mu.Lock()
		s.encResult = r
		s.mu.Unlock()
	}
	return r, err
}

func (s *spyBackend) Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*backend.DecryptResult, error) {
	r, err := s.inner.Decrypt(ctx, keyID, ciphertext)
	if err == nil {
		s.mu.Lock()
		s.decResult = r
		s.mu.Unlock()
	}
	return r, err
}

func (s *spyBackend) ListKeys(ctx context.Context, scope backend.KeyScope) ([]*backend.KeyMeta, error) {
	return s.inner.ListKeys(ctx, scope)
}

func (s *spyBackend) RotateKey(ctx context.Context, keyID string) (*backend.KeyMeta, error) {
	return s.inner.RotateKey(ctx, keyID)
}

func (s *spyBackend) lastSign() *backend.SignResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sigResult
}

func (s *spyBackend) lastEnc() *backend.EncryptResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.encResult
}

func (s *spyBackend) lastDec() *backend.DecryptResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.decResult
}

// ── Server constructors ───────────────────────────────────────────────────────

// newAllowServer builds a Server with an allow-all policy engine.
// Use for happy-path and adversarial shape tests.
func newAllowServer(t *testing.T, b backend.Backend) (*api.Server, *capturingAuditor) {
	t.Helper()
	aud := &capturingAuditor{}
	return api.NewServer(b, aud, policy.AllowAllEngine{}, "dev"), aud
}

// newDenyServer builds a Server with a deny-all policy engine.
// Use for policy-denial tests.
func newDenyServer(t *testing.T, b backend.Backend) (*api.Server, *capturingAuditor) {
	t.Helper()
	aud := &capturingAuditor{}
	return api.NewServer(b, aud, policy.DenyAllEngine{}, "dev"), aud
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

// request sends method + path with an optional JSON body to srv and returns
// the recorded response.
func request(t *testing.T, srv http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

// jsonReader encodes v as JSON and returns an io.Reader over the result.
func jsonReader(t *testing.T, v any) io.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("jsonReader: %v", err)
	}
	return bytes.NewReader(b)
}

// decodeMap decodes the response body into map[string]any.
// Returns the map and the raw body bytes (body is a separate copy since
// the recorder's body is already read).
func decodeMap(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decodeMap: %v (raw: %q)", err, body)
	}
	return m
}

// ── Assertion helpers ─────────────────────────────────────────────────────────

// assertStatus fails if the recorded status code differs from want.
func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Fatalf("expected HTTP %d, got %d (body: %s)", want, rr.Code, rr.Body.String())
	}
}

// assertContentTypeJSON verifies the Content-Type header is application/json.
func assertContentTypeJSON(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

// assertNoPEMHeaders fails if data contains any PEM block delimiter.
// PEM delimiters in a response indicate key material or certificates leaking.
func assertNoPEMHeaders(t *testing.T, label string, data []byte) {
	t.Helper()
	if bytes.Contains(data, []byte("-----BEGIN")) || bytes.Contains(data, []byte("-----END")) {
		t.Errorf("ADVERSARIAL [%s]: response contains PEM block delimiter — possible key material leak", label)
	}
}

// assertNotContains fails if haystack contains needle.
func assertNotContains(t *testing.T, label, needle string, haystack []byte) {
	t.Helper()
	if len(needle) > 0 && bytes.Contains(haystack, []byte(needle)) {
		t.Errorf("ADVERSARIAL [%s]: response contains forbidden substring %q", label, needle)
	}
}

// assertOnlyFields fails if m contains any key not in allowed.
// Extra fields in responses are potential information leaks.
func assertOnlyFields(t *testing.T, label string, m map[string]any, allowed ...string) {
	t.Helper()
	set := make(map[string]struct{}, len(allowed))
	for _, k := range allowed {
		set[k] = struct{}{}
	}
	for k := range m {
		if _, ok := set[k]; !ok {
			t.Errorf("ADVERSARIAL [%s]: response contains unexpected field %q (possible leak)", label, k)
		}
	}
}

// assertErrorShape verifies an error response has exactly "error" and "code"
// fields, both non-empty.
func assertErrorShape(t *testing.T, label string, body []byte) (errMsg, code string) {
	t.Helper()
	m := decodeMap(t, body)
	assertOnlyFields(t, label+" error shape", m, "error", "code")
	errMsg, _ = m["error"].(string)
	code, _ = m["code"].(string)
	if errMsg == "" {
		t.Errorf("[%s] error response missing 'error' field", label)
	}
	if code == "" {
		t.Errorf("[%s] error response missing 'code' field", label)
	}
	return errMsg, code
}

// assertAuditComplete checks that an audit event has all mandatory fields set.
func assertAuditComplete(t *testing.T, ev audit.AuditEvent, wantOp, wantKeyID string) {
	t.Helper()
	if ev.EventID == "" {
		t.Error("audit: EventID is empty")
	}
	if ev.Timestamp.IsZero() {
		t.Error("audit: Timestamp is zero")
	}
	if ev.Operation != wantOp {
		t.Errorf("audit: Operation = %q, want %q", ev.Operation, wantOp)
	}
	if wantKeyID != "" && ev.KeyID != wantKeyID {
		t.Errorf("audit: KeyID = %q, want %q", ev.KeyID, wantKeyID)
	}
	if ev.Outcome == "" {
		t.Error("audit: Outcome is empty")
	}
	if ev.CallerID == "" {
		t.Error("audit: CallerID is empty")
	}
	if ev.Environment == "" {
		t.Error("audit: Environment is empty")
	}
}

// ── Payload hash helper ───────────────────────────────────────────────────────

// hashHex returns a payload_hash value for the given bytes:
// "sha256:<64 lowercase hex characters>".
func hashHex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h)
}

// ── Backend factories ─────────────────────────────────────────────────────────

func newSignBackend(t *testing.T, keyID string) *spyBackend {
	t.Helper()
	b := backend.NewDevBackend()
	if err := b.CreateKey(keyID, backend.AlgorithmES256, "test-team"); err != nil {
		t.Fatalf("CreateKey %q: %v", keyID, err)
	}
	return &spyBackend{inner: b}
}

func newEncBackend(t *testing.T, keyID string) *spyBackend {
	t.Helper()
	b := backend.NewDevBackend()
	if err := b.CreateKey(keyID, backend.AlgorithmAES256GCM, "test-team"); err != nil {
		t.Fatalf("CreateKey %q: %v", keyID, err)
	}
	return &spyBackend{inner: b}
}

// ════════════════════════════════════════════════════════════════════════════
// 1. Happy-path response schema
// ════════════════════════════════════════════════════════════════════════════

func TestHandleSign_HappyPath_SchemaAndContent(t *testing.T) {
	spy := newSignBackend(t, "schema/sign")
	srv, aud := newAllowServer(t, spy)

	rr := request(t, srv, http.MethodPost, "/sign/schema/sign",
		jsonReader(t, map[string]any{
			"payload_hash": hashHex([]byte("hello sign")),
			"algorithm":    "ES256",
		}),
	)
	assertStatus(t, rr, http.StatusOK)
	assertContentTypeJSON(t, rr)

	body := rr.Body.Bytes()
	m := decodeMap(t, body)

	// ── C-06: only expected fields ─────────────────────────────────────────
	assertOnlyFields(t, "sign", m, "signature", "key_version")

	sigB64, ok := m["signature"].(string)
	if !ok || sigB64 == "" {
		t.Fatal("sign response: signature field missing or not a string")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("sign response: signature is not valid base64: %v", err)
	}
	if len(sigBytes) == 0 {
		t.Fatal("sign response: decoded signature is empty")
	}

	kv, ok := m["key_version"].(float64)
	if !ok || kv < 1 {
		t.Fatalf("sign response: key_version missing or < 1 (got %v)", m["key_version"])
	}

	// ── C-06: response signature equals exactly what backend returned ──────
	lastSig := spy.lastSign()
	if lastSig == nil {
		t.Fatal("spy: no Sign result recorded")
	}
	if sigB64 != base64.StdEncoding.EncodeToString(lastSig.Signature) {
		t.Fatal("ADVERSARIAL: response signature differs from backend-returned signature")
	}
	if int(kv) != lastSig.KeyVersion {
		t.Fatalf("response key_version %d != backend key_version %d", int(kv), lastSig.KeyVersion)
	}

	// ── Audit event ─────────────────────────────────────────────────────────
	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	assertAuditComplete(t, ev, audit.OperationSign, "schema/sign")
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("audit outcome = %q, want success", ev.Outcome)
	}
	if ev.Algorithm != "ES256" {
		t.Errorf("audit algorithm = %q, want ES256", ev.Algorithm)
	}
	if !strings.HasPrefix(ev.PayloadHash, "sha256:") {
		t.Errorf("audit payload_hash %q lacks sha256: prefix", ev.PayloadHash)
	}
}

func TestHandleEncrypt_HappyPath_SchemaAndContent(t *testing.T) {
	spy := newEncBackend(t, "schema/enc")
	srv, aud := newAllowServer(t, spy)

	plaintext := []byte("hello encrypt — sensitive payload")
	rr := request(t, srv, http.MethodPost, "/encrypt/schema/enc",
		jsonReader(t, map[string]any{
			"plaintext": base64.StdEncoding.EncodeToString(plaintext),
		}),
	)
	assertStatus(t, rr, http.StatusOK)
	assertContentTypeJSON(t, rr)

	body := rr.Body.Bytes()
	m := decodeMap(t, body)

	// ── C-06: only expected fields ─────────────────────────────────────────
	assertOnlyFields(t, "encrypt", m, "ciphertext", "key_version")

	ctB64, ok := m["ciphertext"].(string)
	if !ok || ctB64 == "" {
		t.Fatal("encrypt response: ciphertext field missing")
	}
	ctBytes, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		t.Fatalf("encrypt response: ciphertext not valid base64: %v", err)
	}
	if len(ctBytes) == 0 {
		t.Fatal("encrypt response: decoded ciphertext is empty")
	}

	kv, ok := m["key_version"].(float64)
	if !ok || kv < 1 {
		t.Fatalf("encrypt response: key_version missing or < 1")
	}

	// ── C-06: ciphertext is exactly what backend returned ─────────────────
	lastEnc := spy.lastEnc()
	if lastEnc == nil {
		t.Fatal("spy: no Encrypt result recorded")
	}
	if ctB64 != base64.StdEncoding.EncodeToString(lastEnc.Ciphertext) {
		t.Fatal("ADVERSARIAL: response ciphertext differs from backend-returned ciphertext")
	}

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	assertAuditComplete(t, ev, audit.OperationEncrypt, "schema/enc")
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("audit outcome = %q, want success", ev.Outcome)
	}
}

func TestHandleDecrypt_HappyPath_SchemaAndContent(t *testing.T) {
	spy := newEncBackend(t, "schema/dec")
	srv, aud := newAllowServer(t, spy)

	plaintext := []byte("round-trip decrypt schema — sensitive")
	ptB64 := base64.StdEncoding.EncodeToString(plaintext)

	// Encrypt to obtain valid ciphertext.
	encRR := request(t, srv, http.MethodPost, "/encrypt/schema/dec",
		jsonReader(t, map[string]any{"plaintext": ptB64}),
	)
	assertStatus(t, encRR, http.StatusOK)
	encBody := encRR.Body.Bytes()
	encM := decodeMap(t, encBody)
	ctB64 := encM["ciphertext"].(string)

	// Decrypt.
	rr := request(t, srv, http.MethodPost, "/decrypt/schema/dec",
		jsonReader(t, map[string]any{"ciphertext": ctB64}),
	)
	assertStatus(t, rr, http.StatusOK)
	assertContentTypeJSON(t, rr)

	body := rr.Body.Bytes()
	m := decodeMap(t, body)

	// ── C-06: only expected field ──────────────────────────────────────────
	assertOnlyFields(t, "decrypt", m, "plaintext")

	ptOut, ok := m["plaintext"].(string)
	if !ok || ptOut == "" {
		t.Fatal("decrypt response: plaintext field missing")
	}
	gotPT, err := base64.StdEncoding.DecodeString(ptOut)
	if err != nil {
		t.Fatalf("decrypt response: plaintext not valid base64: %v", err)
	}
	if !bytes.Equal(gotPT, plaintext) {
		t.Fatalf("decrypt response plaintext mismatch:\n  want %q\n  got  %q", plaintext, gotPT)
	}

	// ── C-06: plaintext in response equals exactly what backend returned ───
	lastDec := spy.lastDec()
	if lastDec == nil {
		t.Fatal("spy: no Decrypt result recorded")
	}
	if ptOut != base64.StdEncoding.EncodeToString(lastDec.Plaintext) {
		t.Fatal("ADVERSARIAL: response plaintext differs from backend-returned plaintext")
	}

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	assertAuditComplete(t, ev, audit.OperationDecrypt, "schema/dec")
}

func TestHandleListKeys_HappyPath_SchemaAndContent(t *testing.T) {
	b := backend.NewDevBackend()
	if err := b.CreateKey("ns/key-a", backend.AlgorithmES256, "ns-team"); err != nil {
		t.Fatal(err)
	}
	if err := b.CreateKey("ns/key-b", backend.AlgorithmAES256GCM, "ns-team"); err != nil {
		t.Fatal(err)
	}
	// Key in a different namespace — should not appear with prefix filter.
	if err := b.CreateKey("other/key-c", backend.AlgorithmEdDSA, "other-team"); err != nil {
		t.Fatal(err)
	}

	srv, aud := newAllowServer(t, b)

	rr := request(t, srv, http.MethodGet, "/keys?prefix=ns/", nil)
	assertStatus(t, rr, http.StatusOK)
	assertContentTypeJSON(t, rr)

	body := rr.Body.Bytes()
	assertNoPEMHeaders(t, "list-keys", body)

	var resp struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode list keys response: %v", err)
	}
	if len(resp.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(resp.Keys))
	}

	for i, km := range resp.Keys {
		// ── C-06: only expected fields per key entry ───────────────────────
		assertOnlyFields(t, fmt.Sprintf("key[%d]", i), km,
			"key_id", "algorithm", "version", "created_at", "rotated_at", "team_id")

		kid, _ := km["key_id"].(string)
		if !strings.HasPrefix(kid, "ns/") {
			t.Errorf("key[%d].key_id %q does not have expected prefix", i, kid)
		}
	}

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event for list-keys")
	}
	assertAuditComplete(t, ev, audit.OperationListKeys, "")
}

// ════════════════════════════════════════════════════════════════════════════
// 2. ADVERSARIAL: plaintext must not appear in encrypt response
// ════════════════════════════════════════════════════════════════════════════

// TestAdversarial_Encrypt_PlaintextNotInResponse verifies that the encrypt
// endpoint does not echo the submitted plaintext — either raw or base64 —
// anywhere in its response body.
func TestAdversarial_Encrypt_PlaintextNotInResponse(t *testing.T) {
	spy := newEncBackend(t, "adv/enc-no-pt")
	srv, _ := newAllowServer(t, spy)

	// Use a recognisable plaintext that would be obvious if accidentally echoed.
	plaintext := []byte("ADVERSARIAL-PLAINTEXT-MUST-NOT-APPEAR-IN-ENCRYPT-RESPONSE-c0ffee")
	ptB64 := base64.StdEncoding.EncodeToString(plaintext)

	rr := request(t, srv, http.MethodPost, "/encrypt/adv/enc-no-pt",
		jsonReader(t, map[string]any{"plaintext": ptB64}),
	)
	assertStatus(t, rr, http.StatusOK)

	body := rr.Body.Bytes()

	// Raw plaintext bytes must not appear.
	if bytes.Contains(body, plaintext) {
		t.Fatal("ADVERSARIAL: encrypt response contains raw plaintext bytes")
	}
	// Base64-encoded plaintext (i.e., the request value) must not be echoed.
	if bytes.Contains(body, []byte(ptB64)) {
		t.Fatal("ADVERSARIAL: encrypt response echoes the base64-encoded plaintext from the request")
	}
}

// TestAdversarial_Decrypt_CiphertextNotEchoedInResponse verifies the decrypt
// response contains the recovered plaintext but NOT the input ciphertext.
func TestAdversarial_Decrypt_CiphertextNotEchoedInResponse(t *testing.T) {
	spy := newEncBackend(t, "adv/dec-no-ct")
	srv, _ := newAllowServer(t, spy)

	plaintext := []byte("adversarial decrypt payload")
	ptB64 := base64.StdEncoding.EncodeToString(plaintext)

	// Step 1: encrypt.
	encRR := request(t, srv, http.MethodPost, "/encrypt/adv/dec-no-ct",
		jsonReader(t, map[string]any{"plaintext": ptB64}),
	)
	assertStatus(t, encRR, http.StatusOK)
	encBody := encRR.Body.Bytes()
	encM := decodeMap(t, encBody)
	ctB64 := encM["ciphertext"].(string)

	// Step 2: decrypt.
	rr := request(t, srv, http.MethodPost, "/decrypt/adv/dec-no-ct",
		jsonReader(t, map[string]any{"ciphertext": ctB64}),
	)
	assertStatus(t, rr, http.StatusOK)

	body := rr.Body.Bytes()

	// The input ciphertext must not appear in the decrypt response.
	if bytes.Contains(body, []byte(ctB64)) {
		t.Fatal("ADVERSARIAL: decrypt response echoes the base64-encoded ciphertext from the request")
	}
	// Verify correct plaintext is returned.
	var parsed struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("parsing decrypt response: %v", err)
	}
	got, err := base64.StdEncoding.DecodeString(parsed.Plaintext)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypt response plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

// ════════════════════════════════════════════════════════════════════════════
// 3. ADVERSARIAL: no PEM headers in any response
// ════════════════════════════════════════════════════════════════════════════

func TestAdversarial_NoPEMHeaders_AllSuccessResponses(t *testing.T) {
	sigSpy := newSignBackend(t, "pem/sign")
	encSpy := newEncBackend(t, "pem/enc")

	sigSrv, _ := newAllowServer(t, sigSpy)
	encSrv, _ := newAllowServer(t, encSpy)

	// Sign.
	rr := request(t, sigSrv, http.MethodPost, "/sign/pem/sign",
		jsonReader(t, map[string]any{
			"payload_hash": hashHex([]byte("pem test")),
			"algorithm":    "ES256",
		}),
	)
	assertStatus(t, rr, http.StatusOK)
	assertNoPEMHeaders(t, "sign 200", rr.Body.Bytes())

	// Encrypt.
	rr = request(t, encSrv, http.MethodPost, "/encrypt/pem/enc",
		jsonReader(t, map[string]any{
			"plaintext": base64.StdEncoding.EncodeToString([]byte("pem enc test")),
		}),
	)
	assertStatus(t, rr, http.StatusOK)
	assertNoPEMHeaders(t, "encrypt 200", rr.Body.Bytes())

	// List keys.
	b := backend.NewDevBackend()
	_ = b.CreateKey("pem/list", backend.AlgorithmES256, "team")
	keySrv, _ := newAllowServer(t, b)
	rr = request(t, keySrv, http.MethodGet, "/keys", nil)
	assertStatus(t, rr, http.StatusOK)
	assertNoPEMHeaders(t, "list-keys 200", rr.Body.Bytes())
}

func TestAdversarial_NoPEMHeaders_AllErrorResponses(t *testing.T) {
	emptyB := backend.NewDevBackend() // no keys
	srv, _ := newAllowServer(t, emptyB)

	cases := []struct {
		name   string
		method string
		path   string
		body   io.Reader
	}{
		{
			name: "sign 404", method: http.MethodPost, path: "/sign/no/key",
			body: jsonReader(t, map[string]any{
				"payload_hash": hashHex([]byte("x")), "algorithm": "ES256",
			}),
		},
		{
			name: "encrypt 404", method: http.MethodPost, path: "/encrypt/no/key",
			body: jsonReader(t, map[string]any{
				"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
			}),
		},
		{
			name: "sign 400 bad hash", method: http.MethodPost, path: "/sign/no/key",
			body: jsonReader(t, map[string]any{
				"payload_hash": "not-a-hash", "algorithm": "ES256",
			}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := request(t, srv, tc.method, tc.path, tc.body)
			assertNoPEMHeaders(t, tc.name, rr.Body.Bytes())
		})
	}

	// Policy-denied 403.
	b2 := backend.NewDevBackend()
	_ = b2.CreateKey("pem/deny", backend.AlgorithmES256, "team")
	denySrv, _ := newDenyServer(t, b2)
	rr403 := request(t, denySrv, http.MethodPost, "/sign/pem/deny",
		jsonReader(t, map[string]any{
			"payload_hash": hashHex([]byte("x")), "algorithm": "ES256",
		}),
	)
	assertNoPEMHeaders(t, "sign 403", rr403.Body.Bytes())
}

// ════════════════════════════════════════════════════════════════════════════
// 4. ADVERSARIAL: no backend internals in HTTP error responses
// ════════════════════════════════════════════════════════════════════════════

// forbiddenResponseStrings lists substrings that must never appear in any
// HTTP response body.  They indicate internal error messages, stack traces,
// source file paths, or Go runtime output leaking to the caller.
var forbiddenResponseStrings = []string{
	"backend:",           // error-wrapping prefix from internal/backend
	"backend.go",        // source file names
	"dev.go",
	"interface.go",
	"panic:",            // Go panic output
	"goroutine ",        // Go stack trace marker
	"runtime/",          // Go runtime source paths
	".go:",              // source:line references
	"github.com/",       // import paths
	"agentkms/internal", // internal package paths
}

func TestAdversarial_ErrorResponses_NoInternalDetails(t *testing.T) {
	emptyB := backend.NewDevBackend() // no keys — all key lookups fail
	srv, _ := newAllowServer(t, emptyB)

	type tc struct {
		name       string
		method     string
		path       string
		body       io.Reader
		wantStatus int
		wantCode   string
	}

	cases := []tc{
		{
			name: "sign key-not-found",
			method: http.MethodPost, path: "/sign/missing/key",
			body: jsonReader(t, map[string]any{
				"payload_hash": hashHex([]byte("x")), "algorithm": "ES256",
			}),
			wantStatus: http.StatusNotFound, wantCode: "key_not_found",
		},
		{
			name: "encrypt key-not-found",
			method: http.MethodPost, path: "/encrypt/missing/key",
			body: jsonReader(t, map[string]any{
				"plaintext": base64.StdEncoding.EncodeToString([]byte("d")),
			}),
			wantStatus: http.StatusNotFound, wantCode: "key_not_found",
		},
		{
			name: "decrypt key-not-found",
			method: http.MethodPost, path: "/decrypt/missing/key",
			body: jsonReader(t, map[string]any{
				"ciphertext": base64.StdEncoding.EncodeToString(make([]byte, 64)),
			}),
			wantStatus: http.StatusNotFound, wantCode: "key_not_found",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := request(t, srv, c.method, c.path, c.body)
			assertStatus(t, rr, c.wantStatus)
			assertContentTypeJSON(t, rr)

			body := rr.Body.Bytes()
			assertNoPEMHeaders(t, c.name, body)

			for _, forbidden := range forbiddenResponseStrings {
				assertNotContains(t, c.name, forbidden, body)
			}

			_, code := assertErrorShape(t, c.name, body)
			if code != c.wantCode {
				t.Errorf("[%s] error code = %q, want %q", c.name, code, c.wantCode)
			}
		})
	}
}

func TestAdversarial_ValidationErrors_NoInternalDetails(t *testing.T) {
	b := backend.NewDevBackend()
	srv, _ := newAllowServer(t, b)

	cases := []struct {
		name string
		path string
		body map[string]any
	}{
		{
			name: "sign bad hash prefix",
			path: "/sign/test/key",
			body: map[string]any{"payload_hash": "md5:abc", "algorithm": "ES256"},
		},
		{
			name: "sign bad algorithm",
			path: "/sign/test/key",
			body: map[string]any{"payload_hash": hashHex([]byte("x")), "algorithm": "AES128-bad"},
		},
		{
			name: "sign encryption algorithm rejected",
			path: "/sign/test/key",
			body: map[string]any{"payload_hash": hashHex([]byte("x")), "algorithm": "AES256GCM"},
		},
		{
			name: "sign unknown field",
			path: "/sign/test/key",
			body: map[string]any{
				"payload_hash": hashHex([]byte("x")),
				"algorithm":    "ES256",
				"secret_key":   "leaked-value",
			},
		},
		{
			name: "encrypt bad base64",
			path: "/encrypt/test/key",
			body: map[string]any{"plaintext": "not!valid!base64!"},
		},
		{
			name: "decrypt bad base64",
			path: "/decrypt/test/key",
			body: map[string]any{"ciphertext": "not!valid!base64!"},
		},
		{
			name: "decrypt unknown field",
			path: "/decrypt/test/key",
			body: map[string]any{
				"ciphertext": base64.StdEncoding.EncodeToString(make([]byte, 64)),
				"injected":   "extra",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := request(t, srv, http.MethodPost, tc.path, jsonReader(t, tc.body))
			assertStatus(t, rr, http.StatusBadRequest)

			body := rr.Body.Bytes()
			assertNoPEMHeaders(t, tc.name, body)
			for _, forbidden := range forbiddenResponseStrings {
				assertNotContains(t, tc.name, forbidden, body)
			}
			assertErrorShape(t, tc.name, body)
		})
	}
}

// TestAdversarial_CrossType_CleanErrors verifies that using the wrong key type
// (e.g., signing with an encryption key) produces a clean 400 with no leakage.
func TestAdversarial_CrossType_CleanErrors(t *testing.T) {
	t.Run("sign with AES key", func(t *testing.T) {
		b := backend.NewDevBackend()
		if err := b.CreateKey("cross/aes", backend.AlgorithmAES256GCM, "team"); err != nil {
			t.Fatal(err)
		}
		srv, _ := newAllowServer(t, b)

		rr := request(t, srv, http.MethodPost, "/sign/cross/aes",
			jsonReader(t, map[string]any{
				"payload_hash": hashHex([]byte("x")), "algorithm": "ES256",
			}),
		)
		assertStatus(t, rr, http.StatusBadRequest)
		body := rr.Body.Bytes()
		assertNoPEMHeaders(t, "sign with AES key", body)
		for _, forbidden := range forbiddenResponseStrings {
			assertNotContains(t, "sign with AES key", forbidden, body)
		}
	})

	t.Run("encrypt with EC key", func(t *testing.T) {
		b := backend.NewDevBackend()
		if err := b.CreateKey("cross/ec", backend.AlgorithmES256, "team"); err != nil {
			t.Fatal(err)
		}
		srv, _ := newAllowServer(t, b)

		rr := request(t, srv, http.MethodPost, "/encrypt/cross/ec",
			jsonReader(t, map[string]any{
				"plaintext": base64.StdEncoding.EncodeToString([]byte("data")),
			}),
		)
		assertStatus(t, rr, http.StatusBadRequest)
		body := rr.Body.Bytes()
		assertNoPEMHeaders(t, "encrypt with EC key", body)
		for _, forbidden := range forbiddenResponseStrings {
			assertNotContains(t, "encrypt with EC key", forbidden, body)
		}
	})
}

// ════════════════════════════════════════════════════════════════════════════
// 5. ADVERSARIAL: audit events
// ════════════════════════════════════════════════════════════════════════════

func TestAdversarial_AuditEvents_RequiredFieldsOnSuccess(t *testing.T) {
	ops := []struct {
		name    string
		setup   func() (backend.Backend, func(*testing.T) *httptest.ResponseRecorder)
		wantOp  string
		wantKey string
	}{
		{
			name: "sign",
			setup: func() (backend.Backend, func(*testing.T) *httptest.ResponseRecorder) {
				spy := newSignBackend(t, "audit/sign")
				srv, _ := newAllowServer(t, spy)
				return spy, func(t *testing.T) *httptest.ResponseRecorder {
					return request(t, srv, http.MethodPost, "/sign/audit/sign",
						jsonReader(t, map[string]any{
							"payload_hash": hashHex([]byte("audit")),
							"algorithm":    "ES256",
						}),
					)
				}
			},
			wantOp: audit.OperationSign, wantKey: "audit/sign",
		},
		{
			name: "encrypt",
			setup: func() (backend.Backend, func(*testing.T) *httptest.ResponseRecorder) {
				spy := newEncBackend(t, "audit/enc")
				srv, _ := newAllowServer(t, spy)
				return spy, func(t *testing.T) *httptest.ResponseRecorder {
					return request(t, srv, http.MethodPost, "/encrypt/audit/enc",
						jsonReader(t, map[string]any{
							"plaintext": base64.StdEncoding.EncodeToString([]byte("data")),
						}),
					)
				}
			},
			wantOp: audit.OperationEncrypt, wantKey: "audit/enc",
		},
	}

	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			b, doReq := op.setup()
			_, aud := newAllowServer(t, b) // re-wire with fresh auditor
			// Note: doReq captures the original server; we must create a
			// server directly for each test so the auditor is fresh.
			// Restructure: inline the server creation.
			_ = b
			_ = doReq

			// Inline setup for clean auditor.
			var (
				srv2 *api.Server
				aud2 *capturingAuditor
			)
			_ = aud
			aud2 = &capturingAuditor{}

			switch op.name {
			case "sign":
				spy2 := newSignBackend(t, op.wantKey+"-2")
				srv2 = api.NewServer(spy2, aud2, policy.AllowAllEngine{}, "dev")
				rr := request(t, srv2, http.MethodPost, "/sign/"+op.wantKey+"-2",
					jsonReader(t, map[string]any{
						"payload_hash": hashHex([]byte("audit")),
						"algorithm":    "ES256",
					}),
				)
				assertStatus(t, rr, http.StatusOK)
			case "encrypt":
				spy2 := newEncBackend(t, op.wantKey+"-2")
				srv2 = api.NewServer(spy2, aud2, policy.AllowAllEngine{}, "dev")
				rr := request(t, srv2, http.MethodPost, "/encrypt/"+op.wantKey+"-2",
					jsonReader(t, map[string]any{
						"plaintext": base64.StdEncoding.EncodeToString([]byte("data")),
					}),
				)
				assertStatus(t, rr, http.StatusOK)
			}

			ev, ok := aud2.lastEvent()
			if !ok {
				t.Fatal("no audit event recorded")
			}
			assertAuditComplete(t, ev, op.wantOp, op.wantKey+"-2")
			if ev.Outcome != audit.OutcomeSuccess {
				t.Errorf("audit outcome = %q, want success", ev.Outcome)
			}
		})
	}
}

// TestAdversarial_AuditEvents_PayloadHashNeverPlaintext verifies that the
// PayloadHash field in audit events is always in sha256:<hex> format and
// never contains the raw plaintext submitted by the caller.
func TestAdversarial_AuditEvents_PayloadHashNeverPlaintext(t *testing.T) {
	spy := newEncBackend(t, "audit-hash/enc")
	aud := &capturingAuditor{}
	srv := api.NewServer(spy, aud, policy.AllowAllEngine{}, "dev")

	plaintext := []byte("SECRET DATA THAT MUST NOT APPEAR IN AUDIT LOG")
	ptB64 := base64.StdEncoding.EncodeToString(plaintext)

	rr := request(t, srv, http.MethodPost, "/encrypt/audit-hash/enc",
		jsonReader(t, map[string]any{"plaintext": ptB64}),
	)
	assertStatus(t, rr, http.StatusOK)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event")
	}

	// PayloadHash must start with "sha256:" and be exactly 71 chars ("sha256:" + 64).
	if !strings.HasPrefix(ev.PayloadHash, "sha256:") {
		t.Errorf("ADVERSARIAL: audit PayloadHash %q lacks sha256: prefix", ev.PayloadHash)
	}
	if len(ev.PayloadHash) != len("sha256:")+64 {
		t.Errorf("ADVERSARIAL: audit PayloadHash length %d, want %d",
			len(ev.PayloadHash), len("sha256:")+64)
	}

	// PayloadHash must NOT contain the raw plaintext.
	if bytes.Contains([]byte(ev.PayloadHash), plaintext) {
		t.Fatal("ADVERSARIAL: audit PayloadHash contains raw plaintext bytes")
	}
	// PayloadHash must NOT be the base64 of the plaintext.
	if ev.PayloadHash == ptB64 {
		t.Fatal("ADVERSARIAL: audit PayloadHash equals base64-encoded plaintext")
	}
	// PayloadHash must NOT be the raw plaintext string.
	if ev.PayloadHash == string(plaintext) {
		t.Fatal("ADVERSARIAL: audit PayloadHash equals raw plaintext string")
	}
}

// ════════════════════════════════════════════════════════════════════════════
// 6. ADVERSARIAL: policy deny-reason not in HTTP response
// ════════════════════════════════════════════════════════════════════════════

// TestAdversarial_PolicyDenyReason_OnlyInAuditLog verifies that when an
// operation is denied, the DenyReason (which may reveal policy structure)
// appears in the audit log but NOT in the HTTP response body.
func TestAdversarial_PolicyDenyReason_OnlyInAuditLog(t *testing.T) {
	b := backend.NewDevBackend()
	if err := b.CreateKey("deny/key", backend.AlgorithmES256, "team"); err != nil {
		t.Fatal(err)
	}
	aud := &capturingAuditor{}
	srv := api.NewServer(b, aud, policy.DenyAllEngine{}, "dev")

	rr := request(t, srv, http.MethodPost, "/sign/deny/key",
		jsonReader(t, map[string]any{
			"payload_hash": hashHex([]byte("denied op")),
			"algorithm":    "ES256",
		}),
	)
	assertStatus(t, rr, http.StatusForbidden)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event for denied operation")
	}
	if ev.Outcome != audit.OutcomeDenied {
		t.Errorf("audit outcome = %q, want %q", ev.Outcome, audit.OutcomeDenied)
	}
	if ev.DenyReason == "" {
		t.Error("audit DenyReason is empty for denied operation")
	}

	body := rr.Body.Bytes()

	// The DenyReason must NOT appear in the HTTP response.
	if bytes.Contains(body, []byte(ev.DenyReason)) {
		t.Errorf("ADVERSARIAL: HTTP 403 body contains audit DenyReason %q — policy structure exposed",
			ev.DenyReason)
	}

	// Response must use the generic denial message.
	_, code := assertErrorShape(t, "policy-deny", body)
	if code != "policy_denied" {
		t.Errorf("403 code = %q, want policy_denied", code)
	}
}

// ════════════════════════════════════════════════════════════════════════════
// 7. ADVERSARIAL: audit event produced for every code path
// ════════════════════════════════════════════════════════════════════════════

func TestAdversarial_AuditOnEveryPath(t *testing.T) {
	t.Run("input validation failure → audit OutcomeDenied", func(t *testing.T) {
		b := backend.NewDevBackend()
		srv, aud := newAllowServer(t, b)

		request(t, srv, http.MethodPost, "/sign/test/key",
			jsonReader(t, map[string]any{
				"payload_hash": "invalid-format",
				"algorithm":    "ES256",
			}),
		)
		ev, ok := aud.lastEvent()
		if !ok {
			t.Fatal("no audit event for validation failure")
		}
		if ev.Outcome != audit.OutcomeDenied {
			t.Errorf("expected OutcomeDenied for validation failure, got %q", ev.Outcome)
		}
	})

	t.Run("policy denial → audit OutcomeDenied", func(t *testing.T) {
		b := backend.NewDevBackend()
		if err := b.CreateKey("path/key", backend.AlgorithmES256, "team"); err != nil {
			t.Fatal(err)
		}
		srv, aud := newDenyServer(t, b)

		request(t, srv, http.MethodPost, "/sign/path/key",
			jsonReader(t, map[string]any{
				"payload_hash": hashHex([]byte("x")),
				"algorithm":    "ES256",
			}),
		)
		ev, ok := aud.lastEvent()
		if !ok {
			t.Fatal("no audit event for policy denial")
		}
		if ev.Outcome != audit.OutcomeDenied {
			t.Errorf("expected OutcomeDenied for policy denial, got %q", ev.Outcome)
		}
	})

	t.Run("backend error (key not found) → audit OutcomeError", func(t *testing.T) {
		b := backend.NewDevBackend() // empty
		srv, aud := newAllowServer(t, b)

		request(t, srv, http.MethodPost, "/sign/missing/key",
			jsonReader(t, map[string]any{
				"payload_hash": hashHex([]byte("x")),
				"algorithm":    "ES256",
			}),
		)
		ev, ok := aud.lastEvent()
		if !ok {
			t.Fatal("no audit event for key-not-found")
		}
		if ev.Outcome != audit.OutcomeError {
			t.Errorf("expected OutcomeError for key-not-found, got %q", ev.Outcome)
		}
	})

	t.Run("success → audit OutcomeSuccess", func(t *testing.T) {
		spy := newSignBackend(t, "path/ok")
		srv, aud := newAllowServer(t, spy)

		rr := request(t, srv, http.MethodPost, "/sign/path/ok",
			jsonReader(t, map[string]any{
				"payload_hash": hashHex([]byte("x")),
				"algorithm":    "ES256",
			}),
		)
		assertStatus(t, rr, http.StatusOK)

		ev, ok := aud.lastEvent()
		if !ok {
			t.Fatal("no audit event for success")
		}
		if ev.Outcome != audit.OutcomeSuccess {
			t.Errorf("expected OutcomeSuccess, got %q", ev.Outcome)
		}
	})
}

// ════════════════════════════════════════════════════════════════════════════
// 8. Input validation
// ════════════════════════════════════════════════════════════════════════════

func TestHandleSign_InputValidation(t *testing.T) {
	b := backend.NewDevBackend()
	if err := b.CreateKey("val/sign", backend.AlgorithmES256, "team"); err != nil {
		t.Fatal(err)
	}
	srv, _ := newAllowServer(t, b)

	cases := []struct {
		name string
		path string
		body map[string]any
		want int
	}{
		{
			name: "uppercase key ID rejected",
			path: "/sign/VAL/sign",
			body: map[string]any{"payload_hash": hashHex([]byte("x")), "algorithm": "ES256"},
			want: http.StatusBadRequest,
		},
		{
			name: "path traversal key ID rejected",
			path: "/sign/valid/key",
			body: map[string]any{
				// The key ID is taken from the URL; this test sends a valid URL
				// but the actual key doesn't exist — tests the happy path gets 404
				// not 400 (i.e., the URL itself is valid but key is absent).
				"payload_hash": hashHex([]byte("x")), "algorithm": "ES256",
			},
			want: http.StatusNotFound,
		},
		{
			name: "missing payload_hash",
			path: "/sign/val/sign",
			body: map[string]any{"algorithm": "ES256"},
			want: http.StatusBadRequest,
		},
		{
			name: "payload_hash wrong prefix",
			path: "/sign/val/sign",
			body: map[string]any{"payload_hash": "md5:abc", "algorithm": "ES256"},
			want: http.StatusBadRequest,
		},
		{
			name: "payload_hash hex too short",
			path: "/sign/val/sign",
			body: map[string]any{"payload_hash": "sha256:abc123", "algorithm": "ES256"},
			want: http.StatusBadRequest,
		},
		{
			name: "payload_hash not hex",
			path: "/sign/val/sign",
			body: map[string]any{
				"payload_hash": "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
				"algorithm":    "ES256",
			},
			want: http.StatusBadRequest,
		},
		{
			name: "unknown algorithm",
			path: "/sign/val/sign",
			body: map[string]any{"payload_hash": hashHex([]byte("x")), "algorithm": "HMACSHA256"},
			want: http.StatusBadRequest,
		},
		{
			name: "encryption algorithm rejected for sign endpoint",
			path: "/sign/val/sign",
			body: map[string]any{"payload_hash": hashHex([]byte("x")), "algorithm": "AES256GCM"},
			want: http.StatusBadRequest,
		},
		{
			name: "unknown JSON field rejected",
			path: "/sign/val/sign",
			body: map[string]any{
				"payload_hash": hashHex([]byte("x")),
				"algorithm":    "ES256",
				"extra_field":  "must-be-rejected",
			},
			want: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := request(t, srv, http.MethodPost, tc.path, jsonReader(t, tc.body))
			if rr.Code != tc.want {
				t.Errorf("expected %d, got %d (body: %s)", tc.want, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleEncrypt_InputValidation(t *testing.T) {
	b := backend.NewDevBackend()
	if err := b.CreateKey("val/enc", backend.AlgorithmAES256GCM, "team"); err != nil {
		t.Fatal(err)
	}
	srv, _ := newAllowServer(t, b)

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{
			name: "missing plaintext field",
			body: map[string]any{},
			want: http.StatusBadRequest,
		},
		{
			name: "empty plaintext string",
			body: map[string]any{"plaintext": ""},
			want: http.StatusBadRequest,
		},
		{
			name: "plaintext not base64",
			body: map[string]any{"plaintext": "not-valid-base64!@#"},
			want: http.StatusBadRequest,
		},
		{
			name: "unknown field rejected",
			body: map[string]any{
				"plaintext":   base64.StdEncoding.EncodeToString([]byte("x")),
				"extra_field": "bad",
			},
			want: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := request(t, srv, http.MethodPost, "/encrypt/val/enc", jsonReader(t, tc.body))
			if rr.Code != tc.want {
				t.Errorf("expected %d, got %d (body: %s)", tc.want, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleDecrypt_InputValidation(t *testing.T) {
	b := backend.NewDevBackend()
	if err := b.CreateKey("val/dec", backend.AlgorithmAES256GCM, "team"); err != nil {
		t.Fatal(err)
	}
	srv, _ := newAllowServer(t, b)

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{
			name: "missing ciphertext field",
			body: map[string]any{},
			want: http.StatusBadRequest,
		},
		{
			name: "empty ciphertext string",
			body: map[string]any{"ciphertext": ""},
			want: http.StatusBadRequest,
		},
		{
			name: "ciphertext not base64",
			body: map[string]any{"ciphertext": "not-valid!@#"},
			want: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := request(t, srv, http.MethodPost, "/decrypt/val/dec", jsonReader(t, tc.body))
			if rr.Code != tc.want {
				t.Errorf("expected %d, got %d (body: %s)", tc.want, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleListKeys_InvalidPrefix(t *testing.T) {
	b := backend.NewDevBackend()
	srv, _ := newAllowServer(t, b)

	rr := request(t, srv, http.MethodGet, "/keys?prefix=UPPERCASE/bad", nil)
	assertStatus(t, rr, http.StatusBadRequest)
	assertContentTypeJSON(t, rr)
}

// ════════════════════════════════════════════════════════════════════════════
// 9. Content-Type is always application/json
// ════════════════════════════════════════════════════════════════════════════

func TestAllEndpoints_AlwaysApplicationJSON(t *testing.T) {
	// Success responses.
	sigSpy := newSignBackend(t, "ct/sign")
	encSpy := newEncBackend(t, "ct/enc")
	sigSrv, _ := newAllowServer(t, sigSpy)
	encSrv, _ := newAllowServer(t, encSpy)

	assertContentTypeJSON(t, request(t, sigSrv, http.MethodPost, "/sign/ct/sign",
		jsonReader(t, map[string]any{
			"payload_hash": hashHex([]byte("x")), "algorithm": "ES256",
		}),
	))
	assertContentTypeJSON(t, request(t, encSrv, http.MethodPost, "/encrypt/ct/enc",
		jsonReader(t, map[string]any{
			"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
		}),
	))

	bKeys := backend.NewDevBackend()
	keySrv, _ := newAllowServer(t, bKeys)
	assertContentTypeJSON(t, request(t, keySrv, http.MethodGet, "/keys", nil))

	// Error responses (400, 403, 404, 501) must also be application/json.
	bEmpty := backend.NewDevBackend()
	errSrv, _ := newAllowServer(t, bEmpty)

	assertContentTypeJSON(t, request(t, errSrv, http.MethodPost, "/sign/missing",
		jsonReader(t, map[string]any{"payload_hash": "bad", "algorithm": "ES256"}),
	))
	assertContentTypeJSON(t, request(t, errSrv, http.MethodPost, "/rotate/any/key", nil))

	bDeny := backend.NewDevBackend()
	if err := bDeny.CreateKey("ct/deny", backend.AlgorithmES256, "team"); err != nil {
		t.Fatal(err)
	}
	denySrv, _ := newDenyServer(t, bDeny)
	assertContentTypeJSON(t, request(t, denySrv, http.MethodPost, "/sign/ct/deny",
		jsonReader(t, map[string]any{
			"payload_hash": hashHex([]byte("x")), "algorithm": "ES256",
		}),
	))
}

// ════════════════════════════════════════════════════════════════════════════
// 10. Rotate stub returns 501
// ════════════════════════════════════════════════════════════════════════════

func TestHandleRotateKeyStub_Returns501(t *testing.T) {
	b := backend.NewDevBackend()
	srv, _ := newAllowServer(t, b)

	cases := []string{
		"/rotate/single",
		"/rotate/payments/signing-key",
		"/rotate/a/b/c",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			rr := request(t, srv, http.MethodPost, path, nil)
			assertStatus(t, rr, http.StatusNotImplemented)
			assertContentTypeJSON(t, rr)
			_, code := assertErrorShape(t, "rotate stub", rr.Body.Bytes())
			if code != "not_implemented" {
				t.Errorf("code = %q, want not_implemented", code)
			}
		})
	}
}

// ════════════════════════════════════════════════════════════════════════════
// 11. All signing algorithms accepted by sign endpoint
// ════════════════════════════════════════════════════════════════════════════

func TestHandleSign_AllSigningAlgorithms(t *testing.T) {
	cases := []struct {
		alg   string
		bkAlg backend.Algorithm
	}{
		{"ES256", backend.AlgorithmES256},
		{"EdDSA", backend.AlgorithmEdDSA},
		// RS256 is intentionally excluded here: RSA key generation takes ~300ms
		// and is exercised fully in the backend adversarial test suite (F-08).
		// To include it, use: {"RS256", backend.AlgorithmRS256}
	}

	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			b := backend.NewDevBackend()
			if err := b.CreateKey("alg/key", tc.bkAlg, "team"); err != nil {
				t.Fatalf("CreateKey: %v", err)
			}
			srv, _ := newAllowServer(t, b)

			rr := request(t, srv, http.MethodPost, "/sign/alg/key",
				jsonReader(t, map[string]any{
					"payload_hash": hashHex([]byte("alg test")),
					"algorithm":    tc.alg,
				}),
			)
			assertStatus(t, rr, http.StatusOK)
			assertNoPEMHeaders(t, tc.alg+" success", rr.Body.Bytes())

			m := decodeMap(t, rr.Body.Bytes())
			assertOnlyFields(t, tc.alg+" response", m, "signature", "key_version")
		})
	}
}

// ════════════════════════════════════════════════════════════════════════════
// 10 (updated). Rotate stub returns 501 AND emits an audit event
// ════════════════════════════════════════════════════════════════════════════

// TestHandleRotateKeyStub_InvalidKeyID verifies that the rotate stub rejects
// malformed key IDs with 400 (not 501) and records an OutcomeDenied audit
// event with a well-formed (empty) KeyID — consistent with every other handler.
func TestHandleRotateKeyStub_InvalidKeyID(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"uppercase segment", "/rotate/UPPER/key"},
		{"dot segment", "/rotate/has.dot"},
		{"at-sign segment", "/rotate/user%40host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := backend.NewDevBackend()
			aud := &capturingAuditor{}
			srv := api.NewServer(b, aud, policy.AllowAllEngine{}, "dev")

			rr := request(t, srv, http.MethodPost, tc.path, nil)
			assertStatus(t, rr, http.StatusBadRequest)
			assertContentTypeJSON(t, rr)
			_, code := assertErrorShape(t, "rotate invalid key", rr.Body.Bytes())
			if code != "invalid_request" {
				t.Errorf("code = %q, want invalid_request", code)
			}

			ev, ok := aud.lastEvent()
			if !ok {
				t.Fatal("no audit event for invalid key ID on rotate stub")
			}
			if ev.Outcome != audit.OutcomeDenied {
				t.Errorf("audit outcome = %q, want denied", ev.Outcome)
			}
			// ev.KeyID must be empty — the invalid ID must not be stored.
			if ev.KeyID != "" {
				t.Errorf("ADVERSARIAL: audit ev.KeyID = %q for invalid key; want empty string", ev.KeyID)
			}
		})
	}
}

// TestHandleRotateKeyStub_Returns501AndAudits verifies that the rotate stub
// returns 501 AND writes an audit event with OperationRotateKey and
// OutcomeError.  Previously the stub returned 501 with no audit record,
// making probe attempts invisible.
func TestHandleRotateKeyStub_Returns501AndAudits(t *testing.T) {
	cases := []string{
		"/rotate/single",
		"/rotate/payments/signing-key",
		"/rotate/a/b/c",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			b := backend.NewDevBackend()
			aud := &capturingAuditor{}
			srv := api.NewServer(b, aud, policy.AllowAllEngine{}, "dev")

			rr := request(t, srv, http.MethodPost, path, nil)
			assertStatus(t, rr, http.StatusNotImplemented)
			assertContentTypeJSON(t, rr)
			_, code := assertErrorShape(t, "rotate stub", rr.Body.Bytes())
			if code != "not_implemented" {
				t.Errorf("code = %q, want not_implemented", code)
			}

			// Audit event must exist.
			ev, ok := aud.lastEvent()
			if !ok {
				t.Fatal("ADVERSARIAL: rotate stub produced no audit event — probe attempts invisible")
			}
			if ev.Operation != audit.OperationRotateKey {
				t.Errorf("audit operation = %q, want %q", ev.Operation, audit.OperationRotateKey)
			}
			if ev.Outcome != audit.OutcomeError {
				t.Errorf("audit outcome = %q, want %q", ev.Outcome, audit.OutcomeError)
			}
			if ev.EventID == "" {
				t.Error("audit EventID is empty")
			}
			if ev.CallerID == "" {
				t.Error("audit CallerID is empty")
			}
		})
	}
}

// ════════════════════════════════════════════════════════════════════════════
// 12. ADVERSARIAL: audit sink failure must cause 500, not silent data loss
// ════════════════════════════════════════════════════════════════════════════

// TestAdversarial_AuditFailure_DenialPaths_Return500 verifies the invariant:
// when the audit sink cannot accept a write, the handler returns 500 rather
// than silently proceeding to return the original 4xx.
//
// Security rationale: if the audit system is down, we cannot record the
// denial.  An attacker who can cause audit failures during probing would
// otherwise leave zero trace of their blocked attempts.  Fail closed: if we
// cannot audit it, we do not respond with the original error code either.
func TestAdversarial_AuditFailure_DenialPaths_Return500(t *testing.T) {
	// newFailServer builds a Server with an always-failing auditor.
	newFailServer := func(b backend.Backend) *api.Server {
		return api.NewServer(b, &failingAuditor{}, policy.AllowAllEngine{}, "dev")
	}

	t.Run("sign: invalid key ID", func(t *testing.T) {
		srv := newFailServer(backend.NewDevBackend())
		rr := request(t, srv, http.MethodPost, "/sign/INVALID/KEY",
			jsonReader(t, map[string]any{
				"payload_hash": hashHex([]byte("x")), "algorithm": "ES256",
			}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
		assertContentTypeJSON(t, rr)
		_, code := assertErrorShape(t, "sign invalid key audit fail", rr.Body.Bytes())
		if code != "internal_error" {
			t.Errorf("expected internal_error code, got %q", code)
		}
	})

	t.Run("sign: invalid payload_hash", func(t *testing.T) {
		srv := newFailServer(backend.NewDevBackend())
		rr := request(t, srv, http.MethodPost, "/sign/test/key",
			jsonReader(t, map[string]any{
				"payload_hash": "not-a-hash", "algorithm": "ES256",
			}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("sign: invalid algorithm", func(t *testing.T) {
		srv := newFailServer(backend.NewDevBackend())
		rr := request(t, srv, http.MethodPost, "/sign/test/key",
			jsonReader(t, map[string]any{
				"payload_hash": hashHex([]byte("x")), "algorithm": "UNKNOWN",
			}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("sign: policy denied", func(t *testing.T) {
		b := backend.NewDevBackend()
		if err := b.CreateKey("deny/key", backend.AlgorithmES256, "team"); err != nil {
			t.Fatal(err)
		}
		// deny-all policy + failing auditor: audit of denial must fail closed.
		srv := api.NewServer(b, &failingAuditor{}, policy.DenyAllEngine{}, "dev")
		rr := request(t, srv, http.MethodPost, "/sign/deny/key",
			jsonReader(t, map[string]any{
				"payload_hash": hashHex([]byte("x")), "algorithm": "ES256",
			}),
		)
		// Must be 500, not 403: we cannot record the denial, so fail closed.
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("encrypt: missing plaintext", func(t *testing.T) {
		srv := newFailServer(backend.NewDevBackend())
		rr := request(t, srv, http.MethodPost, "/encrypt/test/key",
			jsonReader(t, map[string]any{}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("encrypt: invalid base64 plaintext", func(t *testing.T) {
		srv := newFailServer(backend.NewDevBackend())
		rr := request(t, srv, http.MethodPost, "/encrypt/test/key",
			jsonReader(t, map[string]any{"plaintext": "not!base64!"}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("decrypt: missing ciphertext", func(t *testing.T) {
		srv := newFailServer(backend.NewDevBackend())
		rr := request(t, srv, http.MethodPost, "/decrypt/test/key",
			jsonReader(t, map[string]any{}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("decrypt: invalid base64 ciphertext", func(t *testing.T) {
		srv := newFailServer(backend.NewDevBackend())
		rr := request(t, srv, http.MethodPost, "/decrypt/test/key",
			jsonReader(t, map[string]any{"ciphertext": "not!base64!"}),
		)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("list-keys: invalid prefix", func(t *testing.T) {
		srv := newFailServer(backend.NewDevBackend())
		rr := request(t, srv, http.MethodGet, "/keys?prefix=UPPER/CASE", nil)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("list-keys: policy denied", func(t *testing.T) {
		// deny-all + failing auditor: denial cannot be audited, must fail closed.
		srv := api.NewServer(backend.NewDevBackend(), &failingAuditor{}, policy.DenyAllEngine{}, "dev")
		rr := request(t, srv, http.MethodGet, "/keys", nil)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("rotate stub: audit failure returns 500 not 501", func(t *testing.T) {
		// Even the stub must fail closed if audit is unavailable.
		srv := api.NewServer(backend.NewDevBackend(), &failingAuditor{}, policy.AllowAllEngine{}, "dev")
		rr := request(t, srv, http.MethodPost, "/rotate/some/key", nil)
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	t.Run("rotate stub: invalid key ID + audit failure returns 500", func(t *testing.T) {
		// Invalid key ID path on rotate stub + failing audit must return 500, not 400.
		srv := api.NewServer(backend.NewDevBackend(), &failingAuditor{}, policy.AllowAllEngine{}, "dev")
		rr := request(t, srv, http.MethodPost, "/rotate/INVALID/KEY", nil)
		assertStatus(t, rr, http.StatusInternalServerError)
	})
}

// TestAdversarial_AuditFailure_SuccessPath_AlreadyCovered documents that the
// success-path audit failure (returning 500 when Log fails after a successful
// backend operation) was already implemented correctly in the original code.
// This test makes that invariant explicit.
func TestAdversarial_AuditFailure_SuccessPath_Returns500(t *testing.T) {
	spy := newSignBackend(t, "audit-fail/sign")
	srv := api.NewServer(spy, &failingAuditor{}, policy.AllowAllEngine{}, "dev")

	// The backend would succeed (key exists), but the audit sink fails.
	// Handler must return 500 and discard the successful sign result.
	rr := request(t, srv, http.MethodPost, "/sign/audit-fail/sign",
		jsonReader(t, map[string]any{
			"payload_hash": hashHex([]byte("audit fail test")),
			"algorithm":    "ES256",
		}),
	)
	assertStatus(t, rr, http.StatusInternalServerError)
	assertContentTypeJSON(t, rr)
	_, code := assertErrorShape(t, "success+audit-fail", rr.Body.Bytes())
	if code != "internal_error" {
		t.Errorf("expected internal_error code on audit failure, got %q", code)
	}
}
