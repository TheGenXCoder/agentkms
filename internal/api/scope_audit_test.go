package api_test

// B1 Step 5 — Failing tests for scope fields in audit events.
//
// After a successful credential vend, the audit event must carry:
//   - Scope: JSON-serialized effective Scope with kind, ttl, params
//   - ScopeHash: SHA-256 hex digest (64 chars) matching credentials.ScopeHash()
//
// These tests define the acceptance criteria. They SHOULD fail until the
// feature is implemented in the vend handler.

import (
	"encoding/json"
	"net/http"
	"regexp"
	"testing"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/credentials"
)

// hexSHA256 matches exactly 64 lowercase hex chars.
var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ── Test 1: Scope field is populated on vend ─────────────────────────────────

func TestVendAudit_ScopePopulated(t *testing.T) {
	srv, aud, _ := newBucketAServer(t, "sk-ant-scope-pop")

	rr := bucketARequest(t, srv, http.MethodGet,
		"/credentials/llm/anthropic", nil)
	assertStatus(t, rr, http.StatusOK)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.Operation != audit.OperationCredentialVend {
		t.Fatalf("Operation = %q, want %q", ev.Operation, audit.OperationCredentialVend)
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Fatalf("Outcome = %q, want success", ev.Outcome)
	}

	// Scope must be non-nil JSON
	if ev.Scope == nil {
		t.Fatal("Scope is nil on successful vend audit event — B1 step 5 requires it to be populated")
	}

	// Must deserialize to an object with kind, ttl, params
	var scopeMap map[string]any
	if err := json.Unmarshal(ev.Scope, &scopeMap); err != nil {
		t.Fatalf("Scope is not valid JSON: %v (raw: %s)", err, string(ev.Scope))
	}
	if _, ok := scopeMap["kind"]; !ok {
		t.Error("Scope JSON missing 'kind' field")
	}
	if _, ok := scopeMap["ttl"]; !ok {
		t.Error("Scope JSON missing 'ttl' field")
	}
	if _, ok := scopeMap["params"]; !ok {
		t.Error("Scope JSON missing 'params' field")
	}
}

// ── Test 2: ScopeHash is populated and is 64 hex chars ───────────────────────

func TestVendAudit_ScopeHashPopulated(t *testing.T) {
	srv, aud, _ := newBucketAServer(t, "sk-ant-scope-hash")

	rr := bucketARequest(t, srv, http.MethodGet,
		"/credentials/llm/anthropic", nil)
	assertStatus(t, rr, http.StatusOK)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Fatalf("Outcome = %q, want success", ev.Outcome)
	}

	if ev.ScopeHash == "" {
		t.Fatal("ScopeHash is empty on successful vend audit event — B1 step 5 requires it")
	}
	if !hexSHA256.MatchString(ev.ScopeHash) {
		t.Errorf("ScopeHash = %q, want 64 lowercase hex chars (SHA-256)", ev.ScopeHash)
	}
}

// ── Test 3: ScopeHash matches credentials.ScopeHash(Scope) ──────────────────

func TestVendAudit_ScopeHashMatchesScope(t *testing.T) {
	srv, aud, _ := newBucketAServer(t, "sk-ant-scope-match")

	rr := bucketARequest(t, srv, http.MethodGet,
		"/credentials/llm/anthropic", nil)
	assertStatus(t, rr, http.StatusOK)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Fatalf("Outcome = %q, want success", ev.Outcome)
	}
	if ev.Scope == nil {
		t.Fatal("Scope is nil — cannot verify hash match")
	}
	if ev.ScopeHash == "" {
		t.Fatal("ScopeHash is empty — cannot verify hash match")
	}

	// Deserialize the Scope from the audit event into a credentials.Scope
	var scope credentials.Scope
	if err := json.Unmarshal(ev.Scope, &scope); err != nil {
		t.Fatalf("failed to unmarshal Scope from audit event: %v", err)
	}

	// Compute the expected hash and compare
	expectedHash := credentials.ScopeHash(scope)
	if ev.ScopeHash != expectedHash {
		t.Errorf("ScopeHash mismatch:\n  audit event: %q\n  computed:    %q",
			ev.ScopeHash, expectedHash)
	}
}

// ── Test 4: Scope.kind is "llm-session" for LLM vend path ───────────────────

func TestVendAudit_ScopeKindIsLLMSession(t *testing.T) {
	srv, aud, _ := newBucketAServer(t, "sk-ant-scope-kind")

	rr := bucketARequest(t, srv, http.MethodGet,
		"/credentials/llm/anthropic", nil)
	assertStatus(t, rr, http.StatusOK)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Fatalf("Outcome = %q, want success", ev.Outcome)
	}
	if ev.Scope == nil {
		t.Fatal("Scope is nil — cannot check kind")
	}

	var scopeMap map[string]any
	if err := json.Unmarshal(ev.Scope, &scopeMap); err != nil {
		t.Fatalf("Scope JSON unmarshal error: %v", err)
	}

	kind, _ := scopeMap["kind"].(string)
	if kind != "llm-session" {
		t.Errorf("Scope.kind = %q, want %q", kind, "llm-session")
	}
}

// ── Test 5: Scope.params includes provider ───────────────────────────────────

func TestVendAudit_ScopeParamsIncludeProvider(t *testing.T) {
	srv, aud, _ := newBucketAServer(t, "sk-ant-scope-params")

	rr := bucketARequest(t, srv, http.MethodGet,
		"/credentials/llm/anthropic", nil)
	assertStatus(t, rr, http.StatusOK)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Fatalf("Outcome = %q, want success", ev.Outcome)
	}
	if ev.Scope == nil {
		t.Fatal("Scope is nil — cannot check params")
	}

	var scopeMap map[string]any
	if err := json.Unmarshal(ev.Scope, &scopeMap); err != nil {
		t.Fatalf("Scope JSON unmarshal error: %v", err)
	}

	params, ok := scopeMap["params"].(map[string]any)
	if !ok {
		t.Fatal("Scope.params is not an object or is missing")
	}

	provider, _ := params["provider"].(string)
	if provider != "anthropic" {
		t.Errorf("Scope.params.provider = %q, want %q", provider, "anthropic")
	}
}

// ── Test 6: Non-vend operations have nil Scope ───────────────────────────────

func TestVendAudit_NonVendOps_ScopeNil(t *testing.T) {
	// Use the sign endpoint — a non-vend operation that emits audit events.
	srv, aud, _ := newBucketAServer(t, "")

	// POST /sign/{keyID} with a payload hash
	body := []byte(`{"payload_hash":"sha256:` +
		`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`)
	rr := bucketARequest(t, srv, http.MethodPost, "/sign/test/key", body)

	// We don't care about the HTTP status for this test — just check the
	// audit event.  The sign might succeed or 404 depending on backend
	// state, but an event is still emitted.
	_ = rr

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded for sign operation")
	}
	if ev.Operation != audit.OperationSign {
		t.Fatalf("Operation = %q, want %q", ev.Operation, audit.OperationSign)
	}

	// Scope must be nil/empty for non-vend operations
	if ev.Scope != nil {
		t.Errorf("Scope should be nil for non-vend operation, got: %s", string(ev.Scope))
	}
	if ev.ScopeHash != "" {
		t.Errorf("ScopeHash should be empty for non-vend operation, got: %q", ev.ScopeHash)
	}
}
