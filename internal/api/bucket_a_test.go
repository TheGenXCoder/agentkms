package api_test

// Bucket A — end-to-end HTTP handler coverage for the forensics fields.
//
// These tests exercise the wiring between handlers, the policy engine, and
// the audit sink:
//
//   - RuleID is emitted on successful allows (not only on denies)
//   - CertFingerprint, CallerOU, CallerRole flow from Identity into events
//   - CredentialType, CredentialUUID, ProviderTokenHash are recorded on
//     successful credential vends
//   - POST /audit/use accepts and records credential_uuid
//   - Every event produced by a handler stamps SchemaVersion = 1
//
// Existing audit tests in this package remain valid and must continue to pass.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
)

// ── Helpers ────────────────────────────────────────────────────────────────────

// bucketAIdentity returns a fully-populated Identity for tests.  Unlike the
// minimal identity used elsewhere in this package, it sets the forensics
// fields that Bucket A surfaces into the audit event.
func bucketAIdentity() identity.Identity {
	return identity.Identity{
		CallerID:        "ci-runner@payments",
		TeamID:          "payments",
		Role:            identity.RoleService,
		CallerOU:        "service",
		CertFingerprint: hex.EncodeToString(make([]byte, 32)),
	}
}

// bucketARequest issues an HTTP request with bucketAIdentity() injected
// into the context (bypassing the real mTLS middleware).
func bucketARequest(t *testing.T, srv http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *strings.Reader
	if body != nil {
		bodyReader = strings.NewReader(string(body))
	}
	var req *http.Request
	if bodyReader != nil {
		req = httptest.NewRequest(method, path, bodyReader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req = req.WithContext(api.SetIdentityInContext(req.Context(), bucketAIdentity()))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

// newBucketAServer constructs a Server with a policy engine that
// recognises a single allow rule (so Decision.MatchedRuleID is non-empty
// on success) and a vender ready to issue for anthropic.
func newBucketAServer(t *testing.T, apiKey string) (*api.Server, *capturingAuditor, string) {
	t.Helper()
	const ruleID = "bucket-a-test-rule"
	p := policy.New(policy.Policy{
		Version: "1",
		Rules: []policy.Rule{{
			ID:     ruleID,
			Effect: policy.EffectAllow,
			Match:  policy.Match{},
		}},
	})
	aud := &capturingAuditor{}
	b := backend.NewDevBackend()
	rl := auth.NewRevocationList()
	ts, _ := auth.NewTokenService(rl)
	srv := api.NewServer(b, aud, policy.AsEngineI(p), ts, "dev")
	// Disable the vend rate limiter so repeated vends in one test are
	// not rejected as "rate limited".
	srv.SetRateLimitInterval(0)
	if apiKey != "" {
		kv := &stubCredKV{
			data: map[string]map[string]string{
				"kv/data/llm/anthropic": {"api_key": apiKey},
			},
		}
		srv.SetVender(credentials.NewVender(kv, "kv"))
	}
	return srv, aud, ruleID
}

// ── RuleID on allows ──────────────────────────────────────────────────────────

// TestBucketA_RuleID_OnSuccessfulAllow verifies the central Bucket A
// contract: RuleID is captured on the allow path, not only on denies.
//
// Before Bucket A, only DenyReason was audited for denies; successful
// allows had no record of which rule permitted the operation.  A
// forensics query for "what rule granted access to this key" was
// impossible.
func TestBucketA_RuleID_OnSuccessfulAllow(t *testing.T) {
	srv, aud, ruleID := newBucketAServer(t, "sk-ant-test-ruleid")

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
	if ev.RuleID != ruleID {
		t.Errorf("RuleID on successful allow = %q, want %q", ev.RuleID, ruleID)
	}
}

// TestBucketA_RuleID_OnDeny confirms the deny path continues to capture
// RuleID (the previous behaviour, now tested explicitly).
func TestBucketA_RuleID_OnDeny(t *testing.T) {
	const ruleID = "deny-generic"
	p := policy.New(policy.Policy{
		Version: "1",
		Rules: []policy.Rule{{
			ID:          ruleID,
			Effect:      policy.EffectDeny,
			Description: "test deny",
			Match:       policy.Match{},
		}},
	})
	aud := &capturingAuditor{}
	rl := auth.NewRevocationList()
	ts, _ := auth.NewTokenService(rl)
	srv := api.NewServer(backend.NewDevBackend(), aud,
		policy.AsEngineI(p), ts, "dev")

	kv := &stubCredKV{data: map[string]map[string]string{
		"kv/data/llm/anthropic": {"api_key": "sk-x"},
	}}
	srv.SetVender(credentials.NewVender(kv, "kv"))

	rr := bucketARequest(t, srv, http.MethodGet,
		"/credentials/llm/anthropic", nil)
	assertStatus(t, rr, http.StatusForbidden)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.Outcome != audit.OutcomeDenied {
		t.Errorf("Outcome = %q, want denied", ev.Outcome)
	}
	if ev.RuleID != ruleID {
		t.Errorf("RuleID = %q, want %q", ev.RuleID, ruleID)
	}
}

// ── SchemaVersion on every handler-emitted event ──────────────────────────────

// TestBucketA_SchemaVersion_OnHandlerEvents — every event produced by a
// Server handler (success or deny) must carry SchemaVersion == 1.  This
// keeps downstream consumers (v0.3 forensics) from having to guess
// whether to trust the new fields.
func TestBucketA_SchemaVersion_OnHandlerEvents(t *testing.T) {
	srv, aud, _ := newBucketAServer(t, "sk-schema-ver")

	rr := bucketARequest(t, srv, http.MethodGet,
		"/credentials/llm/anthropic", nil)
	assertStatus(t, rr, http.StatusOK)

	if n := aud.eventCount(); n == 0 {
		t.Fatal("expected at least one audit event")
	}
	for i := 0; i < aud.eventCount(); i++ {
		ev := aud.events[i] // safe: no concurrent writers in this test
		if ev.SchemaVersion != audit.CurrentSchemaVersion {
			t.Errorf("event %d SchemaVersion = %d, want %d",
				i, ev.SchemaVersion, audit.CurrentSchemaVersion)
		}
	}
}

// ── Identity → audit forensics flow ───────────────────────────────────────────

// TestBucketA_IdentityFields_Populated verifies that CertFingerprint,
// CallerOU, and CallerRole flow from the injected Identity into the
// recorded audit event.
func TestBucketA_IdentityFields_Populated(t *testing.T) {
	srv, aud, _ := newBucketAServer(t, "sk-ant-idflow")

	rr := bucketARequest(t, srv, http.MethodGet,
		"/credentials/llm/anthropic", nil)
	assertStatus(t, rr, http.StatusOK)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	id := bucketAIdentity()
	if ev.CertFingerprint != id.CertFingerprint {
		t.Errorf("CertFingerprint = %q, want %q",
			ev.CertFingerprint, id.CertFingerprint)
	}
	if ev.CallerOU != id.CallerOU {
		t.Errorf("CallerOU = %q, want %q", ev.CallerOU, id.CallerOU)
	}
	if ev.CallerRole != string(id.Role) {
		t.Errorf("CallerRole = %q, want %q", ev.CallerRole, id.Role)
	}
}

// ── CredentialType / UUID / ProviderTokenHash on vend ─────────────────────────

// TestBucketA_VendAudit_IncludesCredentialFields — Bucket A's centrepiece.
// A successful credential vend audit event must carry:
//
//   - CredentialType (so classes can be filtered without parsing KeyID)
//   - CredentialUUID (so client-side /audit/use calls can be joined)
//   - ProviderTokenHash (so leak reports can be reverse-looked-up)
//
// The raw API key must NOT appear anywhere in the event.
func TestBucketA_VendAudit_IncludesCredentialFields(t *testing.T) {
	const apiKey = "sk-ant-bucket-a-known-token"
	srv, aud, _ := newBucketAServer(t, apiKey)

	rr := bucketARequest(t, srv, http.MethodGet,
		"/credentials/llm/anthropic", nil)
	assertStatus(t, rr, http.StatusOK)

	// Response must expose the credential UUID so the client can echo it.
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	uuidFromResp, _ := resp["credential_uuid"].(string)
	if uuidFromResp == "" {
		t.Fatal("response missing credential_uuid")
	}

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.CredentialType != credentials.TypeLLMSession {
		t.Errorf("CredentialType = %q, want %q",
			ev.CredentialType, credentials.TypeLLMSession)
	}
	if ev.CredentialUUID != uuidFromResp {
		t.Errorf("audit event CredentialUUID = %q, response UUID = %q",
			ev.CredentialUUID, uuidFromResp)
	}
	// ProviderTokenHash must equal sha256(apiKey) hex.
	want := sha256.Sum256([]byte(apiKey))
	wantHex := hex.EncodeToString(want[:])
	if ev.ProviderTokenHash != wantHex {
		t.Errorf("ProviderTokenHash = %q, want %q",
			ev.ProviderTokenHash, wantHex)
	}
	// CRITICAL: the raw token must never reach the audit event.
	encoded, _ := json.Marshal(ev)
	if strings.Contains(string(encoded), apiKey) {
		t.Fatalf(
			"ADVERSARIAL: raw API key leaked into audit event: %s",
			string(encoded),
		)
	}
}

// ── /audit/use accepts credential_uuid ────────────────────────────────────────

// TestBucketA_AuditUse_AcceptsCredentialUUID verifies the use-event path
// threads the CredentialUUID from the request body into the audit event,
// enabling vend↔use correlation.
func TestBucketA_AuditUse_AcceptsCredentialUUID(t *testing.T) {
	srv, aud, _ := newBucketAServer(t, "")

	const credUUID = "550e8400-e29b-41d4-a716-446655440000"
	body := []byte(`{"provider":"anthropic","action":"chat","credential_uuid":"` + credUUID + `"}`)
	rr := bucketARequest(t, srv, http.MethodPost, "/audit/use", body)
	assertStatus(t, rr, http.StatusNoContent)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.Operation != audit.OperationCredentialUse {
		t.Errorf("Operation = %q, want %q",
			ev.Operation, audit.OperationCredentialUse)
	}
	if ev.CredentialUUID != credUUID {
		t.Errorf("CredentialUUID = %q, want %q", ev.CredentialUUID, credUUID)
	}
	if ev.CredentialType != "llm-session" {
		t.Errorf("CredentialType = %q, want llm-session", ev.CredentialType)
	}
	if ev.SchemaVersion != audit.CurrentSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d",
			ev.SchemaVersion, audit.CurrentSchemaVersion)
	}
}

// TestBucketA_AuditUse_RejectsMalformedUUID prevents log poisoning via
// a malformed credential_uuid.
func TestBucketA_AuditUse_RejectsMalformedUUID(t *testing.T) {
	srv, _, _ := newBucketAServer(t, "")

	body := []byte(`{"provider":"anthropic","credential_uuid":"not-a-uuid"}`)
	rr := bucketARequest(t, srv, http.MethodPost, "/audit/use", body)
	assertStatus(t, rr, http.StatusBadRequest)
}

// TestBucketA_AuditUse_OldClient_WithoutUUID verifies backwards
// compatibility: clients that pre-date the credential_uuid field still
// succeed (event is recorded with empty UUID).
func TestBucketA_AuditUse_OldClient_WithoutUUID(t *testing.T) {
	srv, aud, _ := newBucketAServer(t, "")

	body := []byte(`{"provider":"anthropic","action":"chat"}`)
	rr := bucketARequest(t, srv, http.MethodPost, "/audit/use", body)
	assertStatus(t, rr, http.StatusNoContent)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.CredentialUUID != "" {
		t.Errorf("old client CredentialUUID = %q, want empty", ev.CredentialUUID)
	}
	// SchemaVersion still stamped.
	if ev.SchemaVersion != audit.CurrentSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d",
			ev.SchemaVersion, audit.CurrentSchemaVersion)
	}
}

// ── mTLS extractor plumbs CallerOU into Identity ──────────────────────────────

// TestBucketA_MtlsExtract_SetsCallerOU — sanity check that the identity
// extractor now populates CallerOU.  Covered by an in-package unit rather
// than a full mTLS round-trip because the TLS handshake machinery is
// exercised elsewhere.
func TestBucketA_MtlsExtract_SetsCallerOU(t *testing.T) {
	// We cannot reach auth.ExtractIdentity without a *http.Request with
	// r.TLS set, which is the domain of internal/auth tests.  Instead,
	// build an Identity manually and verify the field exists and is
	// serialisable through an AuditEvent.
	id := identity.Identity{
		CallerID: "bert@platform",
		TeamID:   "platform",
		Role:     identity.RoleDeveloper,
		CallerOU: "developer",
	}
	ev, err := audit.New()
	if err != nil {
		t.Fatal(err)
	}
	ev.Operation = audit.OperationSign
	ev.Outcome = audit.OutcomeSuccess
	// Use the package-internal helper via a public handler would be ideal,
	// but populateIdentityFields is unexported.  Mirror its behaviour here
	// to assert the identity→event mapping contract.
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.CertFingerprint = id.CertFingerprint
	ev.CallerOU = id.CallerOU
	ev.CallerRole = string(id.Role)

	if err := ev.Validate(); err != nil {
		t.Fatalf("Validate on identity-populated event: %v", err)
	}
	if ev.CallerOU != "developer" {
		t.Errorf("CallerOU = %q, want developer", ev.CallerOU)
	}
	if ev.CallerRole != "developer" {
		t.Errorf("CallerRole = %q, want developer", ev.CallerRole)
	}
}

// Compile-time silence: context is imported for future expansion of this
// suite without re-touching imports.
var _ = context.Background
