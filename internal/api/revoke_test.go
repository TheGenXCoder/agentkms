package api_test

// FO-B2 — Failing acceptance tests for POST /credentials/revoke.
//
// These tests define the contract for the revocation handler:
//   - Accepts {"credential_uuid": "..."} in the request body
//   - Validates UUID format (RFC 4122)
//   - Records the credential as revoked (idempotent)
//   - Emits an audit event with Operation = OperationRevoke
//   - Returns 200 OK on success, 400 on bad input, 404 on unknown UUID
//
// The handler stub returns 501 Not Implemented — all tests MUST fail until
// the feature is implemented.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// newRevokeServer constructs a Server suitable for revocation tests.
func newRevokeServer(t *testing.T) (*api.Server, *capturingAuditor) {
	t.Helper()
	b := backend.NewDevBackend()
	aud := &capturingAuditor{}
	rl := auth.NewRevocationList()
	ts, _ := auth.NewTokenService(rl)
	srv := api.NewServer(b, aud, policy.AllowAllEngine{}, ts, "dev")
	return srv, aud
}

// revokeRequest issues a POST /credentials/revoke with the given JSON body
// and injected identity.
func revokeRequest(t *testing.T, srv *api.Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "/credentials/revoke", strings.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	id := identity.Identity{
		CallerID:        "admin@platform",
		TeamID:          "platform",
		Role:            identity.RoleDeveloper,
		CallerOU:        "developer",
		CertFingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}
	req = req.WithContext(api.SetIdentityInContext(req.Context(), id))
	srv.ServeHTTP(rr, req)
	return rr
}

// ── Tests ────────────────────────────────────────────────────────────────────

// TestRevoke_Success — POST /credentials/revoke with valid UUID returns 200
// and the audit event has Operation = OperationRevoke.
func TestRevoke_Success(t *testing.T) {
	srv, aud := newRevokeServer(t)

	body := `{"credential_uuid":"550e8400-e29b-41d4-a716-446655440000"}`
	rr := revokeRequest(t, srv, body)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.Operation != audit.OperationRevoke {
		t.Errorf("Operation = %q, want %q", ev.Operation, audit.OperationRevoke)
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %q, want %q", ev.Outcome, audit.OutcomeSuccess)
	}
}

// TestRevoke_AuditEventHasCredentialUUID — the emitted audit event carries
// the correct CredentialUUID from the request.
func TestRevoke_AuditEventHasCredentialUUID(t *testing.T) {
	srv, aud := newRevokeServer(t)

	const credUUID = "550e8400-e29b-41d4-a716-446655440000"
	body := `{"credential_uuid":"` + credUUID + `"}`
	rr := revokeRequest(t, srv, body)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.CredentialUUID != credUUID {
		t.Errorf("CredentialUUID = %q, want %q", ev.CredentialUUID, credUUID)
	}
}

// TestRevoke_AuditEventHasCallerIdentity — CallerID and TeamID populated from
// the mTLS identity context.
func TestRevoke_AuditEventHasCallerIdentity(t *testing.T) {
	srv, aud := newRevokeServer(t)

	body := `{"credential_uuid":"550e8400-e29b-41d4-a716-446655440000"}`
	rr := revokeRequest(t, srv, body)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.CallerID != "admin@platform" {
		t.Errorf("CallerID = %q, want %q", ev.CallerID, "admin@platform")
	}
	if ev.TeamID != "platform" {
		t.Errorf("TeamID = %q, want %q", ev.TeamID, "platform")
	}
}

// TestRevoke_InvalidUUID — malformed UUID in request returns 400 Bad Request.
func TestRevoke_InvalidUUID(t *testing.T) {
	srv, _ := newRevokeServer(t)

	for _, tc := range []struct {
		name string
		uuid string
	}{
		{"too short", "not-a-uuid"},
		{"missing dashes", "550e8400e29b41d4a716446655440000"},
		{"invalid chars", "ZZZZZZZZ-e29b-41d4-a716-446655440000"},
		{"wrong length segment", "550e840-e29b-41d4-a716-446655440000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"credential_uuid":"` + tc.uuid + `"}`
			rr := revokeRequest(t, srv, body)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 for UUID %q", rr.Code, tc.uuid)
			}
		})
	}
}

// TestRevoke_MissingUUID — empty body or missing credential_uuid returns 400.
func TestRevoke_MissingUUID(t *testing.T) {
	srv, _ := newRevokeServer(t)

	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"empty json", "{}"},
		{"empty uuid field", `{"credential_uuid":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := revokeRequest(t, srv, tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 for body %q", rr.Code, tc.body)
			}
		})
	}
}

// TestRevoke_NotFound — UUID that was never issued returns 404.
func TestRevoke_NotFound(t *testing.T) {
	srv, _ := newRevokeServer(t)

	// Use a valid UUID format that was never vended.
	body := `{"credential_uuid":"00000000-0000-4000-8000-000000000000"}`
	rr := revokeRequest(t, srv, body)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

// TestRevoke_Idempotent — revoking the same UUID twice returns 200 both times.
func TestRevoke_Idempotent(t *testing.T) {
	srv, _ := newRevokeServer(t)

	body := `{"credential_uuid":"550e8400-e29b-41d4-a716-446655440000"}`

	rr1 := revokeRequest(t, srv, body)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first revoke: status = %d, want 200", rr1.Code)
	}

	rr2 := revokeRequest(t, srv, body)
	if rr2.Code != http.StatusOK {
		t.Errorf("second revoke: status = %d, want 200 (idempotent)", rr2.Code)
	}
}

// TestRevoke_InvalidationReasonSet — the audit event carries
// InvalidationReason = "revoked-user".
func TestRevoke_InvalidationReasonSet(t *testing.T) {
	srv, aud := newRevokeServer(t)

	body := `{"credential_uuid":"550e8400-e29b-41d4-a716-446655440000"}`
	rr := revokeRequest(t, srv, body)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.InvalidationReason != "revoked-user" {
		t.Errorf("InvalidationReason = %q, want %q",
			ev.InvalidationReason, "revoked-user")
	}

	// Verify the field serialises correctly in JSON.
	encoded, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal audit event: %v", err)
	}
	if !strings.Contains(string(encoded), `"invalidation_reason":"revoked-user"`) {
		t.Errorf("InvalidationReason not found in JSON: %s", string(encoded))
	}
}
