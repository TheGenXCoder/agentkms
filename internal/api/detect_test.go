package api_test

// FO-C2 — Failing acceptance tests for POST /credentials/detect.
//
// These tests define the contract for the detection enrichment handler:
//   - Accepts {"credential_uuid": "...", "detected_at": "...", "source": "..."}
//   - Validates UUID format (RFC 4122)
//   - Validates detected_at is a valid RFC 3339 timestamp
//   - Validates source is non-empty
//   - Checks credential UUID exists (404 if not)
//   - Emits an audit event with InvalidationReason = "revoked-leak"
//   - Returns 200 OK with {"status":"recorded"}
//
// The handler stub returns 501 Not Implemented — all tests MUST fail until
// the feature is implemented.

import (
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

// newDetectServer constructs a Server suitable for detection tests.
func newDetectServer(t *testing.T) (*api.Server, *capturingAuditor) {
	t.Helper()
	b := backend.NewDevBackend()
	aud := &capturingAuditor{}
	rl := auth.NewRevocationList()
	ts, _ := auth.NewTokenService(rl)
	srv := api.NewServer(b, aud, policy.AllowAllEngine{}, ts, "dev")
	return srv, aud
}

// detectRequest issues a POST /credentials/detect with the given JSON body
// and injected identity.
func detectRequest(t *testing.T, srv *api.Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "/credentials/detect", strings.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	id := identity.Identity{
		CallerID:        "security-bot@platform",
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

// TestDetect_Success — POST /credentials/detect with valid payload returns 200
// and response body contains {"status":"recorded"}.
func TestDetect_Success(t *testing.T) {
	srv, _ := newDetectServer(t)

	body := `{
		"credential_uuid": "550e8400-e29b-41d4-a716-446655440000",
		"detected_at": "2026-04-20T10:47:12Z",
		"source": "github-secret-scanning",
		"reason": "Token found in public repository acmecorp/legacy-tool"
	}`
	rr := detectRequest(t, srv, body)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	respBody := rr.Body.String()
	if !strings.Contains(respBody, `"status":"recorded"`) {
		t.Errorf("response body = %q, want to contain %q", respBody, `"status":"recorded"`)
	}
}

// TestDetect_AuditEventEmitted — after success, an audit event exists with
// the credential UUID and InvalidationReason = "revoked-leak".
func TestDetect_AuditEventEmitted(t *testing.T) {
	srv, aud := newDetectServer(t)

	const credUUID = "550e8400-e29b-41d4-a716-446655440000"
	body := `{
		"credential_uuid": "` + credUUID + `",
		"detected_at": "2026-04-20T10:47:12Z",
		"source": "github-secret-scanning",
		"reason": "Token found in public repository"
	}`
	rr := detectRequest(t, srv, body)

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
	if ev.InvalidationReason != "revoked-leak" {
		t.Errorf("InvalidationReason = %q, want %q", ev.InvalidationReason, "revoked-leak")
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %q, want %q", ev.Outcome, audit.OutcomeSuccess)
	}
}

// TestDetect_InvalidUUID — malformed UUID in request returns 400 Bad Request.
func TestDetect_InvalidUUID(t *testing.T) {
	srv, _ := newDetectServer(t)

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
			body := `{
				"credential_uuid": "` + tc.uuid + `",
				"detected_at": "2026-04-20T10:47:12Z",
				"source": "github-secret-scanning"
			}`
			rr := detectRequest(t, srv, body)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 for UUID %q", rr.Code, tc.uuid)
			}
		})
	}
}

// TestDetect_MissingUUID — empty body or missing credential_uuid returns 400.
func TestDetect_MissingUUID(t *testing.T) {
	srv, _ := newDetectServer(t)

	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"empty json", "{}"},
		{"empty uuid field", `{"credential_uuid":"","detected_at":"2026-04-20T10:47:12Z","source":"x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := detectRequest(t, srv, tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 for body %q", rr.Code, tc.body)
			}
		})
	}
}

// TestDetect_MissingDetectedAt — no detected_at field returns 400.
func TestDetect_MissingDetectedAt(t *testing.T) {
	srv, _ := newDetectServer(t)

	body := `{
		"credential_uuid": "550e8400-e29b-41d4-a716-446655440000",
		"source": "github-secret-scanning"
	}`
	rr := detectRequest(t, srv, body)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing detected_at", rr.Code)
	}
}

// TestDetect_InvalidTimestamp — garbage detected_at returns 400.
func TestDetect_InvalidTimestamp(t *testing.T) {
	srv, _ := newDetectServer(t)

	for _, tc := range []struct {
		name       string
		detectedAt string
	}{
		{"not a date", "garbage"},
		{"wrong format", "2026/04/20 10:47:12"},
		{"missing timezone", "2026-04-20T10:47:12"},
		{"epoch int", "1713610032"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{
				"credential_uuid": "550e8400-e29b-41d4-a716-446655440000",
				"detected_at": "` + tc.detectedAt + `",
				"source": "github-secret-scanning"
			}`
			rr := detectRequest(t, srv, body)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 for detected_at %q", rr.Code, tc.detectedAt)
			}
		})
	}
}

// TestDetect_UnknownCredential — UUID that was never issued returns 404.
func TestDetect_UnknownCredential(t *testing.T) {
	srv, _ := newDetectServer(t)

	// Valid UUID format but never vended by the server.
	body := `{
		"credential_uuid": "00000000-0000-4000-8000-000000000000",
		"detected_at": "2026-04-20T10:47:12Z",
		"source": "github-secret-scanning"
	}`
	rr := detectRequest(t, srv, body)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

// TestDetect_CallerIdentityInAudit — audit event has CallerID/TeamID from
// the request identity context.
func TestDetect_CallerIdentityInAudit(t *testing.T) {
	srv, aud := newDetectServer(t)

	body := `{
		"credential_uuid": "550e8400-e29b-41d4-a716-446655440000",
		"detected_at": "2026-04-20T10:47:12Z",
		"source": "github-secret-scanning"
	}`
	rr := detectRequest(t, srv, body)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.CallerID != "security-bot@platform" {
		t.Errorf("CallerID = %q, want %q", ev.CallerID, "security-bot@platform")
	}
	if ev.TeamID != "platform" {
		t.Errorf("TeamID = %q, want %q", ev.TeamID, "platform")
	}
}
