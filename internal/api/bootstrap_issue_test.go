package api_test

// bootstrap_issue_test.go — Unit tests for POST /auth/bootstrap/issue.
//
// Uses the same test infrastructure as cert_enroll_test.go (mockBootstrapStore,
// newMockPKIServer, newCertEnrollStack, issueCertHumanToken, etc.).
//
// NOTE: mockBootstrapStore.Create is defined here (not in cert_enroll_test.go)
// so that the Create method is only compiled once alongside these tests.  The
// mockBootstrapStore type itself is still defined in cert_enroll_test.go.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/auth"
)

// Create implements auth.BootstrapStore.Create for the in-memory mock.
// It uses crypto/rand — same entropy source as the real vaultBootstrapStore —
// so the returned token is a genuine 64-char hex string that the test can
// hand to HandleCertIssue via Fetch.
func (m *mockBootstrapStore) Create(_ context.Context, record auth.BootstrapRecord) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	rawToken := hex.EncodeToString(raw[:])
	record.Used = false
	m.records[rawToken] = &record
	return rawToken, nil
}

// hex64RE matches exactly 64 lower-case hex characters.
var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// bootstrapIssueReq builds a POST /auth/bootstrap/issue HTTP request.
func bootstrapIssueReq(t *testing.T, body any, tokenStr string) *http.Request {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/bootstrap/issue", bytes.NewReader(bodyBytes))
	r.Header.Set("Content-Type", "application/json")
	if tokenStr != "" {
		r.Header.Set("Authorization", "Bearer "+tokenStr)
	}
	return r
}

// ── TestBootstrapIssue_HappyPath_CertHuman ────────────────────────────────────

// TestBootstrapIssue_HappyPath_CertHuman: cert+human bearer, valid body →
// 200, response has a 64-hex-char bootstrap_token and an expires_at
// approximately ttl seconds from now, and the mock store contains the
// record with the right user_id + pattern + Used:false.
func TestBootstrapIssue_HappyPath_CertHuman(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	svc, handler, bs := newCertEnrollStack(t, mockPKI)

	tokenStr := issueCertHumanToken(t, svc, "alice", "alice-laptop", "catalyst9")

	before := time.Now().UTC()
	w := httptest.NewRecorder()
	r := bootstrapIssueReq(t, map[string]any{
		"device_name_pattern": "alice-new-device",
		"ttl_seconds":         7200,
	}, tokenStr)
	handler.HandleBootstrapIssue(w, r)
	after := time.Now().UTC()

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// bootstrap_token must be 64 lowercase hex chars.
	rawToken, _ := resp["bootstrap_token"].(string)
	if !hex64RE.MatchString(rawToken) {
		t.Errorf("bootstrap_token = %q, want 64 lowercase hex chars", rawToken)
	}

	// expires_at must be RFC3339 and approximately now+7200s.
	// RFC3339 truncates to seconds, so allow a 1-second slack on each side.
	expiresStr, _ := resp["expires_at"].(string)
	expiresAt, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil {
		t.Fatalf("expires_at parse error: %v", err)
	}
	expectedLo := before.Add(7200*time.Second - time.Second)
	expectedHi := after.Add(7200*time.Second + time.Second)
	if expiresAt.Before(expectedLo) || expiresAt.After(expectedHi) {
		t.Errorf("expires_at = %v, want between %v and %v", expiresAt, expectedLo, expectedHi)
	}

	// The mock store must contain the record via Fetch.
	rec, fetchErr := bs.Fetch(context.Background(), rawToken)
	if fetchErr != nil {
		t.Fatalf("Fetch: %v", fetchErr)
	}
	if rec == nil {
		t.Fatal("record not found in store after HandleBootstrapIssue")
	}
	if rec.UserID != "alice" {
		t.Errorf("record.UserID = %q, want alice", rec.UserID)
	}
	if rec.DeviceNamePattern != "alice-new-device" {
		t.Errorf("record.DeviceNamePattern = %q, want alice-new-device", rec.DeviceNamePattern)
	}
	if rec.Used {
		t.Error("record.Used = true; newly issued token must not be marked used")
	}
}

// ── TestBootstrapIssue_CertOnly_Forbidden ────────────────────────────────────

// TestBootstrapIssue_CertOnly_Forbidden: cert-only bearer → 403.
func TestBootstrapIssue_CertOnly_Forbidden(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	svc, handler, _ := newCertEnrollStack(t, mockPKI)

	tokenStr := issueCertOnlyToken(t, svc, "bob", "bob-wks", "catalyst9")

	w := httptest.NewRecorder()
	r := bootstrapIssueReq(t, map[string]any{
		"device_name_pattern": "bob-new-device",
	}, tokenStr)
	handler.HandleBootstrapIssue(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for cert-only session; body = %s", w.Code, w.Body.String())
	}
}

// ── TestBootstrapIssue_InvalidPattern ────────────────────────────────────────

// TestBootstrapIssue_InvalidPattern: various invalid device_name_pattern
// values → 400.
func TestBootstrapIssue_InvalidPattern(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	svc, handler, _ := newCertEnrollStack(t, mockPKI)

	tokenStr := issueCertHumanToken(t, svc, "alice", "alice-laptop", "catalyst9")

	cases := []struct {
		name    string
		pattern string
	}{
		{"uppercase", "INVALID_UPPER"},
		{"space", "has space"},
		{"underscore", "has_underscore"},
		{"empty", ""},
		{"too_long", "toolong-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := bootstrapIssueReq(t, map[string]any{
				"device_name_pattern": tc.pattern,
				"ttl_seconds":         3600,
			}, tokenStr)
			handler.HandleBootstrapIssue(w, r)
			if w.Code != http.StatusBadRequest {
				t.Errorf("pattern %q: status = %d, want 400; body = %s",
					tc.pattern, w.Code, w.Body.String())
			}
		})
	}
}

// ── TestBootstrapIssue_WildcardPattern ───────────────────────────────────────

// TestBootstrapIssue_WildcardPattern: device_name_pattern = "*" → 200.
func TestBootstrapIssue_WildcardPattern(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	svc, handler, _ := newCertEnrollStack(t, mockPKI)

	tokenStr := issueCertHumanToken(t, svc, "alice", "alice-laptop", "catalyst9")

	w := httptest.NewRecorder()
	r := bootstrapIssueReq(t, map[string]any{
		"device_name_pattern": "*",
	}, tokenStr)
	handler.HandleBootstrapIssue(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for wildcard pattern; body = %s", w.Code, w.Body.String())
	}
}

// ── TestBootstrapIssue_TTLOutOfRange ─────────────────────────────────────────

// TestBootstrapIssue_TTLOutOfRange tests TTL boundary conditions:
//   - ttl 0 → defaults to 3600, succeeds
//   - ttl 100000 → 400 (exceeds 86400)
//   - ttl 30 → 400 (below minimum 60)
func TestBootstrapIssue_TTLOutOfRange(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	svc, handler, _ := newCertEnrollStack(t, mockPKI)

	tokenStr := issueCertHumanToken(t, svc, "alice", "alice-laptop", "catalyst9")

	// ttl_seconds = 0 → default 3600, must succeed.
	t.Run("zero_defaults_to_3600", func(t *testing.T) {
		before := time.Now().UTC()
		w := httptest.NewRecorder()
		r := bootstrapIssueReq(t, map[string]any{
			"device_name_pattern": "alice-device",
			"ttl_seconds":         0,
		}, tokenStr)
		handler.HandleBootstrapIssue(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for ttl=0; body = %s", w.Code, w.Body.String())
		}
		var resp map[string]any
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		expiresStr, _ := resp["expires_at"].(string)
		expiresAt, err := time.Parse(time.RFC3339, expiresStr)
		if err != nil {
			t.Fatalf("parse expires_at: %v", err)
		}
		// RFC3339 truncates to seconds; allow 2s slack to avoid flakiness.
		diff := expiresAt.Sub(before)
		if diff < 3598*time.Second || diff > 3602*time.Second {
			t.Errorf("expires_at diff = %v, want ~3600s", diff)
		}
	})

	// ttl_seconds = 100000 → 400.
	t.Run("too_large", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := bootstrapIssueReq(t, map[string]any{
			"device_name_pattern": "alice-device",
			"ttl_seconds":         100000,
		}, tokenStr)
		handler.HandleBootstrapIssue(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for ttl=100000; body = %s", w.Code, w.Body.String())
		}
	})

	// ttl_seconds = 30 → 400 (below minimum of 60).
	t.Run("too_small", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := bootstrapIssueReq(t, map[string]any{
			"device_name_pattern": "alice-device",
			"ttl_seconds":         30,
		}, tokenStr)
		handler.HandleBootstrapIssue(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for ttl=30; body = %s", w.Code, w.Body.String())
		}
	})
}

// ── TestBootstrapIssue_NoAuth ─────────────────────────────────────────────────

// TestBootstrapIssue_NoAuth: missing Authorization header → 401.
func TestBootstrapIssue_NoAuth(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	_, handler, _ := newCertEnrollStack(t, mockPKI)

	w := httptest.NewRecorder()
	r := bootstrapIssueReq(t, map[string]any{
		"device_name_pattern": "some-device",
	}, "") // no token
	handler.HandleBootstrapIssue(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body = %s", w.Code, w.Body.String())
	}
}

// ── TestBootstrapIssue_RoundTrip ─────────────────────────────────────────────

// TestBootstrapIssue_RoundTrip: issue a bootstrap token, then call
// HandleCertIssue with that token + a matching CSR → cert is issued.
// Proves the two endpoints integrate cleanly end-to-end.
func TestBootstrapIssue_RoundTrip(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	fakeCert := "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
	mockPKI.signCertPEM = fakeCert
	mockPKI.signSerial = "aa:bb:cc:dd"
	mockPKI.signExpiry = time.Now().Add(365 * 24 * time.Hour).Unix()

	svc, handler, _ := newCertEnrollStack(t, mockPKI)

	// Step 1: operator mints a bootstrap token for alice's new device.
	operatorToken := issueCertHumanToken(t, svc, "operator", "operator-laptop", "catalyst9")

	w1 := httptest.NewRecorder()
	r1 := bootstrapIssueReq(t, map[string]any{
		"device_name_pattern": "alice-new-device",
		"ttl_seconds":         3600,
	}, operatorToken)
	handler.HandleBootstrapIssue(w1, r1)

	if w1.Code != http.StatusOK {
		t.Fatalf("bootstrap/issue: status = %d, body = %s", w1.Code, w1.Body.String())
	}

	var issueResp map[string]any
	if err := json.NewDecoder(w1.Body).Decode(&issueResp); err != nil {
		t.Fatalf("decode bootstrap/issue response: %v", err)
	}
	rawToken, _ := issueResp["bootstrap_token"].(string)
	if rawToken == "" {
		t.Fatal("bootstrap_token is empty")
	}

	// Step 2: the device redeems the bootstrap token to get a cert.
	// The SPIFFE URI encodes the operator's user_id (the token was issued for
	// operator) and the agreed device name.
	spiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/operator/device/alice-new-device"
	csr := makeCSR(t, spiffe)

	w2 := httptest.NewRecorder()
	r2 := makeIssueReq(t, map[string]any{
		"csr":             csr,
		"device_name":     "alice-new-device",
		"bootstrap_token": rawToken,
	}, "")
	handler.HandleCertIssue(w2, r2)

	if w2.Code != http.StatusOK {
		t.Fatalf("cert/issue: status = %d, body = %s", w2.Code, w2.Body.String())
	}

	var certResp map[string]any
	if err := json.NewDecoder(w2.Body).Decode(&certResp); err != nil {
		t.Fatalf("decode cert/issue response: %v", err)
	}
	if certResp["cert"] == "" || certResp["cert"] == nil {
		t.Error("cert/issue response missing cert field")
	}
	if certResp["serial"] != "aa:bb:cc:dd" {
		t.Errorf("cert serial = %v, want aa:bb:cc:dd", certResp["serial"])
	}
}
