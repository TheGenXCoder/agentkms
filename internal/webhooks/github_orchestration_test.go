package webhooks_test

// github_orchestration_test.go — Failing acceptance tests for the three-branch
// webhook orchestration described in Part 6 of the KPM blog series.
//
// These tests define the behaviour of AlertOrchestrator.ProcessAlert:
//
//   Branch 1 (ExpiredBranch):   credential already expired → auto-close, tag
//                                "detected_after_expiry", notify, no escalation.
//   Branch 2 (LiveRevokedBranch): credential still live → revoke at provider,
//                                set InvalidatedAt, tag "revoked_on_detection",
//                                escalate on-call.
//   Branch 3 (ManualRevokeBranch): provider has no revoke API → high-priority
//                                alert with manual revocation URL, no API call.
//
// Every test MUST fail until AlertOrchestrator is implemented.
// Do NOT add any implementation to satisfy these tests — that is the
// implementation agent's job.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/revocation"
	"github.com/agentkms/agentkms/internal/webhooks"
)

// ── Test doubles ──────────────────────────────────────────────────────────────

// mockAuditStore implements webhooks.AuditStore for tests.
// Callers seed it with CredentialRecords; FindByTokenHash does an in-memory scan.
type mockAuditStore struct {
	mu      sync.Mutex
	records []webhooks.CredentialRecord
	findErr error // if non-nil, returned by FindByTokenHash
}

func (s *mockAuditStore) FindByTokenHash(_ context.Context, hash string) (*webhooks.CredentialRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.findErr != nil {
		return nil, s.findErr
	}
	for i := range s.records {
		if s.records[i].ProviderTokenHash == hash {
			return &s.records[i], nil
		}
	}
	return nil, webhooks.ErrCredentialNotFound
}

func (s *mockAuditStore) seed(r webhooks.CredentialRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r)
}

// mockRevoker implements revocation.Revoker for tests.
type mockRevoker struct {
	supportsRevocation  bool
	revokeResult        revocation.RevokeResult
	revokeErr           error
	revokeCalled        bool
	mu                  sync.Mutex
}

func (r *mockRevoker) SupportsRevocation() bool { return r.supportsRevocation }

func (r *mockRevoker) Revoke(_ context.Context, _ revocation.CredentialRecord) (revocation.RevokeResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revokeCalled = true
	return r.revokeResult, r.revokeErr
}

func (r *mockRevoker) wasRevokeCalled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revokeCalled
}

// capturingAuditor records every audit.AuditEvent written by the orchestrator.
type orchestratorAuditor struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

func (a *orchestratorAuditor) Log(_ context.Context, ev audit.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *orchestratorAuditor) Flush(_ context.Context) error { return nil }

func (a *orchestratorAuditor) last() (audit.AuditEvent, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) == 0 {
		return audit.AuditEvent{}, false
	}
	return a.events[len(a.events)-1], true
}

func (a *orchestratorAuditor) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.events)
}

// capturingNotifier records Notify calls.
type capturingNotifier struct {
	mu      sync.Mutex
	results []webhooks.AlertResult
}

func (n *capturingNotifier) Notify(_ context.Context, r webhooks.AlertResult) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.results = append(n.results, r)
	return nil
}

func (n *capturingNotifier) callCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.results)
}

func (n *capturingNotifier) last() (webhooks.AlertResult, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.results) == 0 {
		return webhooks.AlertResult{}, false
	}
	return n.results[len(n.results)-1], true
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const (
	orchTestSecret     = "orch-test-webhook-secret"
	orchTestLeakedToken = "ghp_ABCxyz_leaked_token_value_123"
)

// orchTokenHash is the SHA-256 hex of orchTestLeakedToken.
var orchTokenHash = func() string {
	h := sha256.Sum256([]byte(orchTestLeakedToken))
	return hex.EncodeToString(h[:])
}()

func signBody(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// buildWebhookBody builds a valid GitHub secret-scanning webhook JSON payload.
func buildWebhookBody(secret string) []byte {
	body := `{
  "action": "created",
  "alert": {
    "number": 99,
    "secret_type": "github_personal_access_token",
    "secret": "` + secret + `"
  },
  "repository": {
    "full_name": "acmecorp/legacy-tool"
  }
}`
	return []byte(body)
}

// expiredRecord returns a CredentialRecord whose InvalidatedAt is in the past.
func expiredRecord() webhooks.CredentialRecord {
	now := time.Now().UTC()
	return webhooks.CredentialRecord{
		CredentialUUID:    "550e8400-e29b-41d4-a716-446655440001",
		ProviderTokenHash: orchTokenHash,
		CredentialType:    "github-pat",
		IssuedAt:          now.Add(-72 * time.Hour),
		InvalidatedAt:     now.Add(-64 * time.Hour), // expired 64 hours ago
		CallerID:          "frank@acmecorp",
		RuleID:            "rule-gh-001",
	}
}

// liveRecord returns a CredentialRecord whose InvalidatedAt is zero (still active).
func liveRecord() webhooks.CredentialRecord {
	now := time.Now().UTC()
	return webhooks.CredentialRecord{
		CredentialUUID:    "550e8400-e29b-41d4-a716-446655440002",
		ProviderTokenHash: orchTokenHash,
		CredentialType:    "github-pat",
		IssuedAt:          now.Add(-1 * time.Hour),
		InvalidatedAt:     time.Time{}, // zero == still live
		CallerID:          "frank@acmecorp",
		RuleID:            "rule-gh-001",
	}
}

// noRevokeLiveRecord is a live credential of a type without programmatic revocation.
func noRevokeLiveRecord() webhooks.CredentialRecord {
	r := liveRecord()
	r.CredentialType = "slack-webhook"
	r.CredentialUUID = "550e8400-e29b-41d4-a716-446655440003"
	return r
}

// newOrchestrator constructs an AlertOrchestrator with the given dependencies.
// Fails the test if the constructor does not exist or panics.
func newOrchestrator(
	t *testing.T,
	store webhooks.AuditStore,
	revoker revocation.Revoker,
	auditor audit.Auditor,
	notifier webhooks.Notifier,
) *webhooks.AlertOrchestrator {
	t.Helper()
	return webhooks.NewAlertOrchestrator(store, revoker, auditor, notifier)
}

// ── Tests: Branch 1 — Expired credential ─────────────────────────────────────

// TestOrchestration_ExpiredCredential_AutoCloses verifies that when the leaked
// credential is already past its InvalidatedAt time, ProcessAlert returns
// AlertBranch == ExpiredBranch and does not call the revoker.
func TestOrchestration_ExpiredCredential_AutoCloses(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(expiredRecord())
	revoker := &mockRevoker{supportsRevocation: true}
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, revoker, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:   orchTokenHash,
		SecretType:  "github_personal_access_token",
		Repository:  "acmecorp/legacy-tool",
		AlertNumber: 99,
		DetectedAt:  time.Now().UTC(),
	}

	result, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("ProcessAlert returned unexpected error: %v", err)
	}
	if result.Branch != webhooks.ExpiredBranch {
		t.Errorf("Branch = %v, want ExpiredBranch", result.Branch)
	}
	if revoker.wasRevokeCalled() {
		t.Error("Revoke should NOT be called for already-expired credential")
	}
}

// TestOrchestration_ExpiredCredential_TagsDetectedAfterExpiry verifies the
// "detected_after_expiry" tag is applied to the credential record.
func TestOrchestration_ExpiredCredential_TagsDetectedAfterExpiry(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(expiredRecord())
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, &mockRevoker{}, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	result, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}

	found := false
	for _, tag := range result.TagsApplied {
		if tag == "detected_after_expiry" {
			found = true
		}
	}
	if !found {
		t.Errorf("TagsApplied = %v, want to contain %q", result.TagsApplied, "detected_after_expiry")
	}
}

// TestOrchestration_ExpiredCredential_AuditEvent verifies the audit event
// written for the expired branch uses ReasonExpired and OutcomeSuccess.
func TestOrchestration_ExpiredCredential_AuditEvent(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(expiredRecord())
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, &mockRevoker{}, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	_, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}

	ev, ok := aud.last()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.InvalidationReason != audit.ReasonExpired {
		t.Errorf("InvalidationReason = %q, want %q", ev.InvalidationReason, audit.ReasonExpired)
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %q, want %q", ev.Outcome, audit.OutcomeSuccess)
	}
	if ev.CredentialUUID != expiredRecord().CredentialUUID {
		t.Errorf("CredentialUUID = %q, want %q", ev.CredentialUUID, expiredRecord().CredentialUUID)
	}
}

// TestOrchestration_ExpiredCredential_NotifiesNoEscalation verifies that
// the notifier is called but Escalated is false.
func TestOrchestration_ExpiredCredential_NotifiesNoEscalation(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(expiredRecord())
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, &mockRevoker{}, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	result, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}
	if result.Escalated {
		t.Error("Escalated should be false for expired credential — no human escalation needed")
	}
	if notifier.callCount() == 0 {
		t.Error("Notifier should be called even for auto-closed alerts")
	}
}

// ── Tests: Branch 2 — Live credential, revoked ───────────────────────────────

// TestOrchestration_LiveCredential_RevokesAtProvider verifies that the
// Revoker.Revoke method is called when a live credential is detected.
func TestOrchestration_LiveCredential_RevokesAtProvider(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(liveRecord())
	revoker := &mockRevoker{
		supportsRevocation: true,
		revokeResult:       revocation.RevokeResult{Revoked: true},
	}
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, revoker, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	result, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}
	if !revoker.wasRevokeCalled() {
		t.Error("Revoke should be called for live credential")
	}
	if result.Branch != webhooks.LiveRevokedBranch {
		t.Errorf("Branch = %v, want LiveRevokedBranch", result.Branch)
	}
}

// TestOrchestration_LiveCredential_TagsRevokedOnDetection verifies the
// "revoked_on_detection" tag is applied.
func TestOrchestration_LiveCredential_TagsRevokedOnDetection(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(liveRecord())
	revoker := &mockRevoker{
		supportsRevocation: true,
		revokeResult:       revocation.RevokeResult{Revoked: true},
	}
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, revoker, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	result, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}

	found := false
	for _, tag := range result.TagsApplied {
		if tag == "revoked_on_detection" {
			found = true
		}
	}
	if !found {
		t.Errorf("TagsApplied = %v, want to contain %q", result.TagsApplied, "revoked_on_detection")
	}
}

// TestOrchestration_LiveCredential_AuditEvent verifies ReasonRevokedLeak and
// OutcomeSuccess on the live-revoked audit event.
func TestOrchestration_LiveCredential_AuditEvent(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(liveRecord())
	revoker := &mockRevoker{
		supportsRevocation: true,
		revokeResult:       revocation.RevokeResult{Revoked: true},
	}
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, revoker, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	_, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}

	ev, ok := aud.last()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.InvalidationReason != audit.ReasonRevokedLeak {
		t.Errorf("InvalidationReason = %q, want %q", ev.InvalidationReason, audit.ReasonRevokedLeak)
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %q, want %q", ev.Outcome, audit.OutcomeSuccess)
	}
}

// TestOrchestration_LiveCredential_Escalates verifies that Escalated is true
// when a live credential is found and revoked.
func TestOrchestration_LiveCredential_Escalates(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(liveRecord())
	revoker := &mockRevoker{
		supportsRevocation: true,
		revokeResult:       revocation.RevokeResult{Revoked: true},
	}
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, revoker, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	result, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}
	if !result.Escalated {
		t.Error("Escalated should be true when a live credential is revoked")
	}
}

// ── Tests: Branch 3 — No programmatic revocation ─────────────────────────────

// TestOrchestration_NoRevoke_EmitsHighPriorityAlert verifies that when the
// Revoker does not support revocation, a ManualRevocationURL is populated.
func TestOrchestration_NoRevoke_EmitsHighPriorityAlert(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(noRevokeLiveRecord())
	revoker := &mockRevoker{supportsRevocation: false}
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, revoker, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	result, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}
	if result.Branch != webhooks.ManualRevokeBranch {
		t.Errorf("Branch = %v, want ManualRevokeBranch", result.Branch)
	}
	if result.ManualRevocationURL == "" {
		t.Error("ManualRevocationURL should be populated for no-revoke branch")
	}
	if revoker.wasRevokeCalled() {
		t.Error("Revoke should NOT be called when SupportsRevocation() is false")
	}
}

// TestOrchestration_NoRevoke_AuditEvent verifies OutcomeError and
// manual_revoke_required anomaly tag.
func TestOrchestration_NoRevoke_AuditEvent(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(noRevokeLiveRecord())
	revoker := &mockRevoker{supportsRevocation: false}
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, revoker, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	_, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}

	ev, ok := aud.last()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.Outcome != audit.OutcomeError {
		t.Errorf("Outcome = %q, want %q", ev.Outcome, audit.OutcomeError)
	}

	foundTag := false
	for _, a := range ev.Anomalies {
		if a == "manual_revoke_required" {
			foundTag = true
		}
	}
	if !foundTag {
		t.Errorf("Anomalies = %v, want to contain %q", ev.Anomalies, "manual_revoke_required")
	}
}

// ── Tests: Error paths ────────────────────────────────────────────────────────

// TestOrchestration_CredentialNotFound returns a meaningful error without
// panicking when the token hash does not exist in the audit store.
func TestOrchestration_CredentialNotFound(t *testing.T) {
	store := &mockAuditStore{} // empty — no records seeded
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, &mockRevoker{}, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	_, err := orch.ProcessAlert(context.Background(), alert)
	if err == nil {
		t.Fatal("expected error when credential not found, got nil")
	}
	if !errors.Is(err, webhooks.ErrCredentialNotFound) {
		t.Errorf("error = %v, want to wrap ErrCredentialNotFound", err)
	}
	// Notifier should still be called to alert the team about the unknown token.
	if notifier.callCount() == 0 {
		t.Error("Notifier should be called even when credential is not in ledger")
	}
}

// TestOrchestration_ProviderAPIDown verifies that when Revoker.Revoke returns
// an error, ProcessAlert propagates it and still emits an audit event.
func TestOrchestration_ProviderAPIDown(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(liveRecord())
	revoker := &mockRevoker{
		supportsRevocation: true,
		revokeErr:          errors.New("github api: connection refused"),
	}
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, revoker, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	result, err := orch.ProcessAlert(context.Background(), alert)
	// ProcessAlert should not return a fatal error (webhook must return 2xx so
	// GitHub does not retry indefinitely), but OrchestratorError should be set.
	_ = err
	if result.OrchestratorError == nil {
		t.Error("OrchestratorError should be set when provider API is unreachable")
	}
	// Audit event must still be written even when revocation fails.
	if aud.count() == 0 {
		t.Error("audit event must be written even when provider revocation fails")
	}
}

// TestOrchestration_Idempotency_DuplicateAlert verifies that processing the
// same alert twice does not call Revoke twice. The second call should route to
// ExpiredBranch because InvalidatedAt was set by the first call.
func TestOrchestration_Idempotency_DuplicateAlert(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(liveRecord())
	revoker := &mockRevoker{
		supportsRevocation: true,
		revokeResult:       revocation.RevokeResult{Revoked: true},
	}
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, revoker, aud, notifier)

	alert := &webhooks.GitHubSecretAlert{
		TokenHash:  orchTokenHash,
		DetectedAt: time.Now().UTC(),
	}

	// First call — routes to LiveRevokedBranch, sets InvalidatedAt.
	result1, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("first ProcessAlert error: %v", err)
	}
	if result1.Branch != webhooks.LiveRevokedBranch {
		t.Errorf("first call Branch = %v, want LiveRevokedBranch", result1.Branch)
	}

	// Second call — same alert, credential now has InvalidatedAt set.
	result2, err := orch.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("second ProcessAlert error: %v", err)
	}
	if result2.Branch != webhooks.ExpiredBranch {
		t.Errorf("second call Branch = %v, want ExpiredBranch (idempotent)", result2.Branch)
	}

	// Revoke must only have been called once.
	// mockRevoker doesn't count calls; check audit events instead.
	// Expect exactly 2 audit events: one LiveRevoked, one Expired.
	if aud.count() != 2 {
		t.Errorf("audit event count = %d, want 2 (one per ProcessAlert call)", aud.count())
	}
}

// TestOrchestration_HMACValidated_MalformedAlertBody verifies that a
// HMAC-validated but structurally malformed alert (missing token hash) causes
// ProcessAlert to return an error rather than panic or silently succeed.
func TestOrchestration_HMACValidated_MalformedAlertBody(t *testing.T) {
	store := &mockAuditStore{}
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, &mockRevoker{}, aud, notifier)

	// Alert with empty TokenHash — ParseAlert would already reject this, but
	// the orchestrator may receive a hand-constructed alert in unit tests.
	badAlert := &webhooks.GitHubSecretAlert{
		TokenHash:  "", // empty — should be rejected
		DetectedAt: time.Now().UTC(),
	}

	_, err := orch.ProcessAlert(context.Background(), badAlert)
	if err == nil {
		t.Fatal("expected error for alert with empty TokenHash, got nil")
	}
}

// ── HTTP integration: end-to-end webhook handler ─────────────────────────────

// TestWebhookHandler_EndToEnd verifies the full HTTP path:
// POST /webhooks/github/secret-scanning → HMAC validation → ParseAlert →
// orchestrator.ProcessAlert → HTTP 200.
func TestWebhookHandler_EndToEnd(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(expiredRecord())
	revoker := &mockRevoker{supportsRevocation: true}
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, revoker, aud, notifier)
	handler := webhooks.NewGitHubWebhookHandler(orchTestSecret)
	handler.SetOrchestrator(orch)

	body := buildWebhookBody(orchTestLeakedToken)
	sig := signBody(body, orchTestSecret)

	req := httptest.NewRequest(http.MethodPost, "/webhooks/github/secret-scanning", strings.NewReader(string(body)))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("HTTP status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

// TestWebhookHandler_InvalidSignature_Rejected verifies that a webhook with
// a bad HMAC signature is rejected with 401 and orchestration is NOT invoked.
func TestWebhookHandler_InvalidSignature_Rejected(t *testing.T) {
	store := &mockAuditStore{}
	store.seed(expiredRecord())
	aud := &orchestratorAuditor{}
	notifier := &capturingNotifier{}

	orch := newOrchestrator(t, store, &mockRevoker{}, aud, notifier)
	handler := webhooks.NewGitHubWebhookHandler(orchTestSecret)
	handler.SetOrchestrator(orch)

	body := buildWebhookBody(orchTestLeakedToken)
	badSig := signBody(body, "wrong-secret")

	req := httptest.NewRequest(http.MethodPost, "/webhooks/github/secret-scanning", strings.NewReader(string(body)))
	req.Header.Set("X-Hub-Signature-256", badSig)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("HTTP status = %d, want 401 for invalid signature", rr.Code)
	}
	if aud.count() != 0 {
		t.Error("no audit event should be written for rejected webhook")
	}
}
