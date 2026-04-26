package webhooks_test

// orchestrator_test.go — Tests for RotationHook integration in AlertOrchestrator.
//
// Tests added as part of T5 Part 1:
//   - NoHook: orchestrator without a hook falls back to revoker (baseline preserved)
//   - HookManagedCredential: hook consulted, binding found, TriggerRotation called, revoker skipped
//   - HookUnmanagedCredential: ErrNoBinding → revoker called, TriggerRotation not called
//   - HookTriggerFails: TriggerRotation returns error → revoker called as safety fallback
//   - SetRotationHook: swap hooks; assert only the current hook is called
//
// Mock patterns mirror github_orchestration_test.go: hand-rolled fakes, no mock framework.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/revocation"
	"github.com/agentkms/agentkms/internal/webhooks"
)

// ── fakeRotationHook ─────────────────────────────────────────────────────────

// fakeRotationHook is a hand-rolled test double for webhooks.RotationHook.
// Configure bindingName/bindingErr to control BindingForCredential.
// Configure triggerErr to control TriggerRotation.
type fakeRotationHook struct {
	mu sync.Mutex

	// BindingForCredential config
	bindingName string
	bindingErr  error // if non-nil, returned by BindingForCredential

	// TriggerRotation config
	triggerErr error // if non-nil, returned by TriggerRotation

	// call tracking
	bindingCallCount  int
	triggerCallCount  int
	lastBindingUUID   string
	lastTriggerUUID   string
}

func (h *fakeRotationHook) BindingForCredential(_ context.Context, credentialUUID string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bindingCallCount++
	h.lastBindingUUID = credentialUUID
	if h.bindingErr != nil {
		return "", h.bindingErr
	}
	return h.bindingName, nil
}

func (h *fakeRotationHook) TriggerRotation(_ context.Context, credentialUUID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.triggerCallCount++
	h.lastTriggerUUID = credentialUUID
	return h.triggerErr
}

func (h *fakeRotationHook) getBindingCallCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.bindingCallCount
}

func (h *fakeRotationHook) getTriggerCallCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.triggerCallCount
}

// ── shared test helpers ───────────────────────────────────────────────────────

const hookTestCredUUID = "550e8400-e29b-41d4-a716-446655440099"

// hookLiveRecord returns a CredentialRecord that is still active (InvalidatedAt zero).
// Uses a distinct UUID from the records in github_orchestration_test.go to avoid
// cross-test contamination if stores are ever shared.
func hookLiveRecord() webhooks.CredentialRecord {
	return webhooks.CredentialRecord{
		CredentialUUID:    hookTestCredUUID,
		ProviderTokenHash: "hook-test-token-hash",
		CredentialType:    "github-pat",
		IssuedAt:          time.Now().UTC().Add(-1 * time.Hour),
		InvalidatedAt:     time.Time{}, // zero == still live
		CallerID:          "hook-test-caller",
		RuleID:            "rule-hook-001",
	}
}

// buildHookOrchestrator constructs an AlertOrchestrator seeded with hookLiveRecord
// and a revoker that supports revocation. Returns the orchestrator, the mock revoker,
// and the mock audit store so tests can inspect call counts.
func buildHookOrchestrator(t *testing.T) (
	orch *webhooks.AlertOrchestrator,
	store *mockAuditStore,
	revoker *mockRevoker,
	aud *orchestratorAuditor,
	notifier *capturingNotifier,
) {
	t.Helper()
	store = &mockAuditStore{}
	store.seed(hookLiveRecord())
	revoker = &mockRevoker{
		supportsRevocation: true,
		revokeResult:       revocation.RevokeResult{Revoked: true},
	}
	aud = &orchestratorAuditor{}
	notifier = &capturingNotifier{}
	orch = webhooks.NewAlertOrchestrator(store, revoker, aud, notifier)
	return
}

// hookAlert returns a GitHubSecretAlert whose TokenHash matches hookLiveRecord.
func hookAlert() *webhooks.GitHubSecretAlert {
	return &webhooks.GitHubSecretAlert{
		TokenHash:   "hook-test-token-hash",
		SecretType:  "github_personal_access_token",
		Repository:  "acmecorp/hook-test-repo",
		AlertNumber: 42,
		DetectedAt:  time.Now().UTC(),
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestAlertOrchestrator_NoHook_FallsBackToRevoker verifies that when no
// RotationHook is registered (rotationHook == nil), a LiveRevokedBranch alert
// calls revoker.Revoke exactly once and baseline behavior is preserved.
func TestAlertOrchestrator_NoHook_FallsBackToRevoker(t *testing.T) {
	orch, _, revoker, aud, _ := buildHookOrchestrator(t)
	// No hook registered — nil by default.

	result, err := orch.ProcessAlert(context.Background(), hookAlert())
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}
	if result.Branch != webhooks.LiveRevokedBranch {
		t.Errorf("Branch = %v, want LiveRevokedBranch", result.Branch)
	}
	if !revoker.wasRevokeCalled() {
		t.Error("revoker.Revoke must be called when no RotationHook is registered")
	}
	// Audit event must be emitted by the existing OSS path.
	if aud.count() == 0 {
		t.Error("audit event must be written by the OSS revoker-only path")
	}
	ev, _ := aud.last()
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("audit Outcome = %q, want OutcomeSuccess", ev.Outcome)
	}
}

// TestAlertOrchestrator_HookManagedCredential_DelegatesToHook verifies that when
// a RotationHook is registered and BindingForCredential returns a binding name,
// TriggerRotation is called and revoker.Revoke is NOT called.
func TestAlertOrchestrator_HookManagedCredential_DelegatesToHook(t *testing.T) {
	orch, _, revoker, aud, _ := buildHookOrchestrator(t)

	hook := &fakeRotationHook{
		bindingName: "my-github-pat-binding",
		bindingErr:  nil, // managed credential
		triggerErr:  nil, // trigger succeeds
	}
	orch.SetRotationHook(hook)

	result, err := orch.ProcessAlert(context.Background(), hookAlert())
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}
	if result.Branch != webhooks.LiveRevokedBranch {
		t.Errorf("Branch = %v, want LiveRevokedBranch", result.Branch)
	}

	if hook.getBindingCallCount() != 1 {
		t.Errorf("BindingForCredential call count = %d, want 1", hook.getBindingCallCount())
	}
	if hook.getTriggerCallCount() != 1 {
		t.Errorf("TriggerRotation call count = %d, want 1", hook.getTriggerCallCount())
	}
	if revoker.wasRevokeCalled() {
		t.Error("revoker.Revoke must NOT be called when hook successfully triggers rotation")
	}
	// The OSS branch does NOT emit an audit event when the hook owns the lifecycle.
	// (The rotation hook emits its own audit chain.)
	if aud.count() != 0 {
		t.Errorf("OSS audit event count = %d, want 0 (hook owns audit chain)", aud.count())
	}
}

// TestAlertOrchestrator_HookUnmanagedCredential_FallsBack verifies that when
// BindingForCredential returns ErrNoBinding, TriggerRotation is NOT called and
// revoker.Revoke IS called (existing behavior preserved for unmanaged credentials).
func TestAlertOrchestrator_HookUnmanagedCredential_FallsBack(t *testing.T) {
	orch, _, revoker, _, _ := buildHookOrchestrator(t)

	hook := &fakeRotationHook{
		bindingErr: webhooks.ErrNoBinding,
	}
	orch.SetRotationHook(hook)

	result, err := orch.ProcessAlert(context.Background(), hookAlert())
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}
	if result.Branch != webhooks.LiveRevokedBranch {
		t.Errorf("Branch = %v, want LiveRevokedBranch", result.Branch)
	}

	if hook.getBindingCallCount() != 1 {
		t.Errorf("BindingForCredential call count = %d, want 1", hook.getBindingCallCount())
	}
	if hook.getTriggerCallCount() != 0 {
		t.Errorf("TriggerRotation call count = %d, want 0 (ErrNoBinding → skip rotation)", hook.getTriggerCallCount())
	}
	if !revoker.wasRevokeCalled() {
		t.Error("revoker.Revoke must be called when credential is not managed by any binding")
	}
}

// TestAlertOrchestrator_HookTriggerFails_FallsBack verifies the safety property:
// if TriggerRotation returns an error, revoker.Revoke IS called as a fallback.
// A broken hook must not leave the credential live and unrevoked.
func TestAlertOrchestrator_HookTriggerFails_FallsBack(t *testing.T) {
	orch, _, revoker, _, _ := buildHookOrchestrator(t)

	hook := &fakeRotationHook{
		bindingName: "my-github-pat-binding",
		bindingErr:  nil,                                                     // binding found
		triggerErr:  errors.New("rotation hook: orchestrator plugin crashed"), // trigger fails
	}
	orch.SetRotationHook(hook)

	result, err := orch.ProcessAlert(context.Background(), hookAlert())
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}
	if result.Branch != webhooks.LiveRevokedBranch {
		t.Errorf("Branch = %v, want LiveRevokedBranch", result.Branch)
	}

	if hook.getTriggerCallCount() != 1 {
		t.Errorf("TriggerRotation call count = %d, want 1 (must be attempted before fallback)", hook.getTriggerCallCount())
	}

	// Safety property: failing hook must not leave credential unrevoked.
	if !revoker.wasRevokeCalled() {
		t.Error("SAFETY: revoker.Revoke must be called as fallback when TriggerRotation fails")
	}

	// OrchestratorError should reflect the hook failure.
	if result.OrchestratorError == nil {
		t.Error("OrchestratorError should be set when hook trigger fails")
	}
}

// TestSetRotationHook verifies that SetRotationHook replaces the active hook:
// the previously registered hook is no longer called after replacement.
func TestSetRotationHook(t *testing.T) {
	orch, store, _, _, _ := buildHookOrchestrator(t)

	hookA := &fakeRotationHook{
		bindingName: "binding-a",
		bindingErr:  nil,
		triggerErr:  nil,
	}
	hookB := &fakeRotationHook{
		bindingName: "binding-b",
		bindingErr:  nil,
		triggerErr:  nil,
	}

	// Register hookA, process one alert.
	orch.SetRotationHook(hookA)
	_, err := orch.ProcessAlert(context.Background(), hookAlert())
	if err != nil {
		t.Fatalf("first ProcessAlert error: %v", err)
	}
	if hookA.getTriggerCallCount() != 1 {
		t.Errorf("hookA TriggerRotation count = %d, want 1", hookA.getTriggerCallCount())
	}
	if hookB.getTriggerCallCount() != 0 {
		t.Errorf("hookB TriggerRotation count = %d, want 0 before registration", hookB.getTriggerCallCount())
	}

	// Re-seed the store so the second ProcessAlert sees a live (not invalidated) credential.
	store.seed(webhooks.CredentialRecord{
		CredentialUUID:    "550e8400-e29b-41d4-a716-446655440098",
		ProviderTokenHash: "hook-test-token-hash-b",
		CredentialType:    "github-pat",
		IssuedAt:          time.Now().UTC().Add(-30 * time.Minute),
		InvalidatedAt:     time.Time{},
		CallerID:          "hook-test-caller",
		RuleID:            "rule-hook-002",
	})

	// Replace with hookB, process a second alert against the second record.
	orch.SetRotationHook(hookB)
	alert2 := &webhooks.GitHubSecretAlert{
		TokenHash:  "hook-test-token-hash-b",
		DetectedAt: time.Now().UTC(),
	}
	_, err = orch.ProcessAlert(context.Background(), alert2)
	if err != nil {
		t.Fatalf("second ProcessAlert error: %v", err)
	}

	// hookA must not receive any additional calls after replacement.
	if hookA.getTriggerCallCount() != 1 {
		t.Errorf("hookA TriggerRotation count = %d after replacement, want still 1", hookA.getTriggerCallCount())
	}
	// hookB must have been called for the second alert.
	if hookB.getTriggerCallCount() != 1 {
		t.Errorf("hookB TriggerRotation count = %d, want 1 after registration", hookB.getTriggerCallCount())
	}
}
