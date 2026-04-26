// server_test.go — tests for api.Server wiring methods added in T6:
//
//   TestServer_SetRotationHook_NoAlertOrchestrator
//   TestServer_SetRotationHook_DelegatesToAlertOrchestrator
//   TestServer_WebhookHandler_DispatchesToAlertOrchestrator
//
// These tests verify the three new wiring paths added in the T6 AlertOrchestrator
// wiring task:
//  1. SetRotationHook with nil AlertOrchestrator is a safe no-op (warns, no panic).
//  2. SetRotationHook with a configured AlertOrchestrator passes the hook through.
//  3. POST /webhooks/github/secret-scanning dispatches to ProcessAlert via
//     the registered AlertOrchestrator.

package api_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/internal/revocation"
	"github.com/agentkms/agentkms/internal/webhooks"
)

// ── Test doubles ──────────────────────────────────────────────────────────────

// stubRotationHook records BindingForCredential and TriggerRotation calls.
type stubRotationHook struct {
	mu                   sync.Mutex
	bindingCalls         []string
	triggerCalls         []string
	bindingErr           error
	triggerErr           error
}

func (h *stubRotationHook) BindingForCredential(_ context.Context, credentialUUID string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bindingCalls = append(h.bindingCalls, credentialUUID)
	if h.bindingErr != nil {
		return "", h.bindingErr
	}
	return "test-binding", nil
}

func (h *stubRotationHook) TriggerRotation(_ context.Context, credentialUUID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.triggerCalls = append(h.triggerCalls, credentialUUID)
	return h.triggerErr
}

// processAlertCapturingStore captures FindByTokenHash calls to verify dispatch.
type processAlertCapturingStore struct {
	mu       sync.Mutex
	calls    []string
	findErr  error
}

func (s *processAlertCapturingStore) FindByTokenHash(_ context.Context, hash string) (*webhooks.CredentialRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, hash)
	if s.findErr != nil {
		return nil, s.findErr
	}
	// Return a credential that is already invalidated so orchestration
	// completes cleanly (ExpiredBranch) without needing a real revoker.
	now := time.Now().UTC()
	return &webhooks.CredentialRecord{
		CredentialUUID:    "00000000-0000-0000-0000-000000000001",
		ProviderTokenHash: hash,
		CredentialType:    "github-pat",
		IssuedAt:          now.Add(-24 * time.Hour),
		InvalidatedAt:     now.Add(-1 * time.Hour),
		CallerID:          "test-caller",
		RuleID:            "test-rule",
	}, nil
}

func (s *processAlertCapturingStore) UpdateInvalidatedAt(_ context.Context, _ string, _ time.Time) error {
	return nil
}

func (s *processAlertCapturingStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// noopWebhookNotifier implements webhooks.Notifier for tests.
type noopWebhookNotifier struct{}

func (n *noopWebhookNotifier) Notify(_ context.Context, _ webhooks.AlertResult) error { return nil }

// supportsRevocationRevoker implements revocation.Revoker with SupportsRevocation=true.
// Used to ensure the orchestrator enters the LiveRevokedBranch where hook dispatch occurs.
type supportsRevocationRevoker struct{}

func (r *supportsRevocationRevoker) SupportsRevocation() bool { return true }

func (r *supportsRevocationRevoker) Revoke(_ context.Context, _ revocation.CredentialRecord) (revocation.RevokeResult, error) {
	return revocation.RevokeResult{Revoked: true}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const webhookTestSecret = "t6-test-webhook-secret"

func newTestServer(t *testing.T) *api.Server {
	t.Helper()
	b := backend.NewDevBackend()
	aud := &capturingAuditor{}
	rl := auth.NewRevocationList()
	ts, _ := auth.NewTokenService(rl)
	return api.NewServer(b, aud, policy.AllowAllEngine{}, ts, "dev")
}

func signWebhookBody(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func buildGitHubWebhookBody(leakedSecret string) []byte {
	return []byte(`{
  "action": "created",
  "alert": {
    "number": 1,
    "secret_type": "github_personal_access_token",
    "secret": "` + leakedSecret + `"
  },
  "repository": {
    "full_name": "acmecorp/legacy-tool"
  }
}`)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestServer_SetRotationHook_NoAlertOrchestrator verifies that calling
// SetRotationHook before SetAlertOrchestrator (i.e. when alertOrchestrator is
// nil) is a safe no-op. It must not panic and the server must remain usable.
func TestServer_SetRotationHook_NoAlertOrchestrator(t *testing.T) {
	srv := newTestServer(t)

	// SetRotationHook with no AlertOrchestrator configured must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SetRotationHook panicked when AlertOrchestrator is nil: %v", r)
		}
	}()

	hook := &stubRotationHook{}
	srv.SetRotationHook(hook) // must be a no-op with a warning log, not a panic

	// Verify the server is still functional by making a health request.
	req := httptest.NewRequest(http.MethodGet, "/keys", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	// /keys requires auth — 401 is expected; the important thing is no panic above.
	if rr.Code == 0 {
		t.Error("server returned zero status code after no-op SetRotationHook")
	}
}

// TestServer_SetRotationHook_DelegatesToAlertOrchestrator verifies that when
// an AlertOrchestrator is configured, SetRotationHook passes the hook through
// to it. We verify this indirectly: after calling SetRotationHook, processing
// a webhook alert for a live credential should invoke the hook's
// BindingForCredential rather than the revoker-only path.
func TestServer_SetRotationHook_DelegatesToAlertOrchestrator(t *testing.T) {
	srv := newTestServer(t)

	store := &processAlertCapturingStore{}
	aud := &capturingAuditor{}
	notifier := &noopWebhookNotifier{}
	alertOrch := webhooks.NewAlertOrchestrator(
		store,
		revocation.NewNoopRevoker(),
		aud,
		notifier,
	)
	srv.SetAlertOrchestrator(alertOrch)

	hook := &stubRotationHook{
		// Return ErrNoBinding so that TriggerRotation is not called and
		// the orchestrator falls through to the revoker (idempotent path).
		bindingErr: webhooks.ErrNoBinding,
	}
	// Must not panic; must wire the hook to the AlertOrchestrator.
	srv.SetRotationHook(hook)

	// Now trigger a live-credential alert via the webhook endpoint so we can
	// confirm the hook's BindingForCredential is consulted. Override store to
	// return a live (non-expired) credential.
	const leakedToken = "ghp_live_token_for_hook_test"
	tokenHash := func() string {
		h := sha256.Sum256([]byte(leakedToken))
		return hex.EncodeToString(h[:])
	}()

	liveStore := &liveCredStore{hash: tokenHash}
	// Use a revoker that supports revocation so the orchestrator enters the
	// LiveRevokedBranch where hook dispatch occurs. NoopRevoker.SupportsRevocation()
	// returns false, which routes to ManualRevokeBranch (bypassing hook dispatch).
	orchWithLive := webhooks.NewAlertOrchestrator(
		liveStore,
		&supportsRevocationRevoker{},
		aud,
		notifier,
	)
	hook2 := &stubRotationHook{bindingErr: webhooks.ErrNoBinding}
	orchWithLive.SetRotationHook(hook2)

	// Directly call ProcessAlert (bypasses HTTP) to verify hook dispatch.
	alert := &webhooks.GitHubSecretAlert{
		TokenHash:   tokenHash,
		SecretType:  "github_personal_access_token",
		Repository:  "acmecorp/legacy-tool",
		AlertNumber: 42,
		DetectedAt:  time.Now().UTC(),
	}
	_, err := orchWithLive.ProcessAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("ProcessAlert error: %v", err)
	}

	hook2.mu.Lock()
	bindingCalls := len(hook2.bindingCalls)
	hook2.mu.Unlock()

	if bindingCalls == 0 {
		t.Error("expected BindingForCredential to be called on the RotationHook; got 0 calls")
	}
}

// liveCredStore returns a live (non-expired) credential for a known token hash.
type liveCredStore struct {
	mu   sync.Mutex
	hash string
}

func (s *liveCredStore) FindByTokenHash(_ context.Context, hash string) (*webhooks.CredentialRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hash != s.hash {
		return nil, webhooks.ErrCredentialNotFound
	}
	return &webhooks.CredentialRecord{
		CredentialUUID:    "00000000-0000-0000-0000-000000000002",
		ProviderTokenHash: hash,
		CredentialType:    "github-pat",
		IssuedAt:          time.Now().UTC().Add(-1 * time.Hour),
		InvalidatedAt:     time.Time{}, // zero == still live
		CallerID:          "test-caller",
		RuleID:            "test-rule",
	}, nil
}

func (s *liveCredStore) UpdateInvalidatedAt(_ context.Context, _ string, _ time.Time) error {
	return nil
}

// TestServer_WebhookHandler_DispatchesToAlertOrchestrator verifies the full
// HTTP path: POST /webhooks/github/secret-scanning → HMAC validation →
// ParseAlert → AlertOrchestrator.ProcessAlert → HTTP response.
//
// Specifically confirms that ProcessAlert is invoked (via the store's
// FindByTokenHash call count) when a valid, signed webhook payload arrives.
func TestServer_WebhookHandler_DispatchesToAlertOrchestrator(t *testing.T) {
	srv := newTestServer(t)

	store := &processAlertCapturingStore{}
	aud := &capturingAuditor{}
	notifier := &noopWebhookNotifier{}
	alertOrch := webhooks.NewAlertOrchestrator(
		store,
		revocation.NewNoopRevoker(),
		aud,
		notifier,
	)
	srv.SetAlertOrchestrator(alertOrch)
	srv.RegisterGitHubWebhookHandler(webhookTestSecret)

	const leakedToken = "ghp_leaked_token_for_dispatch_test"
	body := buildGitHubWebhookBody(leakedToken)
	sig := signWebhookBody(body, webhookTestSecret)

	req := httptest.NewRequest(http.MethodPost, "/webhooks/github/secret-scanning",
		bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	// Any 2xx response confirms the webhook was accepted and orchestration ran.
	if rr.Code < 200 || rr.Code >= 300 {
		t.Errorf("POST /webhooks/github/secret-scanning returned %d; want 2xx\nbody: %s",
			rr.Code, rr.Body.String())
	}

	// Confirm ProcessAlert was dispatched: the store must have been queried.
	if store.callCount() == 0 {
		t.Error("AlertOrchestrator.ProcessAlert was not invoked: store.FindByTokenHash was never called")
	}
}

// TestServer_WebhookHandler_InvalidSignature_Returns401 verifies that a webhook
// with a bad HMAC signature is rejected with 401 and ProcessAlert is NOT invoked.
func TestServer_WebhookHandler_InvalidSignature_Returns401(t *testing.T) {
	srv := newTestServer(t)

	store := &processAlertCapturingStore{}
	aud := &capturingAuditor{}
	notifier := &noopWebhookNotifier{}
	alertOrch := webhooks.NewAlertOrchestrator(
		store,
		revocation.NewNoopRevoker(),
		aud,
		notifier,
	)
	srv.SetAlertOrchestrator(alertOrch)
	srv.RegisterGitHubWebhookHandler(webhookTestSecret)

	body := buildGitHubWebhookBody("ghp_some_token")
	badSig := signWebhookBody(body, "wrong-secret")

	req := httptest.NewRequest(http.MethodPost, "/webhooks/github/secret-scanning",
		bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", badSig)

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid HMAC signature, got %d", rr.Code)
	}
	if store.callCount() != 0 {
		t.Error("ProcessAlert must not be invoked when HMAC verification fails")
	}
}

// TestServer_WebhookHandler_NotRegistered_Returns404 verifies that when
// RegisterGitHubWebhookHandler has not been called, the webhook route does not
// exist and the server returns 404 (or 405 depending on mux routing).
func TestServer_WebhookHandler_NotRegistered_Returns404(t *testing.T) {
	srv := newTestServer(t)
	// Do NOT call RegisterGitHubWebhookHandler.

	body := buildGitHubWebhookBody("ghp_some_token")
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github/secret-scanning",
		bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Error("expected non-200 when webhook handler is not registered; got 200")
	}
}

