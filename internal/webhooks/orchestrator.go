package webhooks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/revocation"
)

// ErrCredentialNotFound is returned by AuditStore.FindByTokenHash when no
// audit record matches the given token hash.
var ErrCredentialNotFound = errors.New("webhooks: credential not found in audit ledger")

// CredentialRecord is a type alias to revocation.CredentialRecord.
// Using an alias avoids a circular import while keeping a single canonical type.
type CredentialRecord = revocation.CredentialRecord

// AuditStore is the read/write interface the orchestrator uses to look up
// credentials and update their invalidation state.
//
// Implementations must be safe for durable backends (disk, DB, NDJSON) as well
// as in-memory stores. The orchestrator never relies on pointer-mutation of a
// returned record for idempotency; it always calls UpdateInvalidatedAt explicitly
// so that the durable store can persist the change before an audit event is
// emitted.
type AuditStore interface {
	// FindByTokenHash returns the CredentialRecord whose ProviderTokenHash
	// matches hash. Returns ErrCredentialNotFound if not found.
	// Implementations must NOT assume the caller will mutate the returned value
	// to persist state — use UpdateInvalidatedAt for that.
	FindByTokenHash(ctx context.Context, hash string) (*CredentialRecord, error)

	// UpdateInvalidatedAt persists the InvalidatedAt timestamp for the
	// credential identified by credentialUUID. Must be called (and succeed)
	// before emitting the audit event so that durable stores reflect the
	// change even if the process crashes between revocation and audit logging.
	UpdateInvalidatedAt(ctx context.Context, credentialUUID string, at time.Time) error
}

// Notifier sends human-readable alerts after orchestration completes.
// v0.3.1 ships ConsoleNotifier only. Slack integration is v0.4.
type Notifier interface {
	Notify(ctx context.Context, result AlertResult) error
}

// AlertBranch identifies which of the three orchestration branches was taken.
type AlertBranch int

const (
	// ExpiredBranch: credential was already past InvalidatedAt at detection time.
	// Action: auto-close, tag "detected_after_expiry", notify without escalation.
	ExpiredBranch AlertBranch = iota

	// LiveRevokedBranch: credential was still active; provider revocation succeeded.
	// Action: revoke at provider, set InvalidatedAt, tag "revoked_on_detection", escalate.
	LiveRevokedBranch

	// ManualRevokeBranch: credential was still active but provider has no revoke API.
	// Action: emit high-priority alert with manual revocation URL.
	ManualRevokeBranch
)

// AlertResult is the structured output of AlertOrchestrator.ProcessAlert.
// The HTTP handler records it and writes the HTTP response.
type AlertResult struct {
	Branch              AlertBranch
	CredentialUUID      string
	TagsApplied         []string
	ManualRevocationURL string  // non-empty only for ManualRevokeBranch
	Escalated           bool    // true when on-call was paged
	OrchestratorError   error   // non-nil if any step failed non-fatally
}

// AlertOrchestrator implements the three-branch decision tree for leaked
// credential response, as described in Part 6 of the KPM blog series.
//
// Call chain:
//
//	ProcessAlert
//	  → AuditStore.FindByTokenHash
//	  → branch on InvalidatedAt / SupportsRevocation
//	  → Revoker.Revoke (Branch 2 only)
//	  → audit.Auditor.Log
//	  → Notifier.Notify
type AlertOrchestrator struct {
	store    AuditStore
	revoker  revocation.Revoker
	auditor  audit.Auditor
	notifier Notifier
}

// NewAlertOrchestrator constructs an AlertOrchestrator with the given dependencies.
func NewAlertOrchestrator(
	store AuditStore,
	revoker revocation.Revoker,
	auditor audit.Auditor,
	notifier Notifier,
) *AlertOrchestrator {
	return &AlertOrchestrator{
		store:    store,
		revoker:  revoker,
		auditor:  auditor,
		notifier: notifier,
	}
}

// ProcessAlert executes the three-branch orchestration flow for a GitHub
// secret-scanning alert:
//
//	Branch 1 (ExpiredBranch): credential already expired → auto-close, tag
//	  "detected_after_expiry", audit with ReasonExpired+OutcomeSuccess, no escalation.
//
//	Branch 2 (LiveRevokedBranch): credential still live, revoker supports
//	  programmatic revocation → revoke at provider, set InvalidatedAt (idempotency),
//	  tag "revoked_on_detection", audit with ReasonRevokedLeak+OutcomeSuccess, escalate.
//
//	Branch 3 (ManualRevokeBranch): credential still live but revoker cannot revoke
//	  programmatically → emit high-priority alert with ManualRevocationURL,
//	  audit with ReasonRevokedLeak+OutcomeError, set Escalated=true.
//
// Idempotency: if ProcessAlert is called twice for the same alert, the second
// call finds InvalidatedAt already set (mutated by the first call) and routes
// to ExpiredBranch, avoiding a double-revoke.
//
// Error handling:
//   - Empty TokenHash → immediate error, no audit.
//   - Credential not found → error + notification (unknown token alert).
//   - Provider API down → OrchestratorError set, audit still written.
func (o *AlertOrchestrator) ProcessAlert(ctx context.Context, alert *GitHubSecretAlert) (AlertResult, error) {
	// Input validation.
	if alert.TokenHash == "" {
		return AlertResult{}, errors.New("webhooks: ProcessAlert: alert.TokenHash is empty")
	}

	// Look up the credential in the audit ledger.
	record, err := o.store.FindByTokenHash(ctx, alert.TokenHash)
	if err != nil {
		// Credential not in ledger — notify (unknown token) and return the error.
		result := AlertResult{OrchestratorError: err}
		_ = o.notifier.Notify(ctx, result)
		if errors.Is(err, ErrCredentialNotFound) {
			return result, err
		}
		return result, fmt.Errorf("webhooks: ProcessAlert: audit store lookup failed: %w", err)
	}

	// ── Branch routing ────────────────────────────────────────────────────────

	// Branch 1: credential already invalidated (expired or previously revoked).
	if !record.InvalidatedAt.IsZero() {
		return o.handleExpiredBranch(ctx, record)
	}

	// Branch 2 / 3: credential is still live.
	if o.revoker.SupportsRevocation() {
		return o.handleLiveRevokedBranch(ctx, record)
	}
	return o.handleManualRevokeBranch(ctx, record)
}

// handleExpiredBranch processes Branch 1: credential was already invalidated.
func (o *AlertOrchestrator) handleExpiredBranch(ctx context.Context, record *CredentialRecord) (AlertResult, error) {
	result := AlertResult{
		Branch:         ExpiredBranch,
		CredentialUUID: record.CredentialUUID,
		TagsApplied:    []string{"detected_after_expiry"},
		Escalated:      false,
	}

	ev, err := audit.New()
	if err == nil {
		ev.Operation          = audit.OperationRevoke
		ev.CredentialUUID     = record.CredentialUUID
		ev.CredentialType     = record.CredentialType
		ev.CallerID           = record.CallerID
		ev.RuleID             = record.RuleID
		ev.ProviderTokenHash  = record.ProviderTokenHash
		ev.InvalidationReason = audit.ReasonExpired
		ev.Outcome            = audit.OutcomeSuccess
		ev.Anomalies          = []string{"detected_after_expiry"}
		_ = o.auditor.Log(ctx, ev)
	}

	_ = o.notifier.Notify(ctx, result)
	return result, nil
}

// handleLiveRevokedBranch processes Branch 2: live credential, provider supports revocation.
func (o *AlertOrchestrator) handleLiveRevokedBranch(ctx context.Context, record *CredentialRecord) (AlertResult, error) {
	result := AlertResult{
		Branch:         LiveRevokedBranch,
		CredentialUUID: record.CredentialUUID,
		TagsApplied:    []string{"revoked_on_detection"},
		Escalated:      true,
	}

	revokeResult, revokeErr := o.revoker.Revoke(ctx, *record)

	outcome := audit.OutcomeSuccess
	var orchestratorErr error

	if revokeErr != nil || revokeResult.ProviderError != nil {
		// Provider API unreachable or returned a non-fatal error.
		outcome = audit.OutcomeError
		if revokeErr != nil {
			orchestratorErr = revokeErr
		} else {
			orchestratorErr = revokeResult.ProviderError
		}
		result.OrchestratorError = orchestratorErr
	} else {
		// Revocation succeeded — persist InvalidatedAt via the store interface
		// BEFORE emitting the audit event. This ensures durable backends (disk,
		// DB, NDJSON) commit the state change so a second webhook arriving for
		// the same credential will see InvalidatedAt != zero from a fresh read
		// and route to ExpiredBranch — not re-enter the live-revoked branch.
		// Pointer-mutation of the returned record is NOT sufficient for durable
		// stores because FindByTokenHash deserialises a fresh struct on each call.
		now := time.Now().UTC()
		if updateErr := o.store.UpdateInvalidatedAt(ctx, record.CredentialUUID, now); updateErr != nil {
			// Non-fatal: log the update failure but continue to emit the audit event.
			orchestratorErr = fmt.Errorf("webhooks: UpdateInvalidatedAt failed: %w", updateErr)
			result.OrchestratorError = orchestratorErr
			outcome = audit.OutcomeError
		}
	}

	ev, err := audit.New()
	if err == nil {
		ev.Operation          = audit.OperationRevoke
		ev.CredentialUUID     = record.CredentialUUID
		ev.CredentialType     = record.CredentialType
		ev.CallerID           = record.CallerID
		ev.RuleID             = record.RuleID
		ev.ProviderTokenHash  = record.ProviderTokenHash
		ev.InvalidationReason = audit.ReasonRevokedLeak
		ev.Outcome            = outcome
		ev.Anomalies          = []string{"revoked_on_detection"}
		if orchestratorErr != nil {
			ev.ErrorDetail = "provider revocation failed"
		}
		_ = o.auditor.Log(ctx, ev)
	}

	_ = o.notifier.Notify(ctx, result)
	return result, nil
}

// handleManualRevokeBranch processes Branch 3: live credential, no programmatic revocation.
func (o *AlertOrchestrator) handleManualRevokeBranch(ctx context.Context, record *CredentialRecord) (AlertResult, error) {
	// Construct a manual revocation URL. For GitHub tokens, this is the
	// tokens settings page. For other providers this is the generic fallback.
	manualURL := manualRevocationURL(record)

	result := AlertResult{
		Branch:              ManualRevokeBranch,
		CredentialUUID:      record.CredentialUUID,
		TagsApplied:         []string{"manual_revoke_required"},
		ManualRevocationURL: manualURL,
		Escalated:           true,
	}

	ev, err := audit.New()
	if err == nil {
		ev.Operation          = audit.OperationRevoke
		ev.CredentialUUID     = record.CredentialUUID
		ev.CredentialType     = record.CredentialType
		ev.CallerID           = record.CallerID
		ev.RuleID             = record.RuleID
		ev.ProviderTokenHash  = record.ProviderTokenHash
		ev.InvalidationReason = audit.ReasonRevokedLeak
		ev.Outcome            = audit.OutcomeError
		ev.Anomalies          = []string{"manual_revoke_required"}
		ev.ErrorDetail        = "provider does not support programmatic revocation"
		_ = o.auditor.Log(ctx, ev)
	}

	_ = o.notifier.Notify(ctx, result)
	return result, nil
}

// manualRevocationURL returns the direct URL a human should visit to revoke
// the credential when programmatic revocation is unavailable.
func manualRevocationURL(record *CredentialRecord) string {
	switch record.CredentialType {
	case "github-pat":
		// GitHub tokens settings page — the operator finds and deletes the token here.
		return "https://github.com/settings/tokens"
	case "aws-sts":
		// AWS IAM console — the operator attaches a deny-all policy to the role.
		return "https://console.aws.amazon.com/iam/"
	default:
		return "https://github.com/settings/tokens"
	}
}

// ── HTTP Handler wiring ───────────────────────────────────────────────────────

// SetOrchestrator wires an AlertOrchestrator into the GitHubWebhookHandler.
// Must be called before the handler is registered on any HTTP mux.
func (h *GitHubWebhookHandler) SetOrchestrator(orch *AlertOrchestrator) {
	h.orchestrator = orch
}

// ServeHTTP implements http.Handler for GitHub secret scanning webhooks.
//
// Flow:
//  1. Read and buffer the request body.
//  2. Validate the HMAC-SHA256 signature (X-Hub-Signature-256 header).
//  3. Parse the JSON payload via ParseAlert.
//  4. Invoke the orchestrator's ProcessAlert.
//  5. Write an appropriate HTTP response.
//
// GitHub retries webhook deliveries on non-2xx responses. The handler returns:
//   - 401 Unauthorized  — HMAC validation failed.
//   - 422 Unprocessable — payload parsed but orchestration rejected it (bad alert).
//   - 202 Accepted      — webhook received but credential not in audit ledger
//     (unknown token alert forwarded to notifier; no retryable error).
//   - 200 OK            — orchestration completed (including partial failures
//     where OrchestratorError is set; GitHub must not retry these).
func (h *GitHubWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	sig := r.Header.Get("X-Hub-Signature-256")
	alert, err := h.ParseAlert(body, sig)
	if err != nil {
		// HMAC failure or JSON parse failure.
		// Return 401 for signature errors so tests can distinguish auth vs parse.
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
		return
	}

	if h.orchestrator == nil {
		// No orchestrator wired — still accept the webhook (200) but do nothing.
		w.WriteHeader(http.StatusOK)
		return
	}

	result, orchErr := h.orchestrator.ProcessAlert(r.Context(), alert)
	_ = result
	if orchErr != nil {
		if errors.Is(orchErr, ErrCredentialNotFound) {
			// Credential not in ledger — per design spec return 202 Accepted.
			// GitHub will not retry 2xx responses. 202 signals "received but not
			// actionable" which is semantically correct for an unknown token alert.
			w.WriteHeader(http.StatusAccepted)
			return
		}
		// Orchestration failed in a way GitHub should retry (e.g. audit store down).
		http.Error(w, "orchestration error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
