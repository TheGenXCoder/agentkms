package audit_test

// FO-B4: Failing tests for InvalidationReason enum validation.
//
// These tests define the acceptance criteria:
//   1. Constants exist with correct string values
//   2. Empty InvalidationReason is accepted by Validate()
//   3. Each defined constant is accepted by Validate()
//   4. Unknown/arbitrary reasons are rejected by Validate()
//   5. Validation is case-sensitive (no accidental uppercase acceptance)

import (
	"strings"
	"testing"

	"github.com/agentkms/agentkms/internal/audit"
)

// ── 1. Constants defined with expected values ────────────────────────────────

func TestInvalidationReason_Constants_Defined(t *testing.T) {
	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{"ReasonExpired", audit.ReasonExpired, "expired"},
		{"ReasonRevokedUser", audit.ReasonRevokedUser, "revoked-user"},
		{"ReasonRevokedAdmin", audit.ReasonRevokedAdmin, "revoked-admin"},
		{"ReasonRevokedLeak", audit.ReasonRevokedLeak, "revoked-leak"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("constant %s = %q; want %q", tt.name, tt.got, tt.expected)
			}
		})
	}
}

// ── 2. Empty InvalidationReason accepted ─────────────────────────────────────

func TestValidate_EmptyInvalidationReason_Accepted(t *testing.T) {
	ev := validEventWithReason(t, "")
	if err := ev.Validate(); err != nil {
		t.Fatalf("Validate() rejected empty InvalidationReason: %v", err)
	}
}

// ── 3. Valid reasons accepted ────────────────────────────────────────────────

func TestValidate_ValidReasons_Accepted(t *testing.T) {
	reasons := []string{
		audit.ReasonExpired,
		audit.ReasonRevokedUser,
		audit.ReasonRevokedAdmin,
		audit.ReasonRevokedLeak,
	}
	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			ev := validEventWithReason(t, reason)
			if err := ev.Validate(); err != nil {
				t.Errorf("Validate() rejected valid reason %q: %v", reason, err)
			}
		})
	}
}

// ── 4. Unknown reason rejected ───────────────────────────────────────────────

func TestValidate_UnknownReason_Rejected(t *testing.T) {
	ev := validEventWithReason(t, "some-garbage")
	err := ev.Validate()
	if err == nil {
		t.Fatal("Validate() accepted unknown InvalidationReason \"some-garbage\"; want error")
	}
	if !strings.Contains(err.Error(), "InvalidationReason") &&
		!strings.Contains(err.Error(), "invalidation") {
		t.Errorf("error message should mention InvalidationReason, got: %v", err)
	}
}

// ── 5. Case-sensitive — uppercase variant rejected ───────────────────────────

func TestValidate_CaseSensitive(t *testing.T) {
	ev := validEventWithReason(t, "Expired") // capital E
	err := ev.Validate()
	if err == nil {
		t.Fatal("Validate() accepted \"Expired\" (capital E); want error — reasons are lowercase only")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// validEventWithReason builds a minimal valid AuditEvent and sets its
// InvalidationReason to the given value.
func validEventWithReason(t *testing.T, reason string) audit.AuditEvent {
	t.Helper()
	ev, err := audit.New()
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	ev.CallerID = "test-user@test-team"
	ev.TeamID = "test-team"
	ev.Operation = audit.OperationSign
	ev.Outcome = audit.OutcomeSuccess
	ev.Environment = "dev"
	ev.InvalidationReason = reason
	return ev
}
