package audit_test

// F-09: tests for AuditEvent.Validate() and its integration with MultiAuditor.
//
// Test categories:
//   1. Validate — clean events pass
//   2. Validate — PEM delimiters rejected
//   3. Validate — hex key-length blobs rejected
//   4. Validate — boundary cases (63 vs 64 hex chars, mixed case)
//   5. MultiAuditor — valid event written to sinks
//   6. MultiAuditor — invalid event rejected, zero sinks called (fail closed)

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/agentkms/agentkms/internal/audit"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// hex64 is exactly 64 lowercase hex characters (32 bytes) — the minimum
// length that Validate treats as a possible key-material blob.
const hex64 = "a3f4b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3"

// hex63 is 63 hex characters — one below the threshold; must NOT trigger.
const hex63 = "a3f4b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a"

// hex128 is 128 hex characters (64 bytes, e.g. an Ed25519 private key).
const hex128 = hex64 + hex64

func eventWithDenyReason(t *testing.T, reason string) audit.AuditEvent {
	t.Helper()
	ev, err := audit.New()
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	ev.CallerID = "test@team"
	ev.TeamID = "team"
	ev.Operation = audit.OperationSign
	ev.Outcome = audit.OutcomeDenied
	ev.DenyReason = reason
	return ev
}

// ── 1. Clean events pass ──────────────────────────────────────────────────────

func TestValidate_EmptyDenyReason(t *testing.T) {
	ev := eventWithDenyReason(t, "")
	if err := ev.Validate(); err != nil {
		t.Fatalf("expected nil for empty DenyReason, got: %v", err)
	}
}

func TestValidate_LegitimateTextPasses(t *testing.T) {
	cases := []string{
		"policy: identity not permitted for key namespace",
		"rate limit exceeded: 100 req/min",
		"token expired",
		"operation not permitted outside business hours",
		"key prefix payments/ not allowed for this identity",
		"caller team-a may not access keys owned by team-b",
	}
	for _, reason := range cases {
		ev := eventWithDenyReason(t, reason)
		if err := ev.Validate(); err != nil {
			t.Errorf("Validate(%q) returned unexpected error: %v", reason, err)
		}
	}
}

func TestValidate_SuccessOutcomeNoDenyReason(t *testing.T) {
	ev, err := audit.New()
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	ev.Operation = audit.OperationSign
	ev.Outcome = audit.OutcomeSuccess
	// DenyReason intentionally empty on success.
	if err := ev.Validate(); err != nil {
		t.Fatalf("expected nil for success event, got: %v", err)
	}
}

// ── 2. PEM delimiters rejected ────────────────────────────────────────────────

func TestValidate_DenyReason_PEMBeginHeader(t *testing.T) {
	reason := "-----BEGIN EC PRIVATE KEY----- MHQCAQEEILnvPU..."
	ev := eventWithDenyReason(t, reason)
	err := ev.Validate()
	if err == nil {
		t.Fatal("expected Validate to reject DenyReason containing PEM BEGIN header")
	}
	// Error message must not echo the PEM content verbatim.
	if strings.Contains(err.Error(), "MHQCAQEEILnvPU") {
		t.Fatalf("error message echoes PEM body: %q", err.Error())
	}
}

func TestValidate_DenyReason_PEMEndHeader(t *testing.T) {
	reason := "some context -----END RSA PRIVATE KEY----- done"
	ev := eventWithDenyReason(t, reason)
	if err := ev.Validate(); err == nil {
		t.Fatal("expected Validate to reject DenyReason containing PEM END header")
	}
}

func TestValidate_DenyReason_PEMPublicKey_AlsoRejected(t *testing.T) {
	// Public key PEM headers are also rejected: their presence in a deny
	// reason is anomalous and could indicate cert material being included.
	reason := "key: -----BEGIN PUBLIC KEY----- MFkwEwYH..."
	ev := eventWithDenyReason(t, reason)
	if err := ev.Validate(); err == nil {
		t.Fatal("expected Validate to reject PEM PUBLIC KEY header")
	}
}

// ── 3. Hex key-length blobs rejected ─────────────────────────────────────────

func TestValidate_DenyReason_Hex64Chars_Rejected(t *testing.T) {
	// Exactly 64 hex chars = 32 bytes = minimum key-material threshold.
	ev := eventWithDenyReason(t, "key bytes: "+hex64)
	if err := ev.Validate(); err == nil {
		t.Fatal("expected Validate to reject DenyReason with 64-char hex blob")
	}
}

func TestValidate_DenyReason_Hex128Chars_Rejected(t *testing.T) {
	// 128 hex chars = 64 bytes (e.g. Ed25519 private key).
	ev := eventWithDenyReason(t, hex128)
	if err := ev.Validate(); err == nil {
		t.Fatal("expected Validate to reject DenyReason with 128-char hex blob")
	}
}

func TestValidate_DenyReason_HexEmbeddedInText_Rejected(t *testing.T) {
	// Key material embedded mid-sentence — still caught.
	reason := "denied because key " + hex64 + " is not registered"
	ev := eventWithDenyReason(t, reason)
	if err := ev.Validate(); err == nil {
		t.Fatal("expected Validate to reject hex blob embedded in deny reason text")
	}
}

func TestValidate_DenyReason_UppercaseHex_Rejected(t *testing.T) {
	upperHex := strings.ToUpper(hex64)
	ev := eventWithDenyReason(t, upperHex)
	if err := ev.Validate(); err == nil {
		t.Fatal("expected Validate to reject uppercase hex blob")
	}
}

// ── 4. Boundary cases ─────────────────────────────────────────────────────────

func TestValidate_DenyReason_Hex63Chars_Allowed(t *testing.T) {
	// 63 hex chars = 31.5 bytes — below the 32-byte threshold. Must pass.
	// This ensures the check doesn't over-fire on UUIDs (32 hex without dashes)
	// or short transaction identifiers.
	ev := eventWithDenyReason(t, "ref: "+hex63)
	if err := ev.Validate(); err != nil {
		t.Fatalf("expected Validate to allow 63-char hex, got: %v", err)
	}
}

func TestValidate_DenyReason_NonHexLongString_Allowed(t *testing.T) {
	// A 64-char string that is NOT hex must not be flagged.
	notHex := strings.Repeat("g", 64) // 'g' is not a hex digit
	ev := eventWithDenyReason(t, notHex)
	if err := ev.Validate(); err != nil {
		t.Fatalf("expected Validate to allow 64-char non-hex string, got: %v", err)
	}
}

func TestValidate_DenyReason_UUIDFormat_Allowed(t *testing.T) {
	// UUIDs contain 32 hex chars (without dashes) but the dashes break
	// any contiguous run below 64 chars. Must not be flagged.
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	ev := eventWithDenyReason(t, "session "+uuid+" denied")
	if err := ev.Validate(); err != nil {
		t.Fatalf("expected UUID in deny reason to pass Validate, got: %v", err)
	}
}

func TestValidate_DenyReason_TwoSeparateHex32_Allowed(t *testing.T) {
	// Two separate 32-char hex runs (each 16 bytes) separated by a space.
	// Neither run meets the 64-char threshold individually.
	run32 := hex64[:32]
	reason := run32 + " and " + run32
	ev := eventWithDenyReason(t, reason)
	if err := ev.Validate(); err != nil {
		t.Fatalf("two separate 32-char hex runs should pass: %v", err)
	}
}

// ── 5. MultiAuditor: valid events reach sinks ─────────────────────────────────

func TestMultiAuditor_ValidEvent_WrittenToSinks(t *testing.T) {
	sink := &stubSink{}
	multi := audit.NewMultiAuditor(sink)

	ev := makeTestEvent(t, audit.OperationSign)
	ev.Outcome = audit.OutcomeSuccess
	// No DenyReason — clean event.

	if err := multi.Log(context.Background(), ev); err != nil {
		t.Fatalf("Log of valid event returned error: %v", err)
	}
	if sink.logCount.Load() != 1 {
		t.Fatalf("expected sink to receive 1 event, got %d", sink.logCount.Load())
	}
}

// ── 6. MultiAuditor: invalid events rejected, no sinks called ─────────────────

func TestMultiAuditor_DenyReasonWithPEM_Rejected_NoSinksCalled(t *testing.T) {
	sink := &stubSink{}
	multi := audit.NewMultiAuditor(sink)

	ev := makeTestEvent(t, audit.OperationSign)
	ev.Outcome = audit.OutcomeDenied
	ev.DenyReason = "-----BEGIN EC PRIVATE KEY----- abc..."

	err := multi.Log(context.Background(), ev)
	if err == nil {
		t.Fatal("expected MultiAuditor.Log to return error for PEM in DenyReason")
	}
	// Verify the error indicates validation failure, not a sink error.
	if !strings.Contains(err.Error(), "rejected unsafe event") {
		t.Fatalf("unexpected error message: %q", err.Error())
	}
	// CRITICAL: no sink must have been called — fail closed.
	if sink.logCount.Load() != 0 {
		t.Fatalf("ADVERSARIAL: sink was called despite validation failure — possible key-material leak")
	}
}

func TestMultiAuditor_DenyReasonWithHexBlob_Rejected_NoSinksCalled(t *testing.T) {
	sinkA := &stubSink{name: "a"}
	sinkB := &stubSink{name: "b"}
	multi := audit.NewMultiAuditor(sinkA, sinkB)

	ev := makeTestEvent(t, audit.OperationDecrypt)
	ev.Outcome = audit.OutcomeDenied
	ev.DenyReason = "key material: " + hex64

	err := multi.Log(context.Background(), ev)
	if err == nil {
		t.Fatal("expected MultiAuditor.Log to return error for hex blob in DenyReason")
	}
	// CRITICAL: neither sink must have been called.
	if sinkA.logCount.Load() != 0 || sinkB.logCount.Load() != 0 {
		t.Fatalf("ADVERSARIAL: at least one sink was called despite validation failure")
	}
}

func TestMultiAuditor_InvalidEvent_ErrorUnwrapsToValidationError(t *testing.T) {
	multi := audit.NewMultiAuditor()

	ev := makeTestEvent(t, audit.OperationSign)
	ev.DenyReason = "-----BEGIN RSA PRIVATE KEY-----"

	err := multi.Log(context.Background(), ev)
	if err == nil {
		t.Fatal("expected error")
	}
	// The returned error must be unwrappable to get the validation detail.
	// This is important for callers that want to distinguish validation
	// failures from sink I/O failures.
	if !strings.Contains(err.Error(), "DenyReason") {
		t.Fatalf("error should mention the offending field, got: %q", err.Error())
	}
}

// TestValidate_ErrorMessage_DoesNotEchoKeyMaterial verifies that the error
// message from Validate does not repeat the suspicious content back.
// If it did, a caller logging the error would inadvertently log key material.
func TestValidate_ErrorMessage_DoesNotEchoKeyMaterial(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		needle string // substring we must NOT find in the error
	}{
		{
			name:   "pem_body",
			reason: "-----BEGIN EC PRIVATE KEY----- MHQCAQEEILnvPU==",
			needle: "MHQCAQEEILnvPU",
		},
		{
			name:   "hex_blob",
			reason: "key: " + hex64,
			needle: hex64,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := eventWithDenyReason(t, tc.reason)
			err := ev.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if strings.Contains(err.Error(), tc.needle) {
				t.Fatalf("ADVERSARIAL: Validate error message echoes suspicious content: %q", err.Error())
			}
		})
	}
}

// TestValidate_IsExportedAndCallable verifies the method is exported and
// accessible from outside the package (satisfies the exported-function
// coverage requirement).
func TestValidate_IsExportedAndCallable(t *testing.T) {
	ev, err := audit.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("fresh AuditEvent should pass Validate: %v", err)
	}
}

// TestValidate_MultipleErrors_OnlyFirstFieldChecked verifies current behaviour:
// Validate stops at the first offending field (DenyReason).
// This test documents the contract, not prescribes it — if additional fields
// are checked in future, update accordingly.
func TestValidate_StopsAtFirstViolation(t *testing.T) {
	ev := eventWithDenyReason(t, "-----BEGIN RSA PRIVATE KEY-----")
	err := ev.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	// Must reference DenyReason specifically.
	if !strings.Contains(err.Error(), "DenyReason") {
		t.Fatalf("expected DenyReason in error, got: %q", err.Error())
	}
	// Must not panic or return multiple joined errors from a single-field check.
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		t.Fatal("unexpected joined error from single-field Validate")
	}
}

// ── CRITICAL-03: Validate checks all free-text fields ─────────────────────────

func TestValidate_ErrorDetail_PEM_Rejected(t *testing.T) {
	ev, _ := audit.New()
	ev.CallerID = "test@team"
	ev.TeamID = "team"
	ev.Operation = audit.OperationSign
	ev.Outcome = audit.OutcomeError
	ev.ErrorDetail = "-----BEGIN EC PRIVATE KEY-----\nMHQ..."
	err := ev.Validate()
	if err == nil {
		t.Fatal("expected PEM in ErrorDetail to be rejected")
	}
	if !strings.Contains(err.Error(), "ErrorDetail") {
		t.Fatalf("expected ErrorDetail in error, got: %q", err.Error())
	}
}

func TestValidate_ErrorDetail_HexBlob_Rejected(t *testing.T) {
	ev, _ := audit.New()
	ev.CallerID = "test@team"
	ev.TeamID = "team"
	ev.Operation = audit.OperationSign
	ev.Outcome = audit.OutcomeError
	ev.ErrorDetail = "vault returned: " + hex64
	err := ev.Validate()
	if err == nil {
		t.Fatal("expected hex blob in ErrorDetail to be rejected")
	}
}

func TestValidate_CallerID_PEM_Rejected(t *testing.T) {
	ev, _ := audit.New()
	ev.CallerID = "-----BEGIN PRIVATE KEY-----"
	ev.TeamID = "team"
	ev.Operation = audit.OperationSign
	ev.Outcome = audit.OutcomeSuccess
	err := ev.Validate()
	if err == nil {
		t.Fatal("expected PEM in CallerID to be rejected")
	}
	if !strings.Contains(err.Error(), "CallerID") {
		t.Fatalf("expected CallerID in error, got: %q", err.Error())
	}
}

func TestValidate_UserAgent_HexBlob_Rejected(t *testing.T) {
	ev, _ := audit.New()
	ev.CallerID = "test@team"
	ev.TeamID = "team"
	ev.Operation = audit.OperationSign
	ev.Outcome = audit.OutcomeSuccess
	ev.UserAgent = hex128
	err := ev.Validate()
	if err == nil {
		t.Fatal("expected hex blob in UserAgent to be rejected")
	}
	if !strings.Contains(err.Error(), "UserAgent") {
		t.Fatalf("expected UserAgent in error, got: %q", err.Error())
	}
}

func TestValidate_KeyID_PEM_Rejected(t *testing.T) {
	ev, _ := audit.New()
	ev.CallerID = "test@team"
	ev.TeamID = "team"
	ev.Operation = audit.OperationSign
	ev.Outcome = audit.OutcomeSuccess
	ev.KeyID = "-----END RSA PRIVATE KEY-----"
	err := ev.Validate()
	if err == nil {
		t.Fatal("expected PEM in KeyID to be rejected")
	}
	if !strings.Contains(err.Error(), "KeyID") {
		t.Fatalf("expected KeyID in error, got: %q", err.Error())
	}
}

func TestValidate_CleanFreeTextFields_Pass(t *testing.T) {
	ev, _ := audit.New()
	ev.CallerID = "agent-42@engineering"
	ev.TeamID = "engineering"
	ev.Operation = audit.OperationSign
	ev.Outcome = audit.OutcomeSuccess
	ev.ErrorDetail = "connection timeout after 30s"
	ev.UserAgent = "pi-agent/1.2.3"
	ev.KeyID = "agentkms-signing-v2"
	ev.DenyReason = ""
	if err := ev.Validate(); err != nil {
		t.Fatalf("clean event should pass: %v", err)
	}
}
