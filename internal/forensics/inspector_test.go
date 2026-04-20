package forensics_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/forensics"
)

const testToken = "ghp_ABCxyz123456789"

// helper: builds a vend event with standard forensics fields populated.
func makeVendEvent(t *testing.T, opts vendOpts) audit.AuditEvent {
	t.Helper()
	ev := audit.AuditEvent{
		SchemaVersion:     1,
		EventID:           "evt-vend-001",
		Timestamp:         opts.timestamp,
		CallerID:          opts.callerID,
		TeamID:            opts.teamID,
		Operation:         audit.OperationCredentialVend,
		Outcome:           audit.OutcomeSuccess,
		CredentialUUID:    opts.credUUID,
		CredentialType:    opts.credType,
		ProviderTokenHash: opts.tokenHash,
		RuleID:            opts.ruleID,
		Scope:             opts.scope,
		ScopeHash:         opts.scopeHash,
	}
	return ev
}

type vendOpts struct {
	timestamp  time.Time
	callerID   string
	teamID     string
	credUUID   string
	credType   string
	tokenHash  string
	ruleID     string
	scope      json.RawMessage
	scopeHash  string
}

// helper: builds a use event referencing a credential UUID.
func makeUseEvent(credUUID string, ts time.Time, op string) audit.AuditEvent {
	return audit.AuditEvent{
		SchemaVersion:  1,
		EventID:        "evt-use-001",
		Timestamp:      ts,
		CallerID:       "service@backend",
		TeamID:         "backend-team",
		Operation:      op,
		Outcome:        audit.OutcomeSuccess,
		CredentialUUID: credUUID,
	}
}

func TestInspector_InspectByToken_FindsCredential(t *testing.T) {
	tokenHash := audit.HashProviderToken([]byte(testToken))
	credUUID := "cred-uuid-001"

	events := []audit.AuditEvent{
		makeVendEvent(t, vendOpts{
			timestamp: time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
			callerID:  "bert@platform-team",
			teamID:    "platform-team",
			credUUID:  credUUID,
			credType:  "github-pat",
			tokenHash: tokenHash,
			ruleID:    "rule-gh-001",
			scope:     json.RawMessage(`{"repos":["myrepo"],"expires_at":"2026-04-17T12:00:00Z"}`),
			scopeHash: "abc123",
		}),
	}

	inspector := forensics.NewInspector(events)
	report, err := inspector.InspectByToken(testToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report, got nil")
	}
	if report.CredentialUUID != credUUID {
		t.Errorf("CredentialUUID = %q, want %q", report.CredentialUUID, credUUID)
	}
}

func TestInspector_InspectByTokenHash_Direct(t *testing.T) {
	tokenHash := audit.HashProviderToken([]byte(testToken))
	credUUID := "cred-uuid-002"

	events := []audit.AuditEvent{
		makeVendEvent(t, vendOpts{
			timestamp: time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
			callerID:  "bert@platform-team",
			teamID:    "platform-team",
			credUUID:  credUUID,
			credType:  "github-pat",
			tokenHash: tokenHash,
			ruleID:    "rule-gh-001",
			scope:     json.RawMessage(`{"repos":["myrepo"]}`),
			scopeHash: "def456",
		}),
	}

	inspector := forensics.NewInspector(events)
	report, err := inspector.InspectByTokenHash(tokenHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report, got nil")
	}
	if report.CredentialUUID != credUUID {
		t.Errorf("CredentialUUID = %q, want %q", report.CredentialUUID, credUUID)
	}
}

func TestInspector_NotFound(t *testing.T) {
	events := []audit.AuditEvent{
		makeVendEvent(t, vendOpts{
			timestamp: time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
			callerID:  "bert@platform-team",
			teamID:    "platform-team",
			credUUID:  "cred-other",
			credType:  "github-pat",
			tokenHash: "aaaa",
			ruleID:    "rule-gh-001",
		}),
	}

	inspector := forensics.NewInspector(events)
	_, err := inspector.InspectByToken("nonexistent-token-xyz")
	if err == nil {
		t.Fatal("expected error for unknown token, got nil")
	}
}

func TestInspector_Report_HasCallerIdentity(t *testing.T) {
	tokenHash := audit.HashProviderToken([]byte(testToken))

	events := []audit.AuditEvent{
		makeVendEvent(t, vendOpts{
			timestamp: time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
			callerID:  "ci-runner@payments-team",
			teamID:    "payments-team",
			credUUID:  "cred-uuid-003",
			credType:  "github-pat",
			tokenHash: tokenHash,
			ruleID:    "rule-pay-001",
		}),
	}

	inspector := forensics.NewInspector(events)
	report, err := inspector.InspectByTokenHash(tokenHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report, got nil")
	}
	if report.CallerID != "ci-runner@payments-team" {
		t.Errorf("CallerID = %q, want %q", report.CallerID, "ci-runner@payments-team")
	}
	if report.TeamID != "payments-team" {
		t.Errorf("TeamID = %q, want %q", report.TeamID, "payments-team")
	}
}

func TestInspector_Report_HasScope(t *testing.T) {
	tokenHash := audit.HashProviderToken([]byte(testToken))
	scope := json.RawMessage(`{"repos":["backend","frontend"],"permissions":"read"}`)

	events := []audit.AuditEvent{
		makeVendEvent(t, vendOpts{
			timestamp: time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
			callerID:  "bert@platform-team",
			teamID:    "platform-team",
			credUUID:  "cred-uuid-004",
			credType:  "github-pat",
			tokenHash: tokenHash,
			ruleID:    "rule-gh-001",
			scope:     scope,
			scopeHash: "scope-hash-xyz",
		}),
	}

	inspector := forensics.NewInspector(events)
	report, err := inspector.InspectByTokenHash(tokenHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report, got nil")
	}
	if string(report.Scope) != string(scope) {
		t.Errorf("Scope = %s, want %s", report.Scope, scope)
	}
	if report.ScopeHash != "scope-hash-xyz" {
		t.Errorf("ScopeHash = %q, want %q", report.ScopeHash, "scope-hash-xyz")
	}
}

func TestInspector_Report_HasTimeline(t *testing.T) {
	tokenHash := audit.HashProviderToken([]byte(testToken))
	issuedAt := time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)
	expiresAt := "2026-04-17T12:00:00Z"
	scope := json.RawMessage(`{"expires_at":"` + expiresAt + `","repos":["myrepo"]}`)

	events := []audit.AuditEvent{
		makeVendEvent(t, vendOpts{
			timestamp: issuedAt,
			callerID:  "bert@platform-team",
			teamID:    "platform-team",
			credUUID:  "cred-uuid-005",
			credType:  "github-pat",
			tokenHash: tokenHash,
			ruleID:    "rule-gh-001",
			scope:     scope,
			scopeHash: "timeline-hash",
		}),
	}

	inspector := forensics.NewInspector(events)
	report, err := inspector.InspectByTokenHash(tokenHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report, got nil")
	}
	if !report.IssuedAt.Equal(issuedAt) {
		t.Errorf("IssuedAt = %v, want %v", report.IssuedAt, issuedAt)
	}
	wantExpiry, _ := time.Parse(time.RFC3339, expiresAt)
	if !report.ExpiredAt.Equal(wantExpiry) {
		t.Errorf("ExpiredAt = %v, want %v", report.ExpiredAt, wantExpiry)
	}
}

func TestInspector_Report_UsageEvents(t *testing.T) {
	tokenHash := audit.HashProviderToken([]byte(testToken))
	credUUID := "cred-uuid-006"
	vendTime := time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)
	useTime := time.Date(2026, 4, 10, 14, 30, 0, 0, time.UTC)

	events := []audit.AuditEvent{
		makeVendEvent(t, vendOpts{
			timestamp: vendTime,
			callerID:  "bert@platform-team",
			teamID:    "platform-team",
			credUUID:  credUUID,
			credType:  "github-pat",
			tokenHash: tokenHash,
			ruleID:    "rule-gh-001",
		}),
		makeUseEvent(credUUID, useTime, audit.OperationCredentialUse),
	}

	inspector := forensics.NewInspector(events)
	report, err := inspector.InspectByTokenHash(tokenHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report, got nil")
	}
	if len(report.UsageEvents) == 0 {
		t.Fatal("expected at least one UsageEvent, got none")
	}
	if report.UsageEvents[0].Operation != audit.OperationCredentialUse {
		t.Errorf("UsageEvents[0].Operation = %q, want %q",
			report.UsageEvents[0].Operation, audit.OperationCredentialUse)
	}
	if !report.UsageEvents[0].Timestamp.Equal(useTime) {
		t.Errorf("UsageEvents[0].Timestamp = %v, want %v",
			report.UsageEvents[0].Timestamp, useTime)
	}
}

func TestInspector_Report_Assessment_NoDamage(t *testing.T) {
	tokenHash := audit.HashProviderToken([]byte(testToken))
	credUUID := "cred-uuid-007"
	// Credential expired BEFORE detection time.
	issuedAt := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	expiredAt := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	detectedAt := time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)

	scope := json.RawMessage(`{"expires_at":"` + expiredAt.Format(time.RFC3339) + `"}`)

	events := []audit.AuditEvent{
		makeVendEvent(t, vendOpts{
			timestamp: issuedAt,
			callerID:  "bert@platform-team",
			teamID:    "platform-team",
			credUUID:  credUUID,
			credType:  "github-pat",
			tokenHash: tokenHash,
			ruleID:    "rule-gh-001",
			scope:     scope,
			scopeHash: "no-damage-hash",
		}),
		// Simulate a detection/invalidation event after expiry.
		{
			SchemaVersion:      1,
			EventID:            "evt-revoke-001",
			Timestamp:          detectedAt,
			CallerID:           "scanner@security-team",
			TeamID:             "security-team",
			Operation:          audit.OperationRevoke,
			Outcome:            audit.OutcomeSuccess,
			CredentialUUID:     credUUID,
			InvalidationReason: audit.ReasonRevokedLeak,
		},
	}

	inspector := forensics.NewInspector(events)
	report, err := inspector.InspectByTokenHash(tokenHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report, got nil")
	}
	if report.Assessment != "no damage" {
		t.Errorf("Assessment = %q, want %q", report.Assessment, "no damage")
	}
}

func TestInspector_Report_Assessment_PotentialExposure(t *testing.T) {
	tokenHash := audit.HashProviderToken([]byte(testToken))
	credUUID := "cred-uuid-008"
	// Credential is still LIVE at detection time (expires after detection).
	issuedAt := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	expiredAt := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	detectedAt := time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)

	scope := json.RawMessage(`{"expires_at":"` + expiredAt.Format(time.RFC3339) + `"}`)

	events := []audit.AuditEvent{
		makeVendEvent(t, vendOpts{
			timestamp: issuedAt,
			callerID:  "bert@platform-team",
			teamID:    "platform-team",
			credUUID:  credUUID,
			credType:  "github-pat",
			tokenHash: tokenHash,
			ruleID:    "rule-gh-001",
			scope:     scope,
			scopeHash: "exposure-hash",
		}),
		// Detection event while credential is still live.
		{
			SchemaVersion:      1,
			EventID:            "evt-revoke-002",
			Timestamp:          detectedAt,
			CallerID:           "scanner@security-team",
			TeamID:             "security-team",
			Operation:          audit.OperationRevoke,
			Outcome:            audit.OutcomeSuccess,
			CredentialUUID:     credUUID,
			InvalidationReason: audit.ReasonRevokedLeak,
		},
	}

	inspector := forensics.NewInspector(events)
	report, err := inspector.InspectByTokenHash(tokenHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report, got nil")
	}
	if report.Assessment != "potential exposure" {
		t.Errorf("Assessment = %q, want %q", report.Assessment, "potential exposure")
	}
}
