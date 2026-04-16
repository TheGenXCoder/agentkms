package audit_test

// Bucket A — forensics fields: SchemaVersion, CredentialUUID, RuleID,
// CertSerialNumber, CallerOU, CallerRole, CredentialType, ProviderTokenHash.
//
// These tests cover the audit-package pieces of the Bucket A contract:
//
//   - audit.New() always stamps SchemaVersion = CurrentSchemaVersion (= 1)
//   - audit.HashProviderToken() produces SHA-256 hex of its input
//   - Events missing the new fields still parse (backwards compatibility)
//   - Validate() still accepts the new fields when they are present and
//     legitimate, and rejects key-material patterns in the free-text additions

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentkms/agentkms/internal/audit"
)

// ── SchemaVersion ─────────────────────────────────────────────────────────────

func TestBucketA_New_StampsSchemaVersion1(t *testing.T) {
	ev, err := audit.New()
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	if ev.SchemaVersion != audit.CurrentSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d (CurrentSchemaVersion)",
			ev.SchemaVersion, audit.CurrentSchemaVersion)
	}
	if audit.CurrentSchemaVersion != 1 {
		t.Errorf("CurrentSchemaVersion = %d, want 1 for Bucket A",
			audit.CurrentSchemaVersion)
	}
}

func TestBucketA_SchemaVersion_SerialisedAsInt(t *testing.T) {
	ev, err := audit.New()
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"schema_version":1`) {
		t.Errorf("expected schema_version:1 in JSON, got: %s", string(b))
	}
}

// TestBucketA_OldEventParsesCleanly verifies the backwards-compatibility
// invariant: pre-migration events (SchemaVersion == 0, missing new fields)
// must unmarshal into AuditEvent without error.
func TestBucketA_OldEventParsesCleanly(t *testing.T) {
	// A "v0" event — no schema_version, no Bucket A fields.
	oldJSON := []byte(`{
		"event_id": "11111111-1111-4111-8111-111111111111",
		"timestamp": "2026-01-01T00:00:00Z",
		"caller_id": "old@team",
		"team_id": "team",
		"operation": "sign",
		"outcome": "success"
	}`)

	var ev audit.AuditEvent
	if err := json.Unmarshal(oldJSON, &ev); err != nil {
		t.Fatalf("old event failed to parse: %v", err)
	}
	if ev.SchemaVersion != 0 {
		t.Errorf("old event should have SchemaVersion 0, got %d", ev.SchemaVersion)
	}
	if ev.CallerID != "old@team" {
		t.Errorf("CallerID round-trip failed: %q", ev.CallerID)
	}
	// Bucket A fields must all default to zero values.
	if ev.CredentialUUID != "" || ev.RuleID != "" ||
		ev.CertSerialNumber != "" || ev.CallerOU != "" ||
		ev.CallerRole != "" || ev.CredentialType != "" ||
		ev.ProviderTokenHash != "" {
		t.Errorf("old event should have empty Bucket A fields, got: %+v", ev)
	}
}

// TestBucketA_NewEventRoundTrip verifies events with Bucket A fields
// populated round-trip through JSON without loss.
func TestBucketA_NewEventRoundTrip(t *testing.T) {
	orig, err := audit.New()
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	orig.CallerID = "ci@payments"
	orig.TeamID = "payments"
	orig.Operation = audit.OperationCredentialVend
	orig.Outcome = audit.OutcomeSuccess
	orig.CredentialUUID = "550e8400-e29b-41d4-a716-446655440000"
	orig.RuleID = "rule-payments-vend"
	orig.CertSerialNumber = hex.EncodeToString(make([]byte, 32))
	orig.CallerOU = "service"
	orig.CallerRole = "service"
	orig.CredentialType = "llm-session"
	orig.ProviderTokenHash = hex.EncodeToString(make([]byte, 32))

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var round audit.AuditEvent
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if round.SchemaVersion != orig.SchemaVersion ||
		round.CredentialUUID != orig.CredentialUUID ||
		round.RuleID != orig.RuleID ||
		round.CertSerialNumber != orig.CertSerialNumber ||
		round.CallerOU != orig.CallerOU ||
		round.CallerRole != orig.CallerRole ||
		round.CredentialType != orig.CredentialType ||
		round.ProviderTokenHash != orig.ProviderTokenHash {
		t.Errorf("round-trip mismatch:\n orig = %+v\nround = %+v", orig, round)
	}
}

// ── HashProviderToken ─────────────────────────────────────────────────────────

// TestBucketA_HashProviderToken_MatchesSha256 is the forensics reverse-lookup
// contract: hashing a known token must produce the same SHA-256 hex digest a
// caller would compute directly.  If this invariant is broken, leak reports
// cannot be joined to audit events.
func TestBucketA_HashProviderToken_MatchesSha256(t *testing.T) {
	cases := []string{
		"sk-ant-apiKey-12345",
		"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"AKIA" + strings.Repeat("X", 16),
	}
	for _, tc := range cases {
		want := sha256.Sum256([]byte(tc))
		got := audit.HashProviderToken([]byte(tc))
		if got != hex.EncodeToString(want[:]) {
			t.Errorf("HashProviderToken(%q) = %q, want %q",
				tc, got, hex.EncodeToString(want[:]))
		}
	}
}

func TestBucketA_HashProviderToken_EmptyInput(t *testing.T) {
	if got := audit.HashProviderToken(nil); got != "" {
		t.Errorf("HashProviderToken(nil) = %q, want empty", got)
	}
	if got := audit.HashProviderToken([]byte{}); got != "" {
		t.Errorf("HashProviderToken(empty) = %q, want empty", got)
	}
}

// TestBucketA_HashProviderToken_IsDeterministic — same input → same hash,
// always.  This is what makes reverse lookup possible.
func TestBucketA_HashProviderToken_IsDeterministic(t *testing.T) {
	token := []byte("sk-determinism-check")
	first := audit.HashProviderToken(token)
	for i := 0; i < 10; i++ {
		if got := audit.HashProviderToken(token); got != first {
			t.Fatalf("HashProviderToken not deterministic: %q vs %q", got, first)
		}
	}
}

// TestBucketA_HashProviderToken_NeverReturnsRawToken — adversarial:
// the hash output must never contain the raw token, regardless of input
// shape.  If this test ever fails, the audit log has just become a secret
// store.
func TestBucketA_HashProviderToken_NeverReturnsRawToken(t *testing.T) {
	tokens := []string{
		"sk-leaky-aaaa",
		"password123",
		"-----BEGIN RSA PRIVATE KEY-----",
	}
	for _, tok := range tokens {
		hash := audit.HashProviderToken([]byte(tok))
		if strings.Contains(hash, tok) {
			t.Fatalf("ADVERSARIAL: hash %q contains raw token %q", hash, tok)
		}
	}
}

// ── Validate accepts legitimate Bucket A field values ─────────────────────────

func TestBucketA_Validate_AcceptsLegitimateFields(t *testing.T) {
	ev, err := audit.New()
	if err != nil {
		t.Fatal(err)
	}
	ev.CallerID = "ci@payments"
	ev.TeamID = "payments"
	ev.Operation = audit.OperationCredentialVend
	ev.Outcome = audit.OutcomeSuccess
	ev.CredentialUUID = "550e8400-e29b-41d4-a716-446655440000"
	ev.RuleID = "payments-vend-allow"
	ev.CertSerialNumber = hex.EncodeToString(make([]byte, 32))
	ev.CallerOU = "service"
	ev.CallerRole = "service"
	ev.CredentialType = "llm-session"
	ev.ProviderTokenHash = hex.EncodeToString(make([]byte, 32))

	if err := ev.Validate(); err != nil {
		t.Fatalf("Validate() rejected legitimate Bucket A event: %v", err)
	}
}

// TestBucketA_Validate_RejectsNonHexHash — ProviderTokenHash and
// CertSerialNumber must be strict lowercase hex.  Any other shape
// indicates a misuse (potential raw-token leak).
func TestBucketA_Validate_RejectsNonHexHash(t *testing.T) {
	ev, err := audit.New()
	if err != nil {
		t.Fatal(err)
	}
	ev.CallerID = "x@y"
	ev.TeamID = "y"
	ev.Operation = audit.OperationCredentialVend
	ev.Outcome = audit.OutcomeSuccess
	// Contains non-hex characters — must be rejected.
	ev.ProviderTokenHash = "not-a-valid-hash-sk-ant-leaked"
	if err := ev.Validate(); err == nil {
		t.Fatal("expected Validate to reject non-hex ProviderTokenHash")
	}
}

func TestBucketA_Validate_RejectsPEMInNewFields(t *testing.T) {
	cases := []struct {
		name string
		set  func(ev *audit.AuditEvent)
	}{
		{"CallerOU_PEM", func(ev *audit.AuditEvent) {
			ev.CallerOU = "-----BEGIN PRIVATE KEY-----"
		}},
		{"CallerRole_PEM", func(ev *audit.AuditEvent) {
			ev.CallerRole = "-----END RSA PRIVATE KEY-----"
		}},
		{"CredentialType_PEM", func(ev *audit.AuditEvent) {
			ev.CredentialType = "-----BEGIN EC PRIVATE KEY-----"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := audit.New()
			if err != nil {
				t.Fatal(err)
			}
			ev.CallerID = "x@y"
			ev.TeamID = "y"
			ev.Operation = audit.OperationCredentialVend
			ev.Outcome = audit.OutcomeSuccess
			tc.set(&ev)
			if err := ev.Validate(); err == nil {
				t.Fatal("expected Validate to reject PEM marker in new field")
			}
		})
	}
}
