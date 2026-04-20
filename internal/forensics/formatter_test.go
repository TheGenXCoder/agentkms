package forensics_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/forensics"
)

// fullReport builds a Report with all fields populated, matching the v0.3 launch demo scenario.
func fullReport() *forensics.Report {
	issuedAt := time.Date(2026, 4, 13, 15, 20, 0, 0, time.UTC)
	expiredAt := time.Date(2026, 4, 13, 23, 20, 0, 0, time.UTC)
	detectedAt := time.Date(2026, 4, 16, 10, 47, 0, 0, time.UTC)

	scope := json.RawMessage(`{
		"repos": ["acmecorp/legacy-tool"],
		"permissions": ["contents:write", "pull_requests:write"],
		"expires_at": "2026-04-13T23:20:00Z"
	}`)

	return &forensics.Report{
		CredentialUUID:     "cred-demo-001",
		Provider:           "github",
		CredentialType:     "github-pat",
		Kind:               "PAT",
		IssuedAt:           issuedAt,
		ExpiredAt:          expiredAt,
		DetectedAt:         detectedAt,
		InvalidationReason: "revoked-leak",
		CallerID:           "frank@acmecorp",
		TeamID:             "platform-team",
		RuleID:             "allow-github-for-developers (rule #4)",
		Scope:              scope,
		ScopeHash:          "abc123hash",
		UsageEvents: []forensics.UsageEvent{
			{Timestamp: time.Date(2026, 4, 13, 15, 22, 0, 0, time.UTC), Operation: "credential_use", Description: "clone acmecorp/legacy-tool"},
			{Timestamp: time.Date(2026, 4, 13, 15, 47, 0, 0, time.UTC), Operation: "credential_use", Description: "push branch migration-v3"},
			{Timestamp: time.Date(2026, 4, 13, 16, 31, 0, 0, time.UTC), Operation: "credential_use", Description: "open PR #47"},
		},
		Assessment: "no damage",
	}
}

func TestFormatReport_FullReport(t *testing.T) {
	r := fullReport()
	out := forensics.FormatReport(r)

	checks := []struct {
		name    string
		snippet string
	}{
		{"blast radius header", "Blast radius:"},
		{"blast radius value BOUNDED", "BOUNDED"},
		{"scope repo", "acmecorp/legacy-tool"},
		{"lifecycle issued label", "issued"},
		{"lifecycle expired label", "expired"},
		{"lifecycle leaked label", "leaked"},
		{"issued timestamp", "2026-04-13 15:20 UTC"},
		{"expired timestamp", "2026-04-13 23:20 UTC"},
		{"detected timestamp", "2026-04-16 10:47 UTC"},
		{"usage event clone", "clone acmecorp/legacy-tool"},
		{"usage event push", "push branch migration-v3"},
		{"usage event PR", "open PR #47"},
		{"post-expiry NONE", "Post-expiry usage: NONE"},
		{"assessment no damage", "no damage"},
		{"action required none", "Action required: none"},
		{"issuance context header", "Full issuance context"},
		{"requester CallerID", "frank@acmecorp"},
		{"team", "platform-team"},
		{"rule ID", "allow-github-for-developers"},
		{"teaser c9-forensics-plus", "c9-forensics-plus"},
	}

	for _, c := range checks {
		if !strings.Contains(out, c.snippet) {
			t.Errorf("TestFormatReport_FullReport [%s]: output does not contain %q\nFull output:\n%s", c.name, c.snippet, out)
		}
	}
}

func TestFormatReport_NoDetection(t *testing.T) {
	r := fullReport()
	r.DetectedAt = time.Time{} // zero value — not yet detected
	r.Assessment = ""

	out := forensics.FormatReport(r)

	if !strings.Contains(out, "not yet detected") {
		t.Errorf("expected 'not yet detected' in output when DetectedAt is zero\nFull output:\n%s", out)
	}
}

func TestFormatReport_NoUsageEvents(t *testing.T) {
	r := fullReport()
	r.UsageEvents = nil

	out := forensics.FormatReport(r)

	if !strings.Contains(out, "No usage recorded") {
		t.Errorf("expected 'No usage recorded' in output when UsageEvents is empty\nFull output:\n%s", out)
	}
}

func TestFormatReport_NilScope(t *testing.T) {
	r := fullReport()
	r.Scope = nil

	out := forensics.FormatReport(r)

	if !strings.Contains(out, "Scope not available") {
		t.Errorf("expected 'Scope not available' in output when Scope is nil\nFull output:\n%s", out)
	}
}

func TestFormatReport_ContainsTeaser(t *testing.T) {
	r := fullReport()
	out := forensics.FormatReport(r)

	if !strings.Contains(out, "c9-forensics-plus") {
		t.Errorf("expected OSS teaser containing 'c9-forensics-plus'\nFull output:\n%s", out)
	}
}

func TestFormatReport_AssessmentPending(t *testing.T) {
	r := fullReport()
	r.Assessment = ""
	r.DetectedAt = time.Time{}

	out := forensics.FormatReport(r)

	if !strings.Contains(out, "Assessment pending") {
		t.Errorf("expected 'Assessment pending' when Assessment is empty\nFull output:\n%s", out)
	}
}

func TestFormatReport_PotentialExposure(t *testing.T) {
	r := fullReport()
	// Credential still live when detected.
	r.ExpiredAt = time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	r.DetectedAt = time.Date(2026, 4, 16, 10, 47, 0, 0, time.UTC)
	r.Assessment = "potential exposure"

	out := forensics.FormatReport(r)

	if !strings.Contains(out, "potential exposure") {
		t.Errorf("expected 'potential exposure' in output\nFull output:\n%s", out)
	}
	if !strings.Contains(out, "rotate immediately") {
		t.Errorf("expected 'rotate immediately' action for potential exposure\nFull output:\n%s", out)
	}
}

func TestFormatReport_BlastRadiusWide(t *testing.T) {
	r := fullReport()
	r.Scope = json.RawMessage(`{"repos": ["repo-a", "repo-b", "repo-c"]}`)

	out := forensics.FormatReport(r)

	if !strings.Contains(out, "WIDE") {
		t.Errorf("expected 'WIDE' blast radius for multi-repo scope\nFull output:\n%s", out)
	}
}

func TestFormatReport_BlastRadiusUnknown(t *testing.T) {
	r := fullReport()
	r.Scope = nil

	out := forensics.FormatReport(r)

	if !strings.Contains(out, "UNKNOWN") {
		t.Errorf("expected 'UNKNOWN' blast radius when Scope is nil\nFull output:\n%s", out)
	}
}

func TestFormatReport_TTLLine(t *testing.T) {
	r := fullReport()
	out := forensics.FormatReport(r)

	// The demo credential has an 8h window.
	if !strings.Contains(out, "TTL applied") {
		t.Errorf("expected 'TTL applied' line in output\nFull output:\n%s", out)
	}
	if !strings.Contains(out, "8h") {
		t.Errorf("expected '8h' TTL in output\nFull output:\n%s", out)
	}
}
