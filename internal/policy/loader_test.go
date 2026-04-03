package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadFromFile_ValidFull loads the full fixture and spot-checks key fields.
func TestLoadFromFile_ValidFull(t *testing.T) {
	t.Parallel()

	p, err := LoadFromFile(filepath.Join("testdata", "valid_full.yaml"))
	if err != nil {
		t.Fatalf("LoadFromFile(valid_full.yaml): %v", err)
	}

	if p.Version != "1" {
		t.Errorf("Version = %q; want \"1\"", p.Version)
	}
	if len(p.Rules) != 5 {
		t.Errorf("len(Rules) = %d; want 5", len(p.Rules))
	}

	// First rule: explicit deny for agent sessions on production keys.
	r0 := p.Rules[0]
	if r0.ID != "deny-agent-production-keys" {
		t.Errorf("Rules[0].ID = %q; want \"deny-agent-production-keys\"", r0.ID)
	}
	if r0.Effect != EffectDeny {
		t.Errorf("Rules[0].Effect = %q; want %q", r0.Effect, EffectDeny)
	}
	if r0.Match.KeyPrefix != "production/" {
		t.Errorf("Rules[0].Match.KeyPrefix = %q; want \"production/\"", r0.Match.KeyPrefix)
	}

	// Second rule: allow with time window.
	r1 := p.Rules[1]
	if r1.TimeWindow == nil {
		t.Fatal("Rules[1].TimeWindow should not be nil")
	}
	if r1.TimeWindow.StartUTC != 6 || r1.TimeWindow.EndUTC != 22 {
		t.Errorf("Rules[1].TimeWindow = {%d, %d}; want {6, 22}",
			r1.TimeWindow.StartUTC, r1.TimeWindow.EndUTC)
	}

	// Fifth rule: key_ids (explicit allowlist) + rate_limit.
	r4 := p.Rules[4]
	if len(r4.Match.KeyIDs) != 2 {
		t.Errorf("Rules[4].Match.KeyIDs len = %d; want 2", len(r4.Match.KeyIDs))
	}
	if r4.RateLimit == nil {
		t.Fatal("Rules[4].RateLimit should not be nil")
	}
	if r4.RateLimit.MaxRequests != 500 {
		t.Errorf("Rules[4].RateLimit.MaxRequests = %d; want 500", r4.RateLimit.MaxRequests)
	}
}

// TestLoadFromFile_EmptyRules loads a policy with zero rules and verifies
// it is valid — empty policy is intentionally allowed (deny by default).
func TestLoadFromFile_EmptyRules(t *testing.T) {
	t.Parallel()

	p, err := LoadFromFile(filepath.Join("testdata", "empty_rules.yaml"))
	if err != nil {
		t.Fatalf("LoadFromFile(empty_rules.yaml): %v", err)
	}
	if len(p.Rules) != 0 {
		t.Errorf("expected 0 rules; got %d", len(p.Rules))
	}
}

// TestLoadFromFile_InvalidVersion checks that an unsupported version
// produces an error, not a silently-accepted policy.
func TestLoadFromFile_InvalidVersion(t *testing.T) {
	t.Parallel()

	_, err := LoadFromFile(filepath.Join("testdata", "invalid_bad_version.yaml"))
	if err == nil {
		t.Fatal("expected error for unsupported version; got nil")
	}
	if !strings.Contains(err.Error(), "unsupported schema version") {
		t.Errorf("error should mention 'unsupported schema version'; got: %v", err)
	}
}

// TestLoadFromFile_MultipleErrors verifies that the loader surfaces all
// validation errors from a deeply invalid policy file.
func TestLoadFromFile_MultipleErrors(t *testing.T) {
	t.Parallel()

	_, err := LoadFromFile(filepath.Join("testdata", "invalid_multiple_errors.yaml"))
	if err == nil {
		t.Fatal("expected validation errors; got nil")
	}
	// The error message must contain clues for each category of problem.
	// We check a sampling — not every single message — to keep the test
	// resilient to minor wording changes.
	for _, sub := range []string{
		"id must not be empty",
		"permit",      // bad effect
		"explode",     // bad operation
		"admin",       // bad role
		"start_utc",   // bad time window
		"mutually exclusive", // key_ids + key_prefix
		"duplicate",   // duplicate rule ID
		"max_requests", // bad rate limit
	} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error should contain %q; got:\n%v", sub, err)
		}
	}
}

// TestLoadFromFile_MissingFile verifies that a non-existent path returns an
// error rather than panicking or silently returning an empty policy.
func TestLoadFromFile_MissingFile(t *testing.T) {
	t.Parallel()

	_, err := LoadFromFile("/does/not/exist/policy.yaml")
	if err == nil {
		t.Fatal("expected error for missing file; got nil")
	}
}

// TestLoadFromFile_UnknownFieldFixture verifies that LoadFromFile rejects
// the invalid_unknown_field.yaml fixture — covering the file-based loader
// path for the KnownFields strict-mode security control.
func TestLoadFromFile_UnknownFieldFixture(t *testing.T) {
	t.Parallel()

	_, err := LoadFromFile(filepath.Join("testdata", "invalid_unknown_field.yaml"))
	if err == nil {
		t.Fatal("LoadFromFile should have rejected YAML with unknown field 'matche'; got nil error")
	}
}

// TestLoadFromBytes_MalformedYAML verifies that malformed YAML is rejected.
func TestLoadFromBytes_MalformedYAML(t *testing.T) {
	t.Parallel()

	badYAML := []byte("version: 1\nrules: [\n  - {bad yaml\n")
	_, err := LoadFromBytes(badYAML)
	if err == nil {
		t.Fatal("expected YAML parse error; got nil")
	}
}

// TestLoadFromBytes_UnknownField verifies that a YAML document with an
// unrecognised (e.g. misspelled) field is rejected rather than silently
// accepted with the unknown field discarded.
//
// SECURITY REGRESSION TEST (Finding 1): without KnownFields(true) a typo
// like "matche" instead of "match" would cause the rule's Match to be the
// zero value — matching all identities, all operations, all keys — turning
// a narrow allow into a blanket allow.
func TestLoadFromBytes_UnknownField(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		yaml string
	}{
		{
			name: "misspelled match field (matche)",
			yaml: `version: "1"
rules:
  - id: typo-rule
    matche:
      identity:
        team_id: platform-team
    effect: allow
`,
		},
		{
			name: "unknown top-level field",
			yaml: `version: "1"
super_admin: true
rules: []
`,
		},
		{
			name: "unknown field inside rule",
			yaml: `version: "1"
rules:
  - id: r1
    match: {}
    effect: allow
    bypass_policy: true
`,
		},
		{
			name: "misspelled key_prefix field",
			yaml: `version: "1"
rules:
  - id: r2
    match:
      key_prefiz: "payments/"
    effect: allow
`,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadFromBytes([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("LoadFromBytes should have rejected YAML with unknown field %q; got nil error", tc.name)
			}
		})
	}
}

// TestLoadFromBytes_RoundTrip loads a valid policy from bytes, then writes
// the rules count back out to confirm nothing was silently dropped.
func TestLoadFromBytes_RoundTrip(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("testdata", "valid_full.yaml"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	p, err := LoadFromBytes(data)
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}

	if len(p.Rules) == 0 {
		t.Error("round-trip produced zero rules; fixture should have multiple rules")
	}

	// All rule IDs must be non-empty after parsing.
	for i, r := range p.Rules {
		if r.ID == "" {
			t.Errorf("Rules[%d].ID is empty after parsing", i)
		}
		if !r.Effect.IsValid() {
			t.Errorf("Rules[%d].Effect = %q is not valid after parsing", i, r.Effect)
		}
	}
}
