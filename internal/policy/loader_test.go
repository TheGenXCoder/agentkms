package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── LoadFromFile ──────────────────────────────────────────────────────────────

func TestLoadFromFile_ValidYAML(t *testing.T) {
	data := []byte(`version: 1
environment: dev
rules:
  - id: allow-all
    identities: ["*"]
    teams: ["*"]
    operations: ["*"]
    key_prefixes: ["*"]
    effect: allow
`)
	path := writeTemp(t, data)
	pf, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if len(pf.Rules) != 1 || pf.Rules[0].ID != "allow-all" {
		t.Fatalf("unexpected policy content: %+v", pf)
	}
}

func TestLoadFromFile_MissingFile(t *testing.T) {
	_, err := LoadFromFile("/does/not/exist/policy.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadFromFile_MalformedYAML(t *testing.T) {
	data := []byte("version: 1\nrules: [\n  - {invalid yaml\n")
	path := writeTemp(t, data)
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}

func TestLoadFromFile_WrongVersion(t *testing.T) {
	data := []byte("version: 99\nrules: []\n")
	path := writeTemp(t, data)
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for unsupported version, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported version") {
		t.Errorf("error should mention 'unsupported version'; got: %v", err)
	}
}

func TestLoadFromFile_InvalidRule(t *testing.T) {
	// Rule with empty ID — must be caught by validatePolicyFile.
	data := []byte(`version: 1
rules:
  - id: ""
    identities: ["*"]
    teams: ["*"]
    operations: ["*"]
    key_prefixes: ["*"]
    effect: allow
`)
	path := writeTemp(t, data)
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected validation error for empty rule ID, got nil")
	}
}

// ── DefaultDevPolicy ──────────────────────────────────────────────────────────

func TestDefaultDevPolicy_Structure(t *testing.T) {
	pf := DefaultDevPolicy("bert@dev", "dev-team")

	if pf.Version != 1 {
		t.Errorf("Version = %d, want 1", pf.Version)
	}
	if pf.Environment != "dev" {
		t.Errorf("Environment = %q, want dev", pf.Environment)
	}
	if len(pf.Rules) == 0 {
		t.Fatal("expected at least one rule")
	}

	// The default rule should allow all operations for the specified identity.
	rule := pf.Rules[0]
	if len(rule.Identities) == 0 || rule.Identities[0] != "bert@dev" {
		t.Errorf("default rule identity = %v, want [bert@dev]", rule.Identities)
	}
	if rule.Effect != EffectAllow {
		t.Errorf("default rule effect = %q, want allow", rule.Effect)
	}
	if len(rule.Operations) == 0 {
		t.Error("default rule has no operations")
	}
}

func TestDefaultDevPolicy_PassesValidation(t *testing.T) {
	pf := DefaultDevPolicy("alice@dev", "dev-team")
	if err := validatePolicyFile(pf); err != nil {
		t.Fatalf("DefaultDevPolicy fails validation: %v", err)
	}
}

func TestDefaultDevPolicy_EngineEvaluatesAllow(t *testing.T) {
	pf := DefaultDevPolicy("bert@dev", "dev-team")
	engine := NewEngine(pf)

	dec := engine.Evaluate(Request{
		CallerID:  "bert@dev",
		TeamID:    "dev-team",
		Operation: OperationSign,
		KeyID:     "personal/my-key",
	})
	if !dec.Allowed {
		t.Errorf("default policy should allow caller; got deny: %q", dec.DenyReason)
	}
}

func TestDefaultDevPolicy_OtherIdentityStillDenied(t *testing.T) {
	// Policy is for bert@dev; a different caller must be denied.
	pf := DefaultDevPolicy("bert@dev", "dev-team")
	engine := NewEngine(pf)

	dec := engine.Evaluate(Request{
		CallerID:  "attacker@evil",
		TeamID:    "evil-team",
		Operation: OperationSign,
		KeyID:     "personal/my-key",
	})
	if dec.Allowed {
		t.Error("default policy should not allow a different identity")
	}
}

// ── MarshalYAML ───────────────────────────────────────────────────────────────

func TestMarshalYAML_RoundTrip(t *testing.T) {
	pf := DefaultDevPolicy("bert@dev", "dev-team")

	data, err := MarshalYAML(pf)
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("MarshalYAML returned empty bytes")
	}

	// Write to a temp file and reload — must produce equivalent policy.
	path := writeTemp(t, data)
	reloaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile after marshal: %v", err)
	}

	if reloaded.Version != pf.Version {
		t.Errorf("Version mismatch: %d vs %d", reloaded.Version, pf.Version)
	}
	if len(reloaded.Rules) != len(pf.Rules) {
		t.Errorf("Rules count mismatch: %d vs %d", len(reloaded.Rules), len(pf.Rules))
	}
	if reloaded.Rules[0].ID != pf.Rules[0].ID {
		t.Errorf("Rule[0].ID mismatch: %q vs %q", reloaded.Rules[0].ID, pf.Rules[0].ID)
	}
}

// ── validatePolicyFile ────────────────────────────────────────────────────────

func TestValidatePolicyFile_EmptyRules_Valid(t *testing.T) {
	// An empty rule set is valid (deny-by-default is the correct behaviour).
	pf := &PolicyFile{Version: 1}
	if err := validatePolicyFile(pf); err != nil {
		t.Errorf("empty rules should be valid, got: %v", err)
	}
}

func TestValidatePolicyFile_DuplicateRuleID(t *testing.T) {
	pf := &PolicyFile{
		Version: 1,
		Rules: []Rule{
			{ID: "dup", Identities: []string{"*"}, Teams: []string{"*"},
				Operations: []string{"*"}, KeyPrefixes: []string{"*"}, Effect: EffectAllow},
			{ID: "dup", Identities: []string{"*"}, Teams: []string{"*"},
				Operations: []string{"*"}, KeyPrefixes: []string{"*"}, Effect: EffectDeny},
		},
	}
	err := validatePolicyFile(pf)
	if err == nil {
		t.Fatal("expected error for duplicate rule ID, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error should mention 'duplicate'; got: %v", err)
	}
}

func TestValidatePolicyFile_BadEffect(t *testing.T) {
	pf := &PolicyFile{
		Version: 1,
		Rules: []Rule{
			{ID: "r1", Identities: []string{"*"}, Teams: []string{"*"},
				Operations: []string{"*"}, KeyPrefixes: []string{"*"}, Effect: "permit"},
		},
	}
	err := validatePolicyFile(pf)
	if err == nil {
		t.Fatal("expected error for unknown effect, got nil")
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "policy-*.yaml")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		t.Fatalf("Write: %v", err)
	}
	f.Close()
	return filepath.Clean(f.Name())
}
