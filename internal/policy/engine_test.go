package policy

import (
	"testing"
)

// ── Fixtures ──────────────────────────────────────────────────────────────────

func policyWith(rules ...Rule) *PolicyFile {
	return &PolicyFile{Version: 1, Environment: "dev", Rules: rules}
}

func allowRule(id string, identities, teams, ops, prefixes []string) Rule {
	return Rule{
		ID:          id,
		Identities:  identities,
		Teams:       teams,
		Operations:  ops,
		KeyPrefixes: prefixes,
		Effect:      EffectAllow,
	}
}

func denyRule(id string, identities, teams, ops, prefixes []string) Rule {
	return Rule{
		ID:          id,
		Identities:  identities,
		Teams:       teams,
		Operations:  ops,
		KeyPrefixes: prefixes,
		Effect:      EffectDeny,
	}
}

// ── P-04: Deny-by-default ─────────────────────────────────────────────────────

func TestEngine_EmptyPolicy_DeniesEverything(t *testing.T) {
	engine := NewEngine(policyWith())

	req := Request{
		CallerID:  "bert@dev",
		TeamID:    "dev-team",
		Operation: OperationSign,
		KeyID:     "payments/signing-key",
	}
	dec := engine.Evaluate(req)
	if dec.Allowed {
		t.Fatal("ADVERSARIAL P-04: empty policy allowed an operation — deny-by-default violated")
	}
	if dec.DenyReason == "" {
		t.Fatal("empty policy: expected non-empty DenyReason")
	}
}

func TestEngine_NoMatchingRule_DeniesOperation(t *testing.T) {
	// Rule allows "ml-team" only; request from "payments-team" must be denied.
	engine := NewEngine(policyWith(
		allowRule("allow-ml", []string{"user@ml-team"}, []string{"ml-team"},
			[]string{OperationSign}, []string{"ml/"}),
	))

	dec := engine.Evaluate(Request{
		CallerID:  "user@payments-team",
		TeamID:    "payments-team",
		Operation: OperationSign,
		KeyID:     "payments/key",
	})
	if dec.Allowed {
		t.Fatal("operation allowed despite no matching rule for this identity")
	}
}

// ── Happy-path allow ──────────────────────────────────────────────────────────

func TestEngine_ExplicitAllow_MatchesAll(t *testing.T) {
	engine := NewEngine(policyWith(
		allowRule("allow-sign", []string{"bert@dev"}, []string{"dev-team"},
			[]string{OperationSign}, []string{""}),
	))

	dec := engine.Evaluate(Request{
		CallerID:  "bert@dev",
		TeamID:    "dev-team",
		Operation: OperationSign,
		KeyID:     "any/key",
	})
	if !dec.Allowed {
		t.Fatalf("expected allow, got deny: %s", dec.DenyReason)
	}
	if dec.MatchedRuleID != "allow-sign" {
		t.Fatalf("expected matched rule 'allow-sign', got %q", dec.MatchedRuleID)
	}
}

// ── Explicit deny ─────────────────────────────────────────────────────────────

func TestEngine_ExplicitDeny_BlocksOperation(t *testing.T) {
	engine := NewEngine(policyWith(
		denyRule("deny-decrypt", []string{"*"}, []string{"*"},
			[]string{OperationDecrypt}, []string{""}),
		allowRule("allow-all", []string{"*"}, []string{"*"},
			[]string{"*"}, []string{""}),
	))

	// Decrypt is blocked by the deny rule (first match wins).
	dec := engine.Evaluate(Request{
		CallerID:  "bert@dev",
		TeamID:    "dev-team",
		Operation: OperationDecrypt,
		KeyID:     "any/key",
	})
	if dec.Allowed {
		t.Fatal("ADVERSARIAL: explicit deny rule was bypassed by subsequent allow rule")
	}
	if dec.MatchedRuleID != "deny-decrypt" {
		t.Fatalf("expected deny rule 'deny-decrypt' to match, got %q", dec.MatchedRuleID)
	}

	// Sign is not covered by the deny rule; the allow-all rule permits it.
	dec = engine.Evaluate(Request{
		CallerID:  "bert@dev",
		TeamID:    "dev-team",
		Operation: OperationSign,
		KeyID:     "any/key",
	})
	if !dec.Allowed {
		t.Fatalf("sign should be allowed by allow-all: %s", dec.DenyReason)
	}
}

// ── First-match-wins ordering ─────────────────────────────────────────────────

func TestEngine_FirstMatchWins_DenyBeforeAllow(t *testing.T) {
	// Deny rule appears first; allow rule second.  Deny must win.
	engine := NewEngine(policyWith(
		denyRule("deny-first", []string{"bert@dev"}, []string{"dev-team"},
			[]string{OperationSign}, []string{""}),
		allowRule("allow-second", []string{"bert@dev"}, []string{"dev-team"},
			[]string{OperationSign}, []string{""}),
	))

	dec := engine.Evaluate(Request{
		CallerID:  "bert@dev",
		TeamID:    "dev-team",
		Operation: OperationSign,
		KeyID:     "key",
	})
	if dec.Allowed {
		t.Fatal("allow rule after deny rule should not override deny (first-match-wins)")
	}
	if dec.MatchedRuleID != "deny-first" {
		t.Fatalf("expected 'deny-first' to match, got %q", dec.MatchedRuleID)
	}
}

func TestEngine_FirstMatchWins_AllowBeforeDeny(t *testing.T) {
	// Allow rule first; deny rule second.  Allow wins.
	engine := NewEngine(policyWith(
		allowRule("allow-first", []string{"bert@dev"}, []string{"dev-team"},
			[]string{OperationSign}, []string{""}),
		denyRule("deny-second", []string{"bert@dev"}, []string{"dev-team"},
			[]string{OperationSign}, []string{""}),
	))

	dec := engine.Evaluate(Request{
		CallerID:  "bert@dev",
		TeamID:    "dev-team",
		Operation: OperationSign,
		KeyID:     "key",
	})
	if !dec.Allowed {
		t.Fatalf("allow rule before deny rule should win (first-match): %s", dec.DenyReason)
	}
}

// ── Wildcard matching ─────────────────────────────────────────────────────────

func TestEngine_WildcardIdentity_MatchesAnyCallerID(t *testing.T) {
	engine := NewEngine(policyWith(
		allowRule("allow-any-id", []string{"*"}, []string{"dev-team"},
			[]string{OperationSign}, []string{""}),
	))

	for _, callerID := range []string{"alice@dev", "bob@dev", "ci-runner@dev"} {
		dec := engine.Evaluate(Request{
			CallerID:  callerID,
			TeamID:    "dev-team",
			Operation: OperationSign,
			KeyID:     "key",
		})
		if !dec.Allowed {
			t.Errorf("wildcard identity should match %q: %s", callerID, dec.DenyReason)
		}
	}
}

func TestEngine_WildcardTeam_MatchesAnyTeam(t *testing.T) {
	engine := NewEngine(policyWith(
		allowRule("allow-any-team", []string{"bert@dev"}, []string{"*"},
			[]string{OperationEncrypt}, []string{""}),
	))

	for _, teamID := range []string{"dev-team", "payments-team", "ml-team"} {
		dec := engine.Evaluate(Request{
			CallerID:  "bert@dev",
			TeamID:    teamID,
			Operation: OperationEncrypt,
			KeyID:     "key",
		})
		if !dec.Allowed {
			t.Errorf("wildcard team should match %q: %s", teamID, dec.DenyReason)
		}
	}
}

func TestEngine_WildcardOperation_MatchesAnyOperation(t *testing.T) {
	engine := NewEngine(policyWith(
		allowRule("allow-any-op", []string{"bert@dev"}, []string{"dev-team"},
			[]string{"*"}, []string{""}),
	))

	for _, op := range []string{OperationSign, OperationEncrypt, OperationDecrypt, OperationListKeys} {
		dec := engine.Evaluate(Request{
			CallerID:  "bert@dev",
			TeamID:    "dev-team",
			Operation: op,
			KeyID:     "key",
		})
		if !dec.Allowed {
			t.Errorf("wildcard operation should match %q: %s", op, dec.DenyReason)
		}
	}
}

// ── Key prefix matching ───────────────────────────────────────────────────────

func TestEngine_KeyPrefix_MatchesPrefixedKeys(t *testing.T) {
	engine := NewEngine(policyWith(
		allowRule("allow-payments", []string{"bert@dev"}, []string{"dev-team"},
			[]string{OperationSign}, []string{"payments/"}),
	))

	cases := []struct {
		keyID   string
		allowed bool
	}{
		{"payments/signing-key", true},
		{"payments/enc-key", true},
		{"ml/key", false},
		{"infrastructure/key", false},
		{"", false}, // empty key ID
	}

	for _, tc := range cases {
		dec := engine.Evaluate(Request{
			CallerID:  "bert@dev",
			TeamID:    "dev-team",
			Operation: OperationSign,
			KeyID:     tc.keyID,
		})
		if dec.Allowed != tc.allowed {
			t.Errorf("key %q: want allowed=%v, got allowed=%v (%s)",
				tc.keyID, tc.allowed, dec.Allowed, dec.DenyReason)
		}
	}
}

func TestEngine_KeyPrefix_EmptyString_MatchesAll(t *testing.T) {
	engine := NewEngine(policyWith(
		allowRule("allow-all-keys", []string{"bert@dev"}, []string{"dev-team"},
			[]string{OperationSign}, []string{""}),
	))

	for _, keyID := range []string{"payments/key", "ml/key", "personal/key", "anything"} {
		dec := engine.Evaluate(Request{
			CallerID:  "bert@dev",
			TeamID:    "dev-team",
			Operation: OperationSign,
			KeyID:     keyID,
		})
		if !dec.Allowed {
			t.Errorf("empty prefix should match key %q: %s", keyID, dec.DenyReason)
		}
	}
}

func TestEngine_KeyPrefix_Star_MatchesAll(t *testing.T) {
	engine := NewEngine(policyWith(
		allowRule("allow-star", []string{"bert@dev"}, []string{"dev-team"},
			[]string{OperationSign}, []string{"*"}),
	))

	for _, keyID := range []string{"payments/key", "", "x"} {
		dec := engine.Evaluate(Request{
			CallerID:  "bert@dev",
			TeamID:    "dev-team",
			Operation: OperationSign,
			KeyID:     keyID,
		})
		if !dec.Allowed {
			t.Errorf("'*' prefix should match key %q: %s", keyID, dec.DenyReason)
		}
	}
}

// ── ADVERSARIAL — empty fields never match wildcard ───────────────────────────

func TestEngine_EmptyCallerID_DeniedEvenWithWildcard(t *testing.T) {
	engine := NewEngine(policyWith(
		allowRule("allow-all", []string{"*"}, []string{"*"}, []string{"*"}, []string{""}),
	))

	dec := engine.Evaluate(Request{
		CallerID:  "", // empty — unauthenticated
		TeamID:    "dev-team",
		Operation: OperationSign,
		KeyID:     "key",
	})
	if dec.Allowed {
		t.Fatal("ADVERSARIAL: empty CallerID matched '*' wildcard — unauthenticated identity permitted")
	}
}

func TestEngine_EmptyTeamID_DeniedEvenWithWildcard(t *testing.T) {
	engine := NewEngine(policyWith(
		allowRule("allow-all", []string{"*"}, []string{"*"}, []string{"*"}, []string{""}),
	))

	dec := engine.Evaluate(Request{
		CallerID:  "bert@dev",
		TeamID:    "", // empty — no team context
		Operation: OperationSign,
		KeyID:     "key",
	})
	if dec.Allowed {
		t.Fatal("ADVERSARIAL: empty TeamID matched '*' wildcard")
	}
}

func TestEngine_EmptyOperation_DeniedEvenWithWildcard(t *testing.T) {
	engine := NewEngine(policyWith(
		allowRule("allow-all", []string{"*"}, []string{"*"}, []string{"*"}, []string{""}),
	))

	dec := engine.Evaluate(Request{
		CallerID:  "bert@dev",
		TeamID:    "dev-team",
		Operation: "", // empty — unknown operation
		KeyID:     "key",
	})
	if dec.Allowed {
		t.Fatal("ADVERSARIAL: empty Operation matched '*' wildcard")
	}
}

// ── Identity namespace isolation ──────────────────────────────────────────────

func TestEngine_TeamIsolation_CrossTeamKeyAccessDenied(t *testing.T) {
	// payments-team's key can only be accessed by payments-team members.
	engine := NewEngine(policyWith(
		allowRule("payments-key-access",
			[]string{"*"}, []string{"payments-team"},
			[]string{OperationSign}, []string{"payments/"}),
		allowRule("ml-key-access",
			[]string{"*"}, []string{"ml-team"},
			[]string{OperationSign}, []string{"ml/"}),
	))

	// payments-team member accessing payments key: allowed.
	dec := engine.Evaluate(Request{
		CallerID:  "user@payments-team",
		TeamID:    "payments-team",
		Operation: OperationSign,
		KeyID:     "payments/signing-key",
	})
	if !dec.Allowed {
		t.Fatalf("payments user should access payments key: %s", dec.DenyReason)
	}

	// payments-team member trying to access ml key: denied.
	dec = engine.Evaluate(Request{
		CallerID:  "user@payments-team",
		TeamID:    "payments-team",
		Operation: OperationSign,
		KeyID:     "ml/signing-key",
	})
	if dec.Allowed {
		t.Fatal("ADVERSARIAL: payments-team member accessed ml-team key — namespace isolation failed")
	}
}

// ── Loader: validate ──────────────────────────────────────────────────────────

func TestValidatePolicyFile_EmptyRuleID_Error(t *testing.T) {
	pf := policyWith(Rule{
		ID:          "",
		Identities:  []string{"*"},
		Teams:       []string{"*"},
		Operations:  []string{"*"},
		KeyPrefixes: []string{""},
		Effect:      EffectAllow,
	})
	if err := validatePolicyFile(pf); err == nil {
		t.Fatal("expected error for empty rule ID, got nil")
	}
}

func TestValidatePolicyFile_DuplicateRuleID_Error(t *testing.T) {
	pf := policyWith(
		allowRule("dup", []string{"*"}, []string{"*"}, []string{"*"}, []string{""}),
		allowRule("dup", []string{"*"}, []string{"*"}, []string{"*"}, []string{""}),
	)
	if err := validatePolicyFile(pf); err == nil {
		t.Fatal("expected error for duplicate rule ID, got nil")
	}
}

func TestValidatePolicyFile_UnknownEffect_Error(t *testing.T) {
	pf := policyWith(Rule{
		ID:          "bad-effect",
		Identities:  []string{"*"},
		Teams:       []string{"*"},
		Operations:  []string{"*"},
		KeyPrefixes: []string{""},
		Effect:      "permit", // invalid
	})
	if err := validatePolicyFile(pf); err == nil {
		t.Fatal("expected error for unknown effect 'permit', got nil")
	}
}

func TestValidatePolicyFile_EmptyOperations_Error(t *testing.T) {
	pf := policyWith(Rule{
		ID:          "no-ops",
		Identities:  []string{"*"},
		Teams:       []string{"*"},
		Operations:  []string{}, // empty
		KeyPrefixes: []string{""},
		Effect:      EffectAllow,
	})
	if err := validatePolicyFile(pf); err == nil {
		t.Fatal("expected error for empty operations, got nil")
	}
}
