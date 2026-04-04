package policy

// engine_test.go — Tests for P-03 (evaluator) and P-04 (deny-by-default).
//
// P-04 CRITICAL TEST: TestDenyByDefault_EmptyPolicy proves that an engine
// backed by an empty (zero-rule) policy denies ALL operations for ALL
// identities across ALL key IDs.  This test must never be skipped.
//
// Additional tests cover:
//   - Explicit allow and deny rules
//   - First-match semantics (deny before allow wins)
//   - Identity dimension matching (team, caller pattern, role)
//   - Key matching (prefix and explicit list)
//   - Operation list matching
//   - Time-window matching
//   - Adversarial inputs (unrecognised operations, empty key IDs, etc.)
//   - Reload atomicity (new policy takes effect immediately)

import (
	"fmt"
	"testing"
	"time"

	"github.com/agentkms/agentkms/pkg/identity"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// devID returns a developer Identity for the given team and caller name.
func devID(team, caller string) identity.Identity {
	return identity.Identity{
		CallerID: caller + "@" + team,
		TeamID:   team,
		Role:     identity.RoleDeveloper,
	}
}

// svcID returns a service Identity.
func svcID(team, caller string) identity.Identity {
	return identity.Identity{
		CallerID: caller + "@" + team,
		TeamID:   team,
		Role:     identity.RoleService,
	}
}

// agentID returns an agent-session Identity.
func agentID(team, caller string) identity.Identity {
	return identity.Identity{
		CallerID:     caller + "@" + team,
		TeamID:       team,
		Role:         identity.RoleAgent,
		AgentSession: "sess-abc123",
	}
}

// mustEngine builds an Engine from a Policy, failing the test if validation
// fails.  It simplifies the common case of constructing well-formed policies
// inline.
func mustEngine(t *testing.T, p Policy) *Engine {
	t.Helper()
	if err := p.Validate(); err != nil {
		t.Fatalf("policy.Validate() failed: %v", err)
	}
	return New(p)
}

// allOps returns the complete set of known operations.
func allOps() []Operation {
	return []Operation{
		OpSign, OpEncrypt, OpDecrypt, OpListKeys, OpRotateKey,
		OpCredentialVend, OpCredRefresh, OpAuth,
	}
}

// ── P-04: Deny-by-default ─────────────────────────────────────────────────────

// TestDenyByDefault_EmptyPolicy is the authoritative P-04 test.
//
// REQUIREMENT: An Engine with zero rules MUST deny every possible
// (identity, operation, key-id) triple.  There must be no combination of
// inputs that produces Allow=true when the policy has no rules.
//
// Coverage matrix:
//   - 3 identity types (developer, service, agent) × 3 teams = 9 identities
//   - 8 operations
//   - 5 key IDs (including empty string and a key that looks like a wildcard)
//     = 360 total evaluations, all of which must produce Allow=false.
func TestDenyByDefault_EmptyPolicy(t *testing.T) {
	t.Parallel()

	// Both a nil-Rules and an empty-Rules-slice policy must behave the same.
	policies := []struct {
		name   string
		policy Policy
	}{
		{"nil rules", Policy{Version: "1", Rules: nil}},
		{"empty rules slice", Policy{Version: "1", Rules: []Rule{}}},
	}

	identities := []identity.Identity{
		devID("platform-team", "alice"),
		devID("payments-team", "bob"),
		devID("ml-team", "charlie"),
		svcID("platform-team", "ci-runner"),
		svcID("payments-team", "deploy-bot"),
		svcID("ml-team", "trainer"),
		agentID("platform-team", "pi-agent"),
		agentID("payments-team", "pi-agent"),
		agentID("ml-team", "pi-agent"),
	}

	keyIDs := []string{
		"",                        // empty key ID
		"payments/signing-key",    // namespace-qualified key
		"platform/jwt-key",        // another namespace
		"*",                       // wildcard string (must NOT match as a glob)
		"production/critical-key", // production key
	}

	for _, pc := range policies {
		pc := pc
		t.Run(pc.name, func(t *testing.T) {
			t.Parallel()

			engine := New(pc.policy) // Do NOT call mustEngine — zero rules is intentionally valid.

			for _, id := range identities {
				for _, op := range allOps() {
					for _, keyID := range keyIDs {
						dec := engine.Evaluate(id, op, keyID)
						if dec.Allow {
							t.Errorf(
								"DENY-BY-DEFAULT VIOLATED: empty policy allowed operation\n"+
									"  identity:  %+v\n"+
									"  operation: %q\n"+
									"  key_id:    %q",
								id, op, keyID,
							)
						}
						if dec.DenyReason == "" {
							t.Errorf(
								"denied decision must carry a DenyReason (identity=%+v op=%q keyID=%q)",
								id, op, keyID,
							)
						}
						if dec.MatchedRuleID != "" {
							t.Errorf(
								"deny-by-default should have empty MatchedRuleID; got %q (identity=%+v op=%q keyID=%q)",
								dec.MatchedRuleID, id, op, keyID,
							)
						}
					}
				}
			}
		})
	}
}

// TestDenyByDefault_DenyReasonIsCanonical verifies that the deny-by-default
// DenyReason string is the exported constant, so callers can match on it
// without hardcoding the string in multiple places.
func TestDenyByDefault_DenyReasonIsCanonical(t *testing.T) {
	t.Parallel()

	engine := New(Policy{Version: "1"})
	dec := engine.Evaluate(devID("any-team", "alice"), OpSign, "some/key")

	if dec.Allow {
		t.Fatal("expected deny; got allow")
	}
	if dec.DenyReason != denyByDefaultReason {
		t.Errorf("DenyReason = %q; want constant denyByDefaultReason = %q",
			dec.DenyReason, denyByDefaultReason)
	}
}

// ── Explicit allow ────────────────────────────────────────────────────────────

// TestEvaluate_ExplicitAllow verifies that a matching allow rule produces
// Allow=true with the correct MatchedRuleID.
func TestEvaluate_ExplicitAllow(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID: "allow-platform-sign",
				Match: Match{
					Identity:   IdentityMatch{TeamID: "platform-team", Roles: []string{"developer"}},
					Operations: []Operation{OpSign},
					KeyPrefix:  "platform/",
				},
				Effect: EffectAllow,
			},
		},
	})

	dec := engine.Evaluate(devID("platform-team", "alice"), OpSign, "platform/signing-key")
	if !dec.Allow {
		t.Fatalf("expected allow; got deny: %q", dec.DenyReason)
	}
	if dec.MatchedRuleID != "allow-platform-sign" {
		t.Errorf("MatchedRuleID = %q; want \"allow-platform-sign\"", dec.MatchedRuleID)
	}
}

// TestEvaluate_ExplicitDeny verifies that a matching deny rule produces
// Allow=false with a reason naming the rule.
func TestEvaluate_ExplicitDeny(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:          "deny-agents-production",
				Description: "agents may not touch production keys",
				Match: Match{
					Identity:  IdentityMatch{Roles: []string{"agent"}},
					KeyPrefix: "production/",
				},
				Effect: EffectDeny,
			},
		},
	})

	dec := engine.Evaluate(agentID("platform-team", "pi"), OpSign, "production/signing-key")
	if dec.Allow {
		t.Fatal("expected deny; got allow")
	}
	if dec.MatchedRuleID != "deny-agents-production" {
		t.Errorf("MatchedRuleID = %q; want \"deny-agents-production\"", dec.MatchedRuleID)
	}
	if dec.DenyReason == "" {
		t.Error("explicit deny must have a non-empty DenyReason")
	}
}

// ── First-match semantics ─────────────────────────────────────────────────────

// TestEvaluate_DenyBeforeAllowWins confirms that when a deny rule appears
// before an allow rule and both match, the deny takes precedence.
func TestEvaluate_DenyBeforeAllowWins(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			// Deny first.
			{
				ID:     "deny-alice",
				Match:  Match{Identity: IdentityMatch{CallerIDPattern: "alice@*"}},
				Effect: EffectDeny,
			},
			// Allow second — should never be reached for alice.
			{
				ID:     "allow-platform-team",
				Match:  Match{Identity: IdentityMatch{TeamID: "platform-team"}},
				Effect: EffectAllow,
			},
		},
	})

	// Alice hits the deny rule.
	dec := engine.Evaluate(devID("platform-team", "alice"), OpSign, "any/key")
	if dec.Allow {
		t.Fatal("deny rule should have blocked alice before allow rule was reached")
	}
	if dec.MatchedRuleID != "deny-alice" {
		t.Errorf("MatchedRuleID = %q; want \"deny-alice\"", dec.MatchedRuleID)
	}

	// Bob (same team as Alice but a different caller) hits the allow rule.
	dec2 := engine.Evaluate(devID("platform-team", "bob"), OpSign, "any/key")
	if !dec2.Allow {
		t.Fatalf("bob should be allowed by second rule; got deny: %q", dec2.DenyReason)
	}
	if dec2.MatchedRuleID != "allow-platform-team" {
		t.Errorf("MatchedRuleID = %q; want \"allow-platform-team\"", dec2.MatchedRuleID)
	}
}

// TestEvaluate_AllowBeforeDenyWins confirms the converse: if an allow rule
// appears before a deny rule, the allow takes effect.
func TestEvaluate_AllowBeforeDenyWins(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			// Allow first.
			{
				ID:     "allow-bob",
				Match:  Match{Identity: IdentityMatch{CallerIDPattern: "bob@*"}},
				Effect: EffectAllow,
			},
			// Deny second — should never be reached for bob.
			{
				ID:     "deny-platform-team",
				Match:  Match{Identity: IdentityMatch{TeamID: "platform-team"}},
				Effect: EffectDeny,
			},
		},
	})

	dec := engine.Evaluate(devID("platform-team", "bob"), OpSign, "any/key")
	if !dec.Allow {
		t.Fatalf("bob should be allowed; got deny: %q", dec.DenyReason)
	}
	if dec.MatchedRuleID != "allow-bob" {
		t.Errorf("MatchedRuleID = %q; want \"allow-bob\"", dec.MatchedRuleID)
	}
}

// ── Identity matching ─────────────────────────────────────────────────────────

// TestEvaluate_TeamIDMismatch checks that a rule with a TeamID constraint
// does not apply to a caller from a different team.
func TestEvaluate_TeamIDMismatch(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "allow-platform",
				Match:  Match{Identity: IdentityMatch{TeamID: "platform-team"}},
				Effect: EffectAllow,
			},
		},
	})

	// Wrong team → deny by default.
	dec := engine.Evaluate(devID("payments-team", "alice"), OpSign, "any/key")
	if dec.Allow {
		t.Fatal("wrong-team caller should not be allowed by a team-scoped rule")
	}
	if dec.DenyReason != denyByDefaultReason {
		t.Errorf("DenyReason = %q; want default deny reason", dec.DenyReason)
	}
}

// TestEvaluate_CallerIDGlobMatching exercises glob pattern matching for
// CallerIDPattern across several patterns and subjects.
func TestEvaluate_CallerIDGlobMatching(t *testing.T) {
	t.Parallel()

	cases := []struct {
		pattern   string
		callerID  string
		wantMatch bool
	}{
		// Exact match.
		{"alice@platform-team", "alice@platform-team", true},
		{"alice@platform-team", "bob@platform-team", false},
		// Prefix glob.
		{"ci-*", "ci-runner@payments", true},
		{"ci-*", "ci-deploy@ml", true},
		{"ci-*", "alice@platform", false},
		// Suffix glob.
		{"*@platform-team", "alice@platform-team", true},
		{"*@platform-team", "bob@platform-team", true},
		{"*@platform-team", "alice@payments-team", false},
		// Full wildcard (matches any non-empty CallerID).
		{"*", "anyone@anywhere", true},
		// Empty pattern (no constraint) → always matches.
		{"", "anyone@anywhere", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("pattern=%q subject=%q", tc.pattern, tc.callerID), func(t *testing.T) {
			t.Parallel()

			engine := mustEngine(t, Policy{
				Version: "1",
				Rules: []Rule{
					{
						ID: "test-rule",
						Match: Match{
							Identity: IdentityMatch{CallerIDPattern: tc.pattern},
						},
						Effect: EffectAllow,
					},
				},
			})

			id := identity.Identity{
				CallerID: tc.callerID,
				TeamID:   "any-team",
				Role:     identity.RoleDeveloper,
			}
			dec := engine.Evaluate(id, OpSign, "some/key")
			if dec.Allow != tc.wantMatch {
				t.Errorf("pattern %q vs subject %q: Allow=%v; want %v",
					tc.pattern, tc.callerID, dec.Allow, tc.wantMatch)
			}
		})
	}
}

// TestEvaluate_RoleMismatch checks that a role-scoped rule does not match a
// caller with a different role.
func TestEvaluate_RoleMismatch(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "allow-developers-only",
				Match:  Match{Identity: IdentityMatch{Roles: []string{"developer"}}},
				Effect: EffectAllow,
			},
		},
	})

	// Service identity → should NOT match the developer-only rule.
	dec := engine.Evaluate(svcID("any-team", "ci"), OpSign, "any/key")
	if dec.Allow {
		t.Fatal("service identity should not match developer-only rule")
	}

	// Agent identity → should NOT match either.
	dec2 := engine.Evaluate(agentID("any-team", "pi"), OpSign, "any/key")
	if dec2.Allow {
		t.Fatal("agent identity should not match developer-only rule")
	}

	// Developer → should match.
	dec3 := engine.Evaluate(devID("any-team", "alice"), OpSign, "any/key")
	if !dec3.Allow {
		t.Fatalf("developer identity should match rule; got deny: %q", dec3.DenyReason)
	}
}

// TestEvaluate_MultipleRoleConstraint checks that "roles: [developer, service]"
// allows both but not agent.
func TestEvaluate_MultipleRoleConstraint(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "allow-dev-and-svc",
				Match:  Match{Identity: IdentityMatch{Roles: []string{"developer", "service"}}},
				Effect: EffectAllow,
			},
		},
	})

	if dec := engine.Evaluate(devID("t", "a"), OpSign, "k"); !dec.Allow {
		t.Errorf("developer should be allowed; got deny: %q", dec.DenyReason)
	}
	if dec := engine.Evaluate(svcID("t", "s"), OpSign, "k"); !dec.Allow {
		t.Errorf("service should be allowed; got deny: %q", dec.DenyReason)
	}
	if dec := engine.Evaluate(agentID("t", "p"), OpSign, "k"); dec.Allow {
		t.Error("agent should NOT be allowed by dev+svc rule")
	}
}

// ── Key matching ──────────────────────────────────────────────────────────────

// TestEvaluate_KeyPrefixMatching verifies prefix-based key matching.
func TestEvaluate_KeyPrefixMatching(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "allow-payments-keys",
				Match:  Match{KeyPrefix: "payments/"},
				Effect: EffectAllow,
			},
		},
	})

	allow := []string{"payments/signing-key", "payments/encrypt-key", "payments/sub/key"}
	for _, k := range allow {
		dec := engine.Evaluate(devID("any", "a"), OpSign, k)
		if !dec.Allow {
			t.Errorf("key %q should match prefix \"payments/\"; got deny: %q", k, dec.DenyReason)
		}
	}

	deny := []string{"", "platform/key", "ml/key", "Payments/key", "payments"} // "payments" lacks trailing /
	for _, k := range deny {
		dec := engine.Evaluate(devID("any", "a"), OpSign, k)
		if dec.Allow {
			t.Errorf("key %q should NOT match prefix \"payments/\"", k)
		}
	}
}

// TestEvaluate_KeyIDsExplicitList verifies exact-match key ID lists.
func TestEvaluate_KeyIDsExplicitList(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID: "allow-specific-keys",
				Match: Match{
					KeyIDs: []string{"ml/model-key", "ml/training-key"},
				},
				Effect: EffectAllow,
			},
		},
	})

	if dec := engine.Evaluate(devID("t", "a"), OpEncrypt, "ml/model-key"); !dec.Allow {
		t.Errorf("ml/model-key should be allowed; got deny: %q", dec.DenyReason)
	}
	if dec := engine.Evaluate(devID("t", "a"), OpEncrypt, "ml/training-key"); !dec.Allow {
		t.Errorf("ml/training-key should be allowed; got deny: %q", dec.DenyReason)
	}
	if dec := engine.Evaluate(devID("t", "a"), OpEncrypt, "ml/other-key"); dec.Allow {
		t.Error("ml/other-key should NOT be allowed by explicit key ID list")
	}
	if dec := engine.Evaluate(devID("t", "a"), OpEncrypt, "ml/"); dec.Allow {
		t.Error("ml/ should NOT be allowed — prefix would match but key_ids takes precedence")
	}
}

// ── Operation matching ────────────────────────────────────────────────────────

// TestEvaluate_OperationListMatching verifies that operation constraints
// are respected.
func TestEvaluate_OperationListMatching(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID: "sign-only",
				Match: Match{
					Operations: []Operation{OpSign},
				},
				Effect: EffectAllow,
			},
		},
	})

	if dec := engine.Evaluate(devID("t", "a"), OpSign, "k"); !dec.Allow {
		t.Errorf("sign should be allowed; got deny: %q", dec.DenyReason)
	}
	for _, op := range []Operation{OpEncrypt, OpDecrypt, OpListKeys, OpRotateKey, OpCredentialVend} {
		if dec := engine.Evaluate(devID("t", "a"), op, "k"); dec.Allow {
			t.Errorf("op %q should NOT be allowed by sign-only rule", op)
		}
	}
}

// TestEvaluate_EmptyOperationListMatchesAll verifies that a rule with no
// operations constraint matches all operations.
func TestEvaluate_EmptyOperationListMatchesAll(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "allow-all-ops",
				Match:  Match{Operations: nil},
				Effect: EffectAllow,
			},
		},
	})

	for _, op := range allOps() {
		dec := engine.Evaluate(devID("t", "a"), op, "k")
		if !dec.Allow {
			t.Errorf("op %q should be allowed by empty-operations rule; got deny: %q", op, dec.DenyReason)
		}
	}
}

// ── Time-window matching ──────────────────────────────────────────────────────

// TestEvaluate_TimeWindow verifies that operations outside the allowed time
// window are denied, and operations inside are allowed.
func TestEvaluate_TimeWindow(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID: "business-hours-only",
				Match: Match{
					Identity: IdentityMatch{TeamID: "platform-team"},
				},
				Effect: EffectAllow,
				TimeWindow: &TimeWindow{
					Days:     []string{"mon", "tue", "wed", "thu", "fri"},
					StartUTC: 6,
					EndUTC:   22,
				},
			},
		},
	})

	id := devID("platform-team", "alice")

	// Monday at 10:00 UTC — inside window.
	mon10 := time.Date(2026, 3, 30, 10, 0, 0, 0, time.UTC) // Monday
	if dec := engine.EvaluateAt(id, OpSign, "k", mon10); !dec.Allow {
		t.Errorf("Monday 10:00 UTC should be inside window; got deny: %q", dec.DenyReason)
	}

	// Monday at 05:59 UTC — before window opens.
	mon05 := time.Date(2026, 3, 30, 5, 59, 0, 0, time.UTC)
	if dec := engine.EvaluateAt(id, OpSign, "k", mon05); dec.Allow {
		t.Error("Monday 05:59 UTC should be outside window (before 06:00)")
	}

	// Monday at 22:00 UTC — exactly at EndUTC (exclusive).
	mon22 := time.Date(2026, 3, 30, 22, 0, 0, 0, time.UTC)
	if dec := engine.EvaluateAt(id, OpSign, "k", mon22); dec.Allow {
		t.Error("Monday 22:00 UTC should be outside window (EndUTC is exclusive)")
	}

	// Monday at 21:59 UTC — inside window.
	mon21 := time.Date(2026, 3, 30, 21, 59, 0, 0, time.UTC)
	if dec := engine.EvaluateAt(id, OpSign, "k", mon21); !dec.Allow {
		t.Errorf("Monday 21:59 UTC should be inside window; got deny: %q", dec.DenyReason)
	}

	// Saturday at 10:00 UTC — wrong day.
	sat10 := time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC) // Saturday
	if dec := engine.EvaluateAt(id, OpSign, "k", sat10); dec.Allow {
		t.Error("Saturday should be outside Mon–Fri window")
	}
}

// TestEvaluate_NoTimeWindowAlwaysMatches verifies that a rule without a
// TimeWindow is not restricted to any time.
func TestEvaluate_NoTimeWindowAlwaysMatches(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "always-allow",
				Match:  Match{},
				Effect: EffectAllow,
			},
		},
	})

	// Midnight on any given day should still allow.
	midnight := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if dec := engine.EvaluateAt(devID("t", "a"), OpSign, "k", midnight); !dec.Allow {
		t.Errorf("rule without time window should match at midnight; got deny: %q", dec.DenyReason)
	}
}

// ── Compound / integration scenarios ─────────────────────────────────────────

// TestEvaluate_FullFixturePolicy loads the full YAML fixture and validates
// its evaluation behaviour across a set of representative cases.
func TestEvaluate_FullFixturePolicy(t *testing.T) {
	t.Parallel()

	p, err := LoadFromFile("testdata/valid_full.yaml")
	if err != nil {
		t.Fatalf("loading fixture: %v", err)
	}
	engine := New(*p)

	// Monday at 10:00 UTC — inside the business-hours window.
	mon10 := time.Date(2026, 3, 30, 10, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		id        identity.Identity
		op        Operation
		keyID     string
		now       time.Time
		wantAllow bool
	}{
		// Agent sessions may not access production/ keys (explicit deny).
		{
			name:      "agent denied production key",
			id:        agentID("platform-team", "pi"),
			op:        OpSign,
			keyID:     "production/signing-key",
			now:       mon10,
			wantAllow: false,
		},
		// Platform-team developer may sign payments/ keys during business hours.
		{
			name:      "platform dev signs payments key in hours",
			id:        devID("platform-team", "alice"),
			op:        OpSign,
			keyID:     "payments/signing-key",
			now:       mon10,
			wantAllow: true,
		},
		// Same developer outside business hours — should be denied.
		{
			name:      "platform dev signs payments key outside hours",
			id:        devID("platform-team", "alice"),
			op:        OpSign,
			keyID:     "payments/signing-key",
			now:       time.Date(2026, 3, 30, 2, 0, 0, 0, time.UTC), // 02:00 UTC Monday
			wantAllow: false,
		},
		// CI service account may sign ci/ keys at any time.
		{
			name:      "ci service signs ci key midnight",
			id:        svcID("any-team", "ci-runner"),
			op:        OpSign,
			keyID:     "ci/build-key",
			now:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			wantAllow: true,
		},
		// CI service account cannot sign non-ci/ keys.
		{
			name:      "ci service denied payments key",
			id:        svcID("any-team", "ci-runner"),
			op:        OpSign,
			keyID:     "payments/signing-key",
			now:       mon10,
			wantAllow: false,
		},
		// ML team may encrypt specific approved keys.
		{
			name:      "ml developer encrypts approved key",
			id:        devID("ml-team", "dana"),
			op:        OpEncrypt,
			keyID:     "ml/model-weights-key",
			now:       mon10,
			wantAllow: true,
		},
		// ML team may NOT encrypt a key not in their approved list.
		{
			name:      "ml developer denied unapproved key",
			id:        devID("ml-team", "dana"),
			op:        OpEncrypt,
			keyID:     "ml/other-key",
			now:       mon10,
			wantAllow: false,
		},
		// Completely unrelated identity and key → deny by default.
		{
			name:      "unknown identity denied everything",
			id:        devID("rogue-team", "attacker"),
			op:        OpSign,
			keyID:     "production/secret-key",
			now:       mon10,
			wantAllow: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dec := engine.EvaluateAt(tc.id, tc.op, tc.keyID, tc.now)
			if dec.Allow != tc.wantAllow {
				t.Errorf("Evaluate(%+v, %q, %q) Allow=%v; want %v (DenyReason=%q MatchedRule=%q)",
					tc.id, tc.op, tc.keyID, dec.Allow, tc.wantAllow, dec.DenyReason, dec.MatchedRuleID)
			}
		})
	}
}

// ── Reload ────────────────────────────────────────────────────────────────────

// TestEngine_Reload verifies that Reload atomically swaps the policy and that
// subsequent evaluations use the new policy.
func TestEngine_Reload(t *testing.T) {
	t.Parallel()

	// Start with a policy that allows sign.
	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{ID: "allow-sign", Match: Match{Operations: []Operation{OpSign}}, Effect: EffectAllow},
		},
	})

	id := devID("t", "a")
	if dec := engine.Evaluate(id, OpSign, "k"); !dec.Allow {
		t.Fatalf("before reload: expected allow; got deny: %q", dec.DenyReason)
	}

	// Reload with an empty policy (deny everything).
	err := engine.Reload(Policy{Version: "1"})
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	if dec := engine.Evaluate(id, OpSign, "k"); dec.Allow {
		t.Error("after reload to empty policy: expected deny; got allow")
	}
}

// TestEngine_DeepCopy_MutationIsolation verifies that mutating inner slices on
// the source Policy after calling New() has no effect on the engine's
// evaluation — confirming that copyPolicy produces a deep copy.
//
// SECURITY REGRESSION TEST (Finding 2): a shallow copy would allow a caller
// who retains the *Policy to silently expand a rule's Operations, KeyIDs, or
// Roles after construction, bypassing the validation that was performed at
// New() / Reload() time.
//
// All assertions use EvaluateAt with a fixed Monday-10:00-UTC timestamp so
// that time-window evaluation is deterministic regardless of when the test
// runs.
func TestEngine_DeepCopy_MutationIsolation(t *testing.T) {
	t.Parallel()

	// A Monday inside the 06–22 UTC window.
	mon10 := time.Date(2026, 3, 30, 10, 0, 0, 0, time.UTC)
	// A Saturday — outside the Mon-only window.
	sat10 := time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC)

	src := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID: "sign-only",
				Match: Match{
					Operations: []Operation{OpSign},
					Identity:   IdentityMatch{Roles: []string{"developer"}},
					KeyIDs:     []string{"platform/key"},
				},
				Effect: EffectAllow,
				TimeWindow: &TimeWindow{
					Days:     []string{"mon"},
					StartUTC: 6,
					EndUTC:   22,
				},
			},
		},
	}
	engine := mustEngine(t, src)

	id := devID("any-team", "alice")

	// Before mutation: sign on platform/key on a Monday must be allowed.
	if dec := engine.EvaluateAt(id, OpSign, "platform/key", mon10); !dec.Allow {
		t.Fatalf("before mutation: expected allow on Monday; got deny: %q", dec.DenyReason)
	}
	// Before mutation: encrypt must be denied (not in Operations).
	if dec := engine.EvaluateAt(id, OpEncrypt, "platform/key", mon10); dec.Allow {
		t.Fatal("before mutation: expected deny for encrypt; got allow")
	}
	// Before mutation: Saturday must be denied (not in Days).
	if dec := engine.EvaluateAt(id, OpSign, "platform/key", sat10); dec.Allow {
		t.Fatal("before mutation: expected deny on Saturday; got allow")
	}

	// Mutate the source policy's inner slices — these must NOT affect the engine.
	src.Rules[0].Match.Operations = append(src.Rules[0].Match.Operations, OpEncrypt)
	src.Rules[0].Match.KeyIDs = append(src.Rules[0].Match.KeyIDs, "production/secret")
	src.Rules[0].Match.Identity.Roles = append(src.Rules[0].Match.Identity.Roles, "agent")
	src.Rules[0].TimeWindow.Days = append(src.Rules[0].TimeWindow.Days, "sat")

	// After mutation: engine must still deny encrypt on Monday — Operations slice was isolated.
	if dec := engine.EvaluateAt(id, OpEncrypt, "platform/key", mon10); dec.Allow {
		t.Error("after mutating source Operations: engine allowed encrypt — copyPolicy is not deep enough")
	}
	// After mutation: engine must still deny production/secret — KeyIDs slice was isolated.
	if dec := engine.EvaluateAt(id, OpSign, "production/secret", mon10); dec.Allow {
		t.Error("after mutating source KeyIDs: engine allowed production/secret — copyPolicy is not deep enough")
	}
	// After mutation: engine must still deny agent role — Roles slice was isolated.
	agent := agentID("any-team", "pi")
	if dec := engine.EvaluateAt(agent, OpSign, "platform/key", mon10); dec.Allow {
		t.Error("after mutating source Roles: engine allowed agent — copyPolicy is not deep enough")
	}
	// After mutation: engine must still deny Saturday — TimeWindow.Days slice was isolated.
	if dec := engine.EvaluateAt(id, OpSign, "platform/key", sat10); dec.Allow {
		t.Error("after mutating TimeWindow.Days: engine allowed Saturday — copyPolicy is not deep enough")
	}
}

// TestEngine_Reload_RejectsBadPolicy ensures that Reload rejects an invalid
// policy and leaves the existing policy unchanged.
func TestEngine_Reload_RejectsBadPolicy(t *testing.T) {
	t.Parallel()

	// Start with a permissive policy.
	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{ID: "allow-all", Match: Match{}, Effect: EffectAllow},
		},
	})

	// Attempt to reload with an invalid policy (bad version).
	err := engine.Reload(Policy{Version: "99"})
	if err == nil {
		t.Fatal("Reload with bad policy should return error; got nil")
	}

	// Existing policy must still be in effect.
	if dec := engine.Evaluate(devID("t", "a"), OpSign, "k"); !dec.Allow {
		t.Error("existing policy should still allow after failed reload")
	}
}

// ── Adversarial inputs ────────────────────────────────────────────────────────

// TestEvaluate_EmptyKeyIDNeverMatchesKeyConstraints verifies that an empty
// key ID does not accidentally match a key prefix or key ID list constraint.
func TestEvaluate_EmptyKeyIDNeverMatchesKeyConstraints(t *testing.T) {
	t.Parallel()

	enginePrefix := mustEngine(t, Policy{
		Version: "1",
		Rules:   []Rule{{ID: "r", Match: Match{KeyPrefix: "payments/"}, Effect: EffectAllow}},
	})
	if dec := enginePrefix.Evaluate(devID("t", "a"), OpSign, ""); dec.Allow {
		t.Error("empty key ID should not match non-empty key prefix")
	}

	engineIDs := mustEngine(t, Policy{
		Version: "1",
		Rules:   []Rule{{ID: "r", Match: Match{KeyIDs: []string{"payments/key"}}, Effect: EffectAllow}},
	})
	if dec := engineIDs.Evaluate(devID("t", "a"), OpSign, ""); dec.Allow {
		t.Error("empty key ID should not match explicit key ID list")
	}
}

// TestEvaluate_NoKeyConstraintMatchesAnyKey verifies that a rule without
// any key constraint applies to all key IDs, including empty string.
func TestEvaluate_NoKeyConstraintMatchesAnyKey(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{ID: "r", Match: Match{}, Effect: EffectAllow},
		},
	})

	for _, k := range []string{"", "any/key", "production/secret", "*", "🔑"} {
		if dec := engine.Evaluate(devID("t", "a"), OpSign, k); !dec.Allow {
			t.Errorf("no-key-constraint rule should allow key %q; got deny: %q", k, dec.DenyReason)
		}
	}
}

// TestEvaluate_WildcardKeyIDStringNotTreatedAsGlob verifies that the literal
// string "*" as a key ID is treated as an exact key ID, not as a glob pattern
// that matches all keys.
func TestEvaluate_WildcardKeyIDStringNotTreatedAsGlob(t *testing.T) {
	t.Parallel()

	// Rule allows ONLY the key whose ID is literally "*".
	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{ID: "r", Match: Match{KeyIDs: []string{"*"}}, Effect: EffectAllow},
		},
	})

	// The literal "*" key should be allowed.
	if dec := engine.Evaluate(devID("t", "a"), OpSign, "*"); !dec.Allow {
		t.Errorf("literal key ID \"*\" should be allowed; got deny: %q", dec.DenyReason)
	}

	// Any other key should be denied — "*" is not a glob here.
	for _, k := range []string{"", "any/key", "production/secret"} {
		if dec := engine.Evaluate(devID("t", "a"), OpSign, k); dec.Allow {
			t.Errorf("key %q should NOT match literal key ID \"*\"", k)
		}
	}
}

// TestEvaluate_DenyReasonNeverContainsKeyMaterial is a security smoke-test
// that verifies the DenyReason field does not contain substrings that look
// like private key material.  This is a structural check — the real guarantee
// is in the design of the Decision type, but the test catches regressions.
func TestEvaluate_DenyReasonNeverContainsKeyMaterial(t *testing.T) {
	t.Parallel()

	engine := mustEngine(t, Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:          "explicit-deny",
				Description: "some rule description",
				Match:       Match{},
				Effect:      EffectDeny,
			},
		},
	})

	dec := engine.Evaluate(devID("t", "a"), OpSign, "payments/signing-key")
	if dec.Allow {
		t.Fatal("expected deny")
	}

	// DenyReason must not contain anything that looks like base64 key material
	// or a key value.  We check for common exfiltration patterns.
	reason := dec.DenyReason
	badPatterns := []string{
		"BEGIN PRIVATE KEY",
		"BEGIN EC PRIVATE KEY",
		"BEGIN RSA PRIVATE KEY",
		"AAAA", // base64 prefix of common key types
	}
	for _, bad := range badPatterns {
		if contains := len(reason) > 0 && len(bad) > 0; contains {
			// Simple substring check.
			found := false
			for i := 0; i <= len(reason)-len(bad); i++ {
				if reason[i:i+len(bad)] == bad {
					found = true
					break
				}
			}
			if found {
				t.Errorf("DenyReason contains suspicious pattern %q: %q", bad, reason)
			}
		}
	}
}
