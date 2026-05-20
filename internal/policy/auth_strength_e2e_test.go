package policy

// auth_strength_e2e_test.go — End-to-end integration tests for the
// auth_strength policy hook using the example step-up policy.
//
// These tests cover the three canonical cases that demonstrate Phase 1
// piece #5 of the zero-trust agent identity rollout:
//
//   a) cert-only token + secret_purge → denied (no matching allow rule; falls
//      through to deny-by-default because the allow-secret-purge-step-up rule
//      requires cert+human and the cert-only token does not satisfy it).
//
//   b) cert+human token + secret_purge → allowed (auth_strength meets the
//      cert+human requirement; the allow-secret-purge-step-up rule matches).
//
//   c) cert-only token + secret_write → allowed (allow-registry-ops-cert-only
//      covers secret_write with cert-only; the step-up gate does not block
//      ordinary writes).
//
// The policy is loaded from the canonical example file so this test also
// acts as a parse/validate smoke test for that file.

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentkms/agentkms/pkg/identity"
)

// repoRoot returns the absolute path to the repository root, relative to this
// test file's location.  This lets LoadFromFile find the example policy
// regardless of the working directory the test runner uses.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file is .../internal/policy/auth_strength_e2e_test.go
	// Walk up two directories to reach the repo root.
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// examplePolicyPath returns the absolute path to docs/examples/policy-step-up.yaml.
func examplePolicyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "docs", "examples", "policy-step-up.yaml")
}

// TestPolicyStepUp_LoadExamplePolicy verifies that the example step-up policy
// file is parseable and contains the expected rules.  Fails fast if the file
// is missing or malformed so the sub-tests below don't produce confusing errors.
func TestPolicyStepUp_LoadExamplePolicy(t *testing.T) {
	p, err := LoadFromFile(examplePolicyPath(t))
	if err != nil {
		t.Fatalf("LoadFromFile(%q): %v", examplePolicyPath(t), err)
	}
	if len(p.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(p.Rules))
	}

	ruleIDs := make(map[string]struct{}, len(p.Rules))
	for _, r := range p.Rules {
		ruleIDs[r.ID] = struct{}{}
	}
	for _, want := range []string{
		"allow-all-crypto-ops",
		"allow-registry-ops-cert-only",
		"allow-secret-purge-step-up",
	} {
		if _, ok := ruleIDs[want]; !ok {
			t.Errorf("expected rule %q to be present in the policy", want)
		}
	}
}

// TestPolicyStepUp_AuthStrengthCases is the core integration test.
// It uses EvaluateAtWithStrength — the same code path that the production
// EngineI adapter uses — so the test exercises the real gate, not a mock.
func TestPolicyStepUp_AuthStrengthCases(t *testing.T) {
	p, err := LoadFromFile(examplePolicyPath(t))
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	eng := New(*p)

	caller := identity.Identity{
		CallerID: "bert@platform-team",
		TeamID:   "platform-team",
		Role:     identity.RoleDeveloper,
	}
	now := time.Now().UTC()

	t.Run("a_cert_only_purge_denied", func(t *testing.T) {
		d := eng.EvaluateAtWithStrength(caller, OpSecretPurge, "", "cert-only", now)
		if d.Allow {
			t.Fatalf("expected denied, got Allow=true (matched rule %q)", d.MatchedRuleID)
		}
		// The deny must come from deny-by-default (no rule matched), not from an
		// explicit deny rule.  The DenyReason must reference "policy" to confirm
		// it is from the engine (not a nil/zero Decision).
		if !strings.Contains(d.DenyReason, "policy") {
			t.Errorf("DenyReason %q does not contain 'policy'", d.DenyReason)
		}
	})

	t.Run("b_cert_human_purge_allowed", func(t *testing.T) {
		d := eng.EvaluateAtWithStrength(caller, OpSecretPurge, "", "cert+human", now)
		if !d.Allow {
			t.Fatalf("expected allowed, got Allow=false; DenyReason=%q", d.DenyReason)
		}
		if d.MatchedRuleID != "allow-secret-purge-step-up" {
			t.Errorf("expected matched rule %q, got %q", "allow-secret-purge-step-up", d.MatchedRuleID)
		}
	})

	t.Run("c_cert_only_write_allowed", func(t *testing.T) {
		d := eng.EvaluateAtWithStrength(caller, OpSecretWrite, "", "cert-only", now)
		if !d.Allow {
			t.Fatalf("expected allowed, got Allow=false; DenyReason=%q", d.DenyReason)
		}
		if d.MatchedRuleID != "allow-registry-ops-cert-only" {
			t.Errorf("expected matched rule %q, got %q", "allow-registry-ops-cert-only", d.MatchedRuleID)
		}
	})
}

// TestPolicyStepUp_ViaContext verifies the same three cases using the
// context-threading path (WithAuthStrength / AuthStrengthFromContext) that the
// engineIAdapter uses in production when an HTTP handler attaches the token's
// strength to the request context before calling Evaluate.
func TestPolicyStepUp_ViaContext(t *testing.T) {
	p, err := LoadFromFile(examplePolicyPath(t))
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	eng := AsEngineI(New(*p))

	caller := identity.Identity{
		CallerID: "ci-runner@platform-team",
		TeamID:   "platform-team",
		Role:     identity.RoleService,
	}

	t.Run("a_cert_only_purge_denied", func(t *testing.T) {
		ctx := WithAuthStrength(context.Background(), "cert-only")
		d, err := eng.Evaluate(ctx, caller, "secret_purge", "")
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if d.Allow {
			t.Fatalf("expected denied, got Allow=true")
		}
	})

	t.Run("b_cert_human_purge_allowed", func(t *testing.T) {
		ctx := WithAuthStrength(context.Background(), "cert+human")
		d, err := eng.Evaluate(ctx, caller, "secret_purge", "")
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !d.Allow {
			t.Fatalf("expected allowed, got Allow=false; DenyReason=%q", d.DenyReason)
		}
	})

	t.Run("c_cert_only_write_allowed", func(t *testing.T) {
		ctx := WithAuthStrength(context.Background(), "cert-only")
		d, err := eng.Evaluate(ctx, caller, "secret_write", "")
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !d.Allow {
			t.Fatalf("expected allowed, got Allow=false; DenyReason=%q", d.DenyReason)
		}
	})
}
