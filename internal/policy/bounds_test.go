package policy

// bounds_test.go — B1 Step 2: Acceptance tests for policy bounds parsing.
//
// These tests define the acceptance criteria for populating
// Decision.AllowedBounds when a rule has a `bounds:` section in its YAML.
//
// These tests are EXPECTED TO FAIL until the feature is implemented.

import (
	"testing"
	"time"
)

// ── Test 1: Allow rule with bounds section populates AllowedBounds ───────────

func TestBounds_AllowWithBounds_PopulatesAllowedBounds(t *testing.T) {
	t.Parallel()

	yamlPolicy := []byte(`
version: "1"
rules:
  - id: allow-github-for-developers
    effect: allow
    match:
      identity:
        roles: [developer]
      operations: [credential_vend]
    bounds:
      kind: github-pat
      max_params:
        repositories: ["acmecorp/*"]
        permissions: ["contents:write", "pull_requests:write"]
      max_ttl: 8h
`)

	p, err := LoadFromBytes(yamlPolicy)
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}

	engine := New(*p)
	dec := engine.Evaluate(devID("platform-team", "alice"), OpCredentialVend, "github/token")

	if !dec.Allow {
		t.Fatalf("expected allow; got deny: %s", dec.DenyReason)
	}
	if dec.AllowedBounds == nil {
		t.Fatal("expected AllowedBounds to be populated; got nil")
	}
	if dec.AllowedBounds.Kind != "github-pat" {
		t.Errorf("AllowedBounds.Kind = %q; want %q", dec.AllowedBounds.Kind, "github-pat")
	}
	if dec.AllowedBounds.MaxTTL != 8*time.Hour {
		t.Errorf("AllowedBounds.MaxTTL = %v; want %v", dec.AllowedBounds.MaxTTL, 8*time.Hour)
	}

	// Check MaxParams
	if dec.AllowedBounds.MaxParams == nil {
		t.Fatal("AllowedBounds.MaxParams is nil; want populated map")
	}
	repos, ok := dec.AllowedBounds.MaxParams["repositories"]
	if !ok {
		t.Fatal("MaxParams missing 'repositories' key")
	}
	repoSlice, ok := repos.([]any)
	if !ok {
		t.Fatalf("MaxParams['repositories'] type = %T; want []any", repos)
	}
	if len(repoSlice) != 1 || repoSlice[0] != "acmecorp/*" {
		t.Errorf("MaxParams['repositories'] = %v; want [acmecorp/*]", repoSlice)
	}

	perms, ok := dec.AllowedBounds.MaxParams["permissions"]
	if !ok {
		t.Fatal("MaxParams missing 'permissions' key")
	}
	permSlice, ok := perms.([]any)
	if !ok {
		t.Fatalf("MaxParams['permissions'] type = %T; want []any", perms)
	}
	if len(permSlice) != 2 {
		t.Errorf("MaxParams['permissions'] length = %d; want 2", len(permSlice))
	}
}

// ── Test 2: Deny decision has nil AllowedBounds even if rule has bounds ──────

func TestBounds_DenyDecision_AllowedBoundsNil(t *testing.T) {
	t.Parallel()

	yamlPolicy := []byte(`
version: "1"
rules:
  - id: deny-all-agents
    effect: deny
    match:
      identity:
        roles: [developer]
      operations: [credential_vend]
  - id: allow-with-bounds
    effect: allow
    match:
      identity:
        roles: [developer]
      operations: [credential_vend]
    bounds:
      kind: github-pat
      max_ttl: 4h
`)

	p, err := LoadFromBytes(yamlPolicy)
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}

	engine := New(*p)
	dec := engine.Evaluate(devID("platform-team", "alice"), OpCredentialVend, "github/token")

	if dec.Allow {
		t.Fatal("expected deny (first-match deny rule); got allow")
	}
	if dec.AllowedBounds != nil {
		t.Errorf("denied decision should have nil AllowedBounds; got %+v", dec.AllowedBounds)
	}
}

// ── Test 3: Allow rule without bounds section → AllowedBounds nil ────────────

func TestBounds_AllowWithoutBounds_AllowedBoundsNil(t *testing.T) {
	t.Parallel()

	policy := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "allow-no-bounds",
				Effect: EffectAllow,
				Match: Match{
					Identity:   IdentityMatch{Roles: []string{"developer"}},
					Operations: []Operation{OpCredentialVend},
				},
			},
		},
	}

	engine := mustEngine(t, policy)
	dec := engine.Evaluate(devID("platform-team", "alice"), OpCredentialVend, "some/key")

	if !dec.Allow {
		t.Fatalf("expected allow; got deny: %s", dec.DenyReason)
	}
	if dec.AllowedBounds != nil {
		t.Errorf("expected AllowedBounds to be nil for rule without bounds; got %+v", dec.AllowedBounds)
	}
}

// ── Test 4: Bounds max_ttl parsed as time.Duration ───────────────────────────

func TestBounds_MaxTTL_ParsedAsDuration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		ttlYAML  string
		wantTTL  time.Duration
	}{
		{"8 hours", "8h", 8 * time.Hour},
		{"30 minutes", "30m", 30 * time.Minute},
		{"1h30m", "1h30m", 90 * time.Minute},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			yamlPolicy := []byte(`
version: "1"
rules:
  - id: allow-with-ttl
    effect: allow
    match:
      identity:
        roles: [developer]
      operations: [credential_vend]
    bounds:
      kind: test-cred
      max_ttl: ` + tc.ttlYAML + `
`)

			p, err := LoadFromBytes(yamlPolicy)
			if err != nil {
				t.Fatalf("LoadFromBytes failed: %v", err)
			}

			engine := New(*p)
			dec := engine.Evaluate(devID("team", "alice"), OpCredentialVend, "key")

			if !dec.Allow {
				t.Fatalf("expected allow; got deny: %s", dec.DenyReason)
			}
			if dec.AllowedBounds == nil {
				t.Fatal("expected AllowedBounds to be populated; got nil")
			}
			if dec.AllowedBounds.MaxTTL != tc.wantTTL {
				t.Errorf("AllowedBounds.MaxTTL = %v; want %v", dec.AllowedBounds.MaxTTL, tc.wantTTL)
			}
		})
	}
}

// ── Test 5: Bounds with empty max_params does not panic ──────────────────────

func TestBounds_EmptyMaxParams_NoPanic(t *testing.T) {
	t.Parallel()

	yamlPolicy := []byte(`
version: "1"
rules:
  - id: allow-empty-params
    effect: allow
    match:
      identity:
        roles: [developer]
      operations: [credential_vend]
    bounds:
      kind: minimal-cred
      max_ttl: 1h
`)

	p, err := LoadFromBytes(yamlPolicy)
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}

	engine := New(*p)
	dec := engine.Evaluate(devID("team", "alice"), OpCredentialVend, "key")

	if !dec.Allow {
		t.Fatalf("expected allow; got deny: %s", dec.DenyReason)
	}
	if dec.AllowedBounds == nil {
		t.Fatal("expected AllowedBounds to be populated; got nil")
	}
	if dec.AllowedBounds.Kind != "minimal-cred" {
		t.Errorf("AllowedBounds.Kind = %q; want %q", dec.AllowedBounds.Kind, "minimal-cred")
	}
	// MaxParams should be nil or empty — either is acceptable; must not panic.
	if dec.AllowedBounds.MaxParams != nil && len(dec.AllowedBounds.MaxParams) != 0 {
		t.Errorf("AllowedBounds.MaxParams = %v; want nil or empty", dec.AllowedBounds.MaxParams)
	}
}

// ── Test 6: Bounds kind field correctly propagated ───────────────────────────

func TestBounds_KindField_Propagated(t *testing.T) {
	t.Parallel()

	yamlPolicy := []byte(`
version: "1"
rules:
  - id: allow-aws-cred
    effect: allow
    match:
      identity:
        roles: [service]
      operations: [credential_vend]
    bounds:
      kind: aws-sts
      max_ttl: 1h
`)

	p, err := LoadFromBytes(yamlPolicy)
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}

	engine := New(*p)
	dec := engine.Evaluate(svcID("infra-team", "deployer"), OpCredentialVend, "aws/role")

	if !dec.Allow {
		t.Fatalf("expected allow; got deny: %s", dec.DenyReason)
	}
	if dec.AllowedBounds == nil {
		t.Fatal("expected AllowedBounds to be populated; got nil")
	}
	if dec.AllowedBounds.Kind != "aws-sts" {
		t.Errorf("AllowedBounds.Kind = %q; want %q", dec.AllowedBounds.Kind, "aws-sts")
	}
}

// ── Test 7: First matching allow rule's bounds are used ──────────────────────

func TestBounds_FirstMatchingAllowRule_BoundsUsed(t *testing.T) {
	t.Parallel()

	yamlPolicy := []byte(`
version: "1"
rules:
  - id: allow-narrow-bounds
    effect: allow
    match:
      identity:
        roles: [developer]
      operations: [credential_vend]
      key_prefix: "github/"
    bounds:
      kind: github-pat
      max_params:
        repositories: ["acmecorp/frontend"]
      max_ttl: 2h
  - id: allow-wide-bounds
    effect: allow
    match:
      identity:
        roles: [developer]
      operations: [credential_vend]
    bounds:
      kind: github-pat
      max_params:
        repositories: ["acmecorp/*"]
      max_ttl: 24h
`)

	p, err := LoadFromBytes(yamlPolicy)
	if err != nil {
		t.Fatalf("LoadFromBytes failed: %v", err)
	}

	engine := New(*p)

	// This should match the first rule (key_prefix "github/")
	dec := engine.Evaluate(devID("platform-team", "alice"), OpCredentialVend, "github/token")

	if !dec.Allow {
		t.Fatalf("expected allow; got deny: %s", dec.DenyReason)
	}
	if dec.AllowedBounds == nil {
		t.Fatal("expected AllowedBounds from first matching rule; got nil")
	}
	if dec.AllowedBounds.MaxTTL != 2*time.Hour {
		t.Errorf("AllowedBounds.MaxTTL = %v; want %v (from first matching rule)", dec.AllowedBounds.MaxTTL, 2*time.Hour)
	}
	if dec.MatchedRuleID != "allow-narrow-bounds" {
		t.Errorf("MatchedRuleID = %q; want %q", dec.MatchedRuleID, "allow-narrow-bounds")
	}

	repos, ok := dec.AllowedBounds.MaxParams["repositories"]
	if !ok {
		t.Fatal("MaxParams missing 'repositories' from first matching rule")
	}
	repoSlice, ok := repos.([]any)
	if !ok {
		t.Fatalf("MaxParams['repositories'] type = %T; want []any", repos)
	}
	if len(repoSlice) != 1 || repoSlice[0] != "acmecorp/frontend" {
		t.Errorf("MaxParams['repositories'] = %v; want [acmecorp/frontend] (from first rule, not second)",
			repoSlice)
	}
}
