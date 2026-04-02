package policy

import (
	"strings"
	"testing"
)

// TestEffectIsValid verifies that only the two canonical effects are accepted.
func TestEffectIsValid(t *testing.T) {
	t.Parallel()

	valid := []Effect{EffectAllow, EffectDeny}
	for _, e := range valid {
		if !e.IsValid() {
			t.Errorf("Effect(%q).IsValid() = false; want true", e)
		}
	}

	invalid := []Effect{"", "permit", "ALLOW", "Deny", "accept", "reject"}
	for _, e := range invalid {
		if e.IsValid() {
			t.Errorf("Effect(%q).IsValid() = true; want false", e)
		}
	}
}

// TestOperationIsKnown verifies that all declared operations are recognised
// and that unknown strings are not.
func TestOperationIsKnown(t *testing.T) {
	t.Parallel()

	known := []Operation{
		OpSign, OpEncrypt, OpDecrypt, OpListKeys, OpRotateKey,
		OpCredentialVend, OpCredRefresh, OpAuth,
	}
	for _, op := range known {
		if !op.IsKnown() {
			t.Errorf("Operation(%q).IsKnown() = false; want true", op)
		}
	}

	unknown := []Operation{"", "SIGN", "Sign", "exec", "read", "delete"}
	for _, op := range unknown {
		if op.IsKnown() {
			t.Errorf("Operation(%q).IsKnown() = true; want false", op)
		}
	}
}

// TestPolicyValidate_EmptyRulesIsValid confirms that a zero-rule policy is
// valid (deny-by-default is correct behaviour, not an error).
func TestPolicyValidate_EmptyRulesIsValid(t *testing.T) {
	t.Parallel()

	p := Policy{Version: "1", Rules: nil}
	if err := p.Validate(); err != nil {
		t.Errorf("empty rules policy should be valid; got error: %v", err)
	}

	p2 := Policy{Version: "1", Rules: []Rule{}}
	if err := p2.Validate(); err != nil {
		t.Errorf("empty rules slice should be valid; got error: %v", err)
	}
}

// TestPolicyValidate_BadVersion checks that unsupported versions are rejected.
func TestPolicyValidate_BadVersion(t *testing.T) {
	t.Parallel()

	for _, v := range []string{"", "0", "2", "99", "v1", "1.0"} {
		p := Policy{Version: v}
		err := p.Validate()
		if err == nil {
			t.Errorf("version %q: expected validation error; got nil", v)
		}
	}
}

// TestPolicyValidate_ValidRule verifies that a well-formed rule passes.
func TestPolicyValidate_ValidRule(t *testing.T) {
	t.Parallel()

	p := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:          "test-rule",
				Description: "a valid rule",
				Match: Match{
					Identity:   IdentityMatch{TeamID: "team-a", Roles: []string{"developer"}},
					Operations: []Operation{OpSign},
					KeyPrefix:  "team-a/",
				},
				Effect: EffectAllow,
				TimeWindow: &TimeWindow{
					Days:     []string{"mon", "fri"},
					StartUTC: 8,
					EndUTC:   18,
				},
				RateLimit: &RateLimit{MaxRequests: 100, Window: "1h"},
			},
		},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("valid rule should pass validation; got: %v", err)
	}
}

// TestPolicyValidate_AllErrors is an adversarial test that checks every
// individual validation path.  Each sub-test injects exactly one flaw and
// asserts that validation fails and the error message is informative.
func TestPolicyValidate_AllErrors(t *testing.T) {
	t.Parallel()

	base := func() Rule {
		return Rule{
			ID:     "base-rule",
			Match:  Match{},
			Effect: EffectAllow,
		}
	}

	cases := []struct {
		name        string
		mutate      func(*Rule)
		wantErrSubs []string // substrings that must appear in error
	}{
		{
			name:        "empty id",
			mutate:      func(r *Rule) { r.ID = "" },
			wantErrSubs: []string{"id must not be empty"},
		},
		{
			name:        "unknown effect",
			mutate:      func(r *Rule) { r.Effect = "permit" },
			wantErrSubs: []string{"effect must be", "permit"},
		},
		{
			name:        "empty effect",
			mutate:      func(r *Rule) { r.Effect = "" },
			wantErrSubs: []string{"effect must be"},
		},
		{
			name:        "unknown operation",
			mutate:      func(r *Rule) { r.Match.Operations = []Operation{"sign", "explode"} },
			wantErrSubs: []string{"unknown operation", "explode"},
		},
		{
			name:        "unknown role",
			mutate:      func(r *Rule) { r.Match.Identity.Roles = []string{"developer", "overlord"} },
			wantErrSubs: []string{"unknown role", "overlord"},
		},
		{
			name: "time window start >= end",
			mutate: func(r *Rule) {
				r.TimeWindow = &TimeWindow{StartUTC: 22, EndUTC: 6}
			},
			wantErrSubs: []string{"start_utc", "end_utc"},
		},
		{
			name: "time window bad day",
			mutate: func(r *Rule) {
				r.TimeWindow = &TimeWindow{Days: []string{"monday"}, StartUTC: 8, EndUTC: 18}
			},
			wantErrSubs: []string{"weekday", "monday"},
		},
		{
			name: "time window start_utc out of range",
			mutate: func(r *Rule) {
				r.TimeWindow = &TimeWindow{StartUTC: 24, EndUTC: 6}
			},
			wantErrSubs: []string{"start_utc"},
		},
		{
			name: "key_ids and key_prefix both set",
			mutate: func(r *Rule) {
				r.Match.KeyPrefix = "foo/"
				r.Match.KeyIDs = []string{"foo/bar"}
			},
			wantErrSubs: []string{"mutually exclusive"},
		},
		{
			name: "rate_limit zero max_requests",
			mutate: func(r *Rule) {
				r.RateLimit = &RateLimit{MaxRequests: 0, Window: "1h"}
			},
			wantErrSubs: []string{"max_requests", "> 0"},
		},
		{
			name: "rate_limit empty window",
			mutate: func(r *Rule) {
				r.RateLimit = &RateLimit{MaxRequests: 10, Window: ""}
			},
			wantErrSubs: []string{"window"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := base()
			tc.mutate(&r)
			p := Policy{Version: "1", Rules: []Rule{r}}

			err := p.Validate()
			if err == nil {
				t.Fatalf("expected validation error for %q; got nil", tc.name)
			}
			for _, sub := range tc.wantErrSubs {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q should contain %q", err.Error(), sub)
				}
			}
		})
	}
}

// TestPolicyValidate_MalformedCallerIDPattern verifies that structurally
// invalid and semantically-degenerate glob patterns in CallerIDPattern are
// caught by Validate.
//
// SECURITY REGRESSION TEST: a malformed or reversed-range deny pattern
// silently matches nothing at runtime, meaning the deny never fires.
// Validation must catch this BEFORE the policy is accepted into the engine.
func TestPolicyValidate_MalformedCallerIDPattern(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		pattern    string
		wantSubstr string
	}{
		{
			name:       "unclosed bracket",
			pattern:    "ci-[unclosed",
			wantSubstr: "malformed glob",
		},
		{
			name:       "reversed character range [z-a]",
			pattern:    "[z-a]*",
			wantSubstr: "reversed character range",
		},
		{
			name:       "reversed range inside prefix",
			pattern:    "ci-[z-a]-service",
			wantSubstr: "reversed character range",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := Policy{
				Version: "1",
				Rules: []Rule{
					{
						ID:     "bad-pattern",
						Match:  Match{Identity: IdentityMatch{CallerIDPattern: tc.pattern}},
						Effect: EffectDeny,
					},
				},
			}
			err := p.Validate()
			if err == nil {
				t.Fatalf("expected validation error for pattern %q; got nil", tc.pattern)
			}
			if !strings.Contains(err.Error(), "caller_id_pattern") {
				t.Errorf("error should mention 'caller_id_pattern'; got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error should contain %q; got: %v", tc.wantSubstr, err)
			}
		})
	}

	// A valid glob pattern must pass.
	goodP := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "good",
				Match:  Match{Identity: IdentityMatch{CallerIDPattern: "ci-[a-z]*"}},
				Effect: EffectAllow,
			},
		},
	}
	if err := goodP.Validate(); err != nil {
		t.Errorf("valid pattern should pass validation; got: %v", err)
	}
}

// TestPolicyValidate_DuplicateRuleID checks that duplicate IDs are caught.
func TestPolicyValidate_DuplicateRuleID(t *testing.T) {
	t.Parallel()

	p := Policy{
		Version: "1",
		Rules: []Rule{
			{ID: "same-id", Match: Match{}, Effect: EffectAllow},
			{ID: "different-id", Match: Match{}, Effect: EffectAllow},
			{ID: "same-id", Match: Match{}, Effect: EffectDeny},
		},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate rule ID; got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error should mention 'duplicate'; got: %v", err)
	}
	if !strings.Contains(err.Error(), "same-id") {
		t.Errorf("error should name the duplicate ID; got: %v", err)
	}
}

// TestPolicyValidate_MultipleErrors verifies that ALL errors are reported in
// a single call, not just the first one.
func TestPolicyValidate_MultipleErrors(t *testing.T) {
	t.Parallel()

	p := Policy{
		Version: "1",
		Rules: []Rule{
			// Rule 1: missing ID + bad effect.
			{ID: "", Match: Match{}, Effect: "permit"},
			// Rule 2: valid (baseline to confirm partial passes work).
			{ID: "ok-rule", Match: Match{}, Effect: EffectAllow},
			// Rule 3: bad operation + bad role.
			{
				ID: "multi-bad",
				Match: Match{
					Operations: []Operation{"explode"},
					Identity:   IdentityMatch{Roles: []string{"overlord"}},
				},
				Effect: EffectDeny,
			},
		},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected validation errors; got nil")
	}
	// Must mention all three problems.
	for _, sub := range []string{"id must not be empty", "permit", "explode", "overlord"} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("combined error should contain %q; got: %v", sub, err)
		}
	}
}
