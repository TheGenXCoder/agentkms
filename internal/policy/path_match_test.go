package policy

import (
	"testing"
)

// TestPathPatternSupersecretDenyList verifies that a deny rule with
// path_pattern "supersecret/**" blocks metadata_list under that tree while
// a later catch-all allow still permits other paths.
func TestPathPatternSupersecretDenyList(t *testing.T) {
	t.Parallel()

	p := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:          "deny-supersecret-list",
				Description: "deny listing secrets under supersecret/",
				Match: Match{
					Operations:  []Operation{OpMetadataList},
					PathPattern: "supersecret/**",
				},
				Effect: EffectDeny,
			},
			{
				ID:          "allow-metadata-list",
				Description: "allow metadata_list for any path",
				Match: Match{
					Operations: []Operation{OpMetadataList},
				},
				Effect: EffectAllow,
			},
		},
	}
	eng := mustEngine(t, p)
	id := devID("platform-team", "alice")

	// Path under supersecret/ must be denied by the path_pattern rule.
	dec := eng.Evaluate(id, OpMetadataList, "supersecret/stripe")
	if dec.Allow {
		t.Errorf("supersecret/stripe: Allow=true; want false (path_pattern deny)")
	}
	if dec.MatchedRuleID != "deny-supersecret-list" {
		t.Errorf("supersecret/stripe: MatchedRuleID=%q; want deny-supersecret-list", dec.MatchedRuleID)
	}

	// Exact prefix path (no trailing segment) must also match /** semantics.
	dec = eng.Evaluate(id, OpMetadataList, "supersecret")
	if dec.Allow {
		t.Errorf("supersecret: Allow=true; want false (/** includes exact prefix)")
	}
	if dec.MatchedRuleID != "deny-supersecret-list" {
		t.Errorf("supersecret: MatchedRuleID=%q; want deny-supersecret-list", dec.MatchedRuleID)
	}

	// Nested path under supersecret/.
	dec = eng.Evaluate(id, OpMetadataList, "supersecret/team/a")
	if dec.Allow {
		t.Errorf("supersecret/team/a: Allow=true; want false")
	}

	// Unrelated path must fall through to the allow rule.
	dec = eng.Evaluate(id, OpMetadataList, "UTA/mssql-user")
	if !dec.Allow {
		t.Errorf("UTA/mssql-user: Allow=false (%s); want true", dec.DenyReason)
	}
	if dec.MatchedRuleID != "allow-metadata-list" {
		t.Errorf("UTA/mssql-user: MatchedRuleID=%q; want allow-metadata-list", dec.MatchedRuleID)
	}

	// Sibling that only shares a string prefix must not match supersecret/**.
	dec = eng.Evaluate(id, OpMetadataList, "supersecretX")
	if !dec.Allow {
		t.Errorf("supersecretX: Allow=false; want true (not under supersecret/)")
	}
}

// TestPathPatternLLMPrefix verifies single-segment globs via path.Match
// (e.g. llm/* matches llm/anthropic but not nested or unrelated paths).
func TestPathPatternLLMPrefix(t *testing.T) {
	t.Parallel()

	p := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:          "allow-llm-metadata",
				Description: "allow metadata_list only under llm/*",
				Match: Match{
					Operations:  []Operation{OpMetadataList},
					PathPattern: "llm/*",
				},
				Effect: EffectAllow,
			},
		},
	}
	eng := mustEngine(t, p)
	id := devID("platform-team", "alice")

	dec := eng.Evaluate(id, OpMetadataList, "llm/anthropic")
	if !dec.Allow {
		t.Errorf("llm/anthropic: Allow=false (%s); want true", dec.DenyReason)
	}
	if dec.MatchedRuleID != "allow-llm-metadata" {
		t.Errorf("llm/anthropic: MatchedRuleID=%q; want allow-llm-metadata", dec.MatchedRuleID)
	}

	// Nested under llm/ should not match llm/* (single segment only).
	dec = eng.Evaluate(id, OpMetadataList, "llm/providers/anthropic")
	if dec.Allow {
		t.Errorf("llm/providers/anthropic: Allow=true; want false (llm/* is single-segment)")
	}

	// Unrelated path denied by default.
	dec = eng.Evaluate(id, OpMetadataList, "UTA/x")
	if dec.Allow {
		t.Errorf("UTA/x: Allow=true; want false")
	}
	if dec.DenyReason != denyByDefaultReason {
		t.Errorf("UTA/x: DenyReason=%q; want deny-by-default", dec.DenyReason)
	}
}

// TestPathPattern_KeyIDsPrecedence verifies that a non-empty KeyIDs list
// wins over path_pattern (exact IDs only).
func TestPathPattern_KeyIDsPrecedence(t *testing.T) {
	t.Parallel()

	p := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID: "keyids-win",
				Match: Match{
					Operations:  []Operation{OpMetadataList},
					KeyIDs:      []string{"exact/only"},
					PathPattern: "llm/*",
				},
				Effect: EffectAllow,
			},
		},
	}
	eng := mustEngine(t, p)
	id := devID("platform-team", "alice")

	if dec := eng.Evaluate(id, OpMetadataList, "exact/only"); !dec.Allow {
		t.Errorf("exact/only: Allow=false; want true (KeyIDs match)")
	}
	// Would match path_pattern but KeyIDs takes precedence — not in list.
	if dec := eng.Evaluate(id, OpMetadataList, "llm/anthropic"); dec.Allow {
		t.Errorf("llm/anthropic: Allow=true; want false (KeyIDs non-empty ignores path_pattern)")
	}
}

// TestPathPattern_OverKeyPrefix verifies path_pattern is preferred over
// KeyPrefix when KeyIDs is empty.
func TestPathPattern_OverKeyPrefix(t *testing.T) {
	t.Parallel()

	p := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID: "pattern-over-prefix",
				Match: Match{
					Operations:  []Operation{OpMetadataList},
					KeyPrefix:   "ignored/",
					PathPattern: "llm/*",
				},
				Effect: EffectAllow,
			},
		},
	}
	eng := mustEngine(t, p)
	id := devID("platform-team", "alice")

	if dec := eng.Evaluate(id, OpMetadataList, "llm/x"); !dec.Allow {
		t.Errorf("llm/x: Allow=false; want true (path_pattern)")
	}
	// KeyPrefix would allow this, but path_pattern takes precedence.
	if dec := eng.Evaluate(id, OpMetadataList, "ignored/secret"); dec.Allow {
		t.Errorf("ignored/secret: Allow=true; want false (KeyPrefix ignored when path_pattern set)")
	}
}

// TestPathMatchesUnit covers pathMatches helper edge cases directly.
func TestPathMatchesUnit(t *testing.T) {
	t.Parallel()

	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"", "any/path", true}, // empty = match all
		{"supersecret/**", "supersecret", true},
		{"supersecret/**", "supersecret/", true}, // prefix + "/"
		{"supersecret/**", "supersecret/a", true},
		{"supersecret/**", "supersecret/a/b", true},
		{"supersecret/**", "supersecretX", false},
		{"supersecret/**", "other", false},
		{"llm/*", "llm/anthropic", true},
		{"llm/*", "llm/a/b", false},
		{"llm/*", "llm", false},
		{"*", "foo", true},
		{"*", "foo/bar", false}, // path.Match * does not cross /
	}
	for _, tc := range cases {
		got := pathMatches(tc.pattern, tc.path)
		if got != tc.want {
			t.Errorf("pathMatches(%q, %q) = %v; want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

// TestPolicyValidate_PathPattern rejects malformed path_pattern globs.
func TestPolicyValidate_PathPattern(t *testing.T) {
	t.Parallel()

	// Valid pattern passes.
	p := Policy{
		Version: "1",
		Rules: []Rule{{
			ID:     "ok",
			Match:  Match{PathPattern: "supersecret/**"},
			Effect: EffectAllow,
		}},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("valid path_pattern rejected: %v", err)
	}

	// Empty path_pattern is fine (match-all).
	p = Policy{
		Version: "1",
		Rules: []Rule{{
			ID:     "empty-ok",
			Match:  Match{PathPattern: ""},
			Effect: EffectAllow,
		}},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("empty path_pattern rejected: %v", err)
	}

	// Malformed bracket expression must fail validation.
	p = Policy{
		Version: "1",
		Rules: []Rule{{
			ID:     "bad",
			Match:  Match{PathPattern: "foo["},
			Effect: EffectAllow,
		}},
	}
	if err := p.Validate(); err == nil {
		t.Error("malformed path_pattern accepted; want validation error")
	}
}
