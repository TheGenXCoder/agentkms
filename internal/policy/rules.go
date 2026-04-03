package policy

// rules.go — P-01: Policy rule schema.
//
// The schema is deliberately narrow:
//   - Every dimension has an explicit empty-means-any semantic that is
//     documented in each field comment.
//   - Effect is always explicit ("allow" or "deny") — there is no implicit
//     default effect on a matched rule; the default is handled by the engine.
//   - Rate limiting fields are parsed and enforced by the engine (P-06).
//
// YAML tags drive the on-disk format.  All fields also carry json tags so
// that the structs can be serialised to JSON for logging and debugging
// without leaking unintended information.
//
// Dependency note: this file imports only the standard library.  The YAML
// library (gopkg.in/yaml.v3) is used only in loader.go.

import (
	"fmt"
	"path"
	"strings"
	"time"
)

// ── Operation ─────────────────────────────────────────────────────────────────

// Operation identifies a cryptographic or administrative operation in the
// policy rule schema.  Values are lowercase strings with underscore separators
// to match the audit log Operation* constants.
type Operation string

const (
	// OpSign — sign a payload hash with an asymmetric key.
	OpSign Operation = "sign"

	// OpEncrypt — encrypt plaintext with a symmetric or asymmetric key.
	OpEncrypt Operation = "encrypt"

	// OpDecrypt — decrypt ciphertext produced by OpEncrypt.
	OpDecrypt Operation = "decrypt"

	// OpListKeys — list key metadata (never key material) for a scope.
	OpListKeys Operation = "list_keys"

	// OpRotateKey — rotate a key to a new version.
	OpRotateKey Operation = "rotate_key"

	// OpCredentialVend — vend a short-lived LLM provider credential.
	OpCredentialVend Operation = "credential_vend"

	// OpCredRefresh — refresh a previously vended LLM credential.
	OpCredRefresh Operation = "credential_refresh"

	// OpAuth — issue or refresh a session token.
	OpAuth Operation = "auth"
)

// allOperations is the canonical set of known operations.
// Any operation not in this set is rejected by Validate.
var allOperations = map[Operation]struct{}{
	OpSign:           {},
	OpEncrypt:        {},
	OpDecrypt:        {},
	OpListKeys:       {},
	OpRotateKey:      {},
	OpCredentialVend: {},
	OpCredRefresh:    {},
	OpAuth:           {},
}

// IsKnown reports whether op is a recognised operation value.
func (op Operation) IsKnown() bool {
	_, ok := allOperations[op]
	return ok
}

// ── Effect ────────────────────────────────────────────────────────────────────

// Effect is the outcome applied when a Rule's Match conditions are satisfied.
type Effect string

const (
	// EffectAllow explicitly permits the operation for matching identities.
	EffectAllow Effect = "allow"

	// EffectDeny explicitly prohibits the operation for matching identities.
	// A deny rule that matches takes priority over any later allow rule
	// (first-match semantics; see engine.go).
	EffectDeny Effect = "deny"
)

// IsValid reports whether e is a known Effect value.
func (e Effect) IsValid() bool {
	return e == EffectAllow || e == EffectDeny
}

// ── Weekday helpers ───────────────────────────────────────────────────────────

// validWeekdays is the set of accepted day abbreviations for TimeWindow.Days.
var validWeekdays = map[string]struct{}{
	"mon": {}, "tue": {}, "wed": {}, "thu": {}, "fri": {}, "sat": {}, "sun": {},
}

// isValidWeekday reports whether d (case-insensitive) is a valid weekday token.
func isValidWeekday(d string) bool {
	_, ok := validWeekdays[strings.ToLower(d)]
	return ok
}

// ── Schema structs ────────────────────────────────────────────────────────────

// Policy is the top-level document loaded from a policy file.
//
// Schema version "1" is the only currently supported value.
// A zero-rule Policy is valid and results in deny-by-default for all
// operations — this is intentional.
type Policy struct {
	// Version identifies the schema version.  Must be "1".
	Version string `yaml:"version" json:"version"`

	// Rules is the ordered list of policy rules.  Rules are evaluated in
	// declaration order; the first matching rule determines the outcome.
	// An empty Rules slice means no operation is ever allowed (deny by default).
	Rules []Rule `yaml:"rules" json:"rules"`
}

// Rule is a single policy entry that maps a set of match conditions to an
// effect (allow or deny).
//
// Rules are evaluated in the order they appear in the policy document.
// The first rule whose Match conditions are all satisfied determines the
// outcome.  If no rule matches, the engine denies by default.
type Rule struct {
	// ID is a human-readable identifier for this rule.  Must be unique within
	// the policy document.  Used in audit log DenyReason fields so that
	// operators can trace a denial back to the specific rule.
	// Required; must be non-empty.
	ID string `yaml:"id" json:"id"`

	// Description is an optional human-readable explanation of the rule's
	// intent.  Not interpreted by the engine.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// Match defines the conditions that must ALL be satisfied for this rule to
	// apply.  All match dimensions are ANDed together.
	Match Match `yaml:"match" json:"match"`

	// Effect is the outcome when all Match conditions are satisfied.
	// Must be "allow" or "deny".
	Effect Effect `yaml:"effect" json:"effect"`

	// RateLimit optionally limits the number of matching operations within a
	// rolling time window.  When the limit is exceeded, the rule's effect is
	// not applied; instead, the engine returns a rate-limit denial.  The
	// operation still counts as "matched" for first-match purposes — it does
	// NOT fall through to a later rule.
	RateLimit *RateLimit `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`

	// TimeWindow optionally restricts when this rule may match.  If the
	// current UTC time falls outside the window, the rule is skipped even
	// if all other conditions match.
	TimeWindow *TimeWindow `yaml:"time_window,omitempty" json:"time_window,omitempty"`
}

// Match defines the set of conditions that must all be true for a rule to
// apply to a given (identity, operation, key-id) triple.
//
// All conditions are ANDed together.  An empty condition (zero value) always
// matches — see individual field documentation for the exact semantics.
type Match struct {
	// Identity constrains which callers this rule applies to.
	// A zero-value IdentityMatch matches any caller.
	Identity IdentityMatch `yaml:"identity" json:"identity"`

	// Operations is the list of operations this rule covers.
	// Empty (or omitted) means the rule applies to ALL operations.
	// Each value must be a known Operation constant.
	Operations []Operation `yaml:"operations,omitempty" json:"operations,omitempty"`

	// KeyPrefix restricts this rule to keys whose ID begins with the given
	// string.  Empty (or omitted) means the rule applies to all key IDs.
	//
	// If KeyIDs is also non-empty, a key must appear in KeyIDs; KeyPrefix is
	// then ignored.  Use one or the other, not both, to avoid confusion.
	KeyPrefix string `yaml:"key_prefix,omitempty" json:"key_prefix,omitempty"`

	// KeyIDs is an explicit allowlist of key IDs.  If non-empty, the key
	// being operated on must appear exactly in this list.  KeyPrefix is
	// ignored when KeyIDs is non-empty.
	KeyIDs []string `yaml:"key_ids,omitempty" json:"key_ids,omitempty"`
}

// IdentityMatch constrains which callers a rule applies to.
//
// All specified fields are ANDed.  A zero-value IdentityMatch (all fields
// empty) matches any caller — this is useful for broad deny rules but should
// be used carefully in allow rules.
type IdentityMatch struct {
	// TeamID restricts this rule to a specific team.
	// Must be an exact match against identity.TeamID.
	// Empty means "any team".
	TeamID string `yaml:"team_id,omitempty" json:"team_id,omitempty"`

	// CallerIDPattern is a glob pattern matched against identity.CallerID.
	// Glob syntax follows path.Match semantics: '*' matches any sequence of
	// non-separator characters, '?' matches a single non-separator character.
	// The path separator is '/' — since CallerIDs never contain '/', '*'
	// effectively matches any substring.
	//
	// Examples:
	//   "*@platform-team"  — any caller in platform-team
	//   "ci-*"             — any caller whose ID starts with "ci-"
	//   ""                 — any caller (no pattern constraint applied)
	CallerIDPattern string `yaml:"caller_id_pattern,omitempty" json:"caller_id_pattern,omitempty"`

	// Roles restricts this rule to callers with one of the listed roles.
	// Each value must be one of: "developer", "service", "agent".
	// Empty means "any role".
	Roles []string `yaml:"roles,omitempty" json:"roles,omitempty"`
}

// RateLimit restricts the number of matched operations within a rolling
// time window.
//
// Rate limiting is enforced per (rule, callerID) bucket.
// Two different callers hitting the same rule get independent counters.
// A single caller hitting the same rule for different operations or key IDs
// shares one counter — the budget is consumed across all matching operations
// and key IDs within that rule.  This is intentionally conservative: a caller
// cannot reset the rate limit by switching operation types or key IDs.
//
// The sliding window is implemented by tracking the timestamps of each
// request and pruning entries older than the window duration.
type RateLimit struct {
	// MaxRequests is the maximum number of matched operations allowed within
	// the rolling Window.  Must be > 0.
	MaxRequests int `yaml:"max_requests" json:"max_requests"`

	// Window is the duration of the rolling time window, expressed as a Go
	// duration string (e.g. "1h", "5m", "24h").
	// Must be parseable by time.ParseDuration.
	Window string `yaml:"window" json:"window"`

	// WindowDuration is the parsed form of Window.  Set by Validate() after
	// successful parsing.  Excluded from YAML and JSON serialisation.
	// Zero means the window has not been parsed (should not happen after
	// a successful Validate() call).
	WindowDuration time.Duration `yaml:"-" json:"-"`
}

// TimeWindow restricts a rule to specific UTC days and hours.
//
// The rule only matches if the current UTC time falls within the specified
// window.  If both Days and StartUTC/EndUTC are zero values, the rule
// matches at all times (no temporal constraint).
type TimeWindow struct {
	// Days is the list of weekdays on which this rule may match.
	// Accepted values (case-insensitive): "mon", "tue", "wed", "thu", "fri",
	// "sat", "sun".  Empty means any day of the week.
	Days []string `yaml:"days,omitempty" json:"days,omitempty"`

	// StartUTC is the first UTC hour (0–23, inclusive) in which the rule is
	// active.
	StartUTC int `yaml:"start_utc" json:"start_utc"`

	// EndUTC is the UTC hour (0–23, exclusive) after which the rule is no
	// longer active.  Must be > StartUTC.
	//
	// To express 06:00–22:00 UTC: StartUTC: 6, EndUTC: 22.
	// Overnight windows (e.g. 22:00–06:00) are not supported in a single
	// TimeWindow; use two rules instead.
	EndUTC int `yaml:"end_utc" json:"end_utc"`
}

// ── Validation ────────────────────────────────────────────────────────────────

// Validate checks that the Policy is structurally sound.  It returns a
// combined error listing all problems found, not just the first one.
//
// Validate does NOT enforce business-logic constraints (e.g. "allow rules
// must have a TeamID").  It enforces only schema invariants.
//
// A Policy with zero rules passes validation — deny-by-default is the
// correct behaviour for an empty ruleset.
func (p *Policy) Validate() error {
	if p.Version != "1" {
		return fmt.Errorf("policy: unsupported schema version %q (want \"1\")", p.Version)
	}

	seenIDs := make(map[string]int) // rule ID → first-seen index
	var errs []string

	for i, r := range p.Rules {
		for _, e := range r.validate(i) {
			errs = append(errs, e)
		}
		if r.ID != "" {
			if prev, seen := seenIDs[r.ID]; seen {
				errs = append(errs, fmt.Sprintf("rules[%d]: duplicate rule ID %q (first seen at rules[%d])", i, r.ID, prev))
			} else {
				seenIDs[r.ID] = i
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("policy validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// validate returns a slice of error strings for this rule.  An empty slice
// means the rule is valid.  idx is used only in error messages.
func (r *Rule) validate(idx int) []string {
	prefix := fmt.Sprintf("rules[%d]", idx)
	var errs []string

	if r.ID == "" {
		errs = append(errs, fmt.Sprintf("%s: id must not be empty", prefix))
	}

	if !r.Effect.IsValid() {
		errs = append(errs, fmt.Sprintf("%s (%q): effect must be \"allow\" or \"deny\", got %q",
			prefix, r.ID, r.Effect))
	}

	for j, op := range r.Match.Operations {
		if !op.IsKnown() {
			errs = append(errs, fmt.Sprintf("%s (%q): match.operations[%d]: unknown operation %q",
				prefix, r.ID, j, op))
		}
	}

	if r.Match.Identity.CallerIDPattern != "" {
		if err := validateGlobPattern(r.Match.Identity.CallerIDPattern); err != nil {
			errs = append(errs, fmt.Sprintf(
				"%s (%q): match.identity.caller_id_pattern: %v",
				prefix, r.ID, err))
		}
	}

	for _, role := range r.Match.Identity.Roles {
		switch strings.ToLower(role) {
		case "developer", "service", "agent":
			// valid
		default:
			errs = append(errs, fmt.Sprintf("%s (%q): match.identity.roles: unknown role %q (valid: developer, service, agent)",
				prefix, r.ID, role))
		}
	}

	if tw := r.TimeWindow; tw != nil {
		for _, d := range tw.Days {
			if !isValidWeekday(d) {
				errs = append(errs, fmt.Sprintf("%s (%q): time_window.days: unknown weekday %q",
					prefix, r.ID, d))
			}
		}
		if tw.StartUTC < 0 || tw.StartUTC > 23 {
			errs = append(errs, fmt.Sprintf("%s (%q): time_window.start_utc must be 0–23, got %d",
				prefix, r.ID, tw.StartUTC))
		}
		if tw.EndUTC < 0 || tw.EndUTC > 23 {
			errs = append(errs, fmt.Sprintf("%s (%q): time_window.end_utc must be 0–23, got %d",
				prefix, r.ID, tw.EndUTC))
		}
		if tw.StartUTC >= tw.EndUTC && !(tw.StartUTC == 0 && tw.EndUTC == 0) {
			// Both zero is the sentinel "no time constraint" value; skip check.
			errs = append(errs, fmt.Sprintf("%s (%q): time_window.start_utc (%d) must be < end_utc (%d)",
				prefix, r.ID, tw.StartUTC, tw.EndUTC))
		}
	}

	if rl := r.RateLimit; rl != nil {
		if rl.MaxRequests <= 0 {
			errs = append(errs, fmt.Sprintf("%s (%q): rate_limit.max_requests must be > 0, got %d",
				prefix, r.ID, rl.MaxRequests))
		}
		if rl.Window == "" {
			errs = append(errs, fmt.Sprintf("%s (%q): rate_limit.window must not be empty",
				prefix, r.ID))
		} else if d, err := time.ParseDuration(rl.Window); err != nil {
			errs = append(errs, fmt.Sprintf("%s (%q): rate_limit.window %q is not a valid Go duration: %v",
				prefix, r.ID, rl.Window, err))
		} else if d < 0 {
			errs = append(errs, fmt.Sprintf("%s (%q): rate_limit.window must be positive, got %q",
				prefix, r.ID, rl.Window))
		} else {
			rl.WindowDuration = d // stash parsed duration for engine use
		}
	}

	if len(r.Match.KeyIDs) > 0 && r.Match.KeyPrefix != "" {
		errs = append(errs, fmt.Sprintf("%s (%q): match.key_ids and match.key_prefix are mutually exclusive; specify only one",
			prefix, r.ID))
	}

	return errs
}

// validateGlobPattern checks that pattern is syntactically valid for use with
// path.Match.  It catches two classes of defect:
//
//  1. Structurally malformed patterns that cause path.Match to return
//     ErrBadPattern (e.g. unclosed bracket "abc[").
//
//  2. Reversed character class ranges (e.g. "[z-a]") that Go's path.Match
//     silently treats as never-matching.  In a deny rule, a never-matching
//     pattern means the deny never fires — a privilege-escalation risk.
//
// Returns a non-nil error describing the first problem found.
func validateGlobPattern(pattern string) error {
	// Phase 1: structural check via path.Match (catches unclosed brackets).
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("malformed glob %q: %v", pattern, err)
	}

	// Phase 2: reversed character-range check.
	// Walk through bracket expressions and verify lo ≤ hi for each a-b range.
	i := 0
	for i < len(pattern) {
		if pattern[i] != '[' {
			if pattern[i] == '\\' {
				i++ // skip escaped char
			}
			i++
			continue
		}
		// Entering a bracket expression.
		i++ // skip '['
		if i < len(pattern) && pattern[i] == '^' {
			i++ // skip optional negation '^'
		}
		// Walk the character-range elements until ']'.
		for i < len(pattern) && pattern[i] != ']' {
			var lo byte
			if pattern[i] == '\\' && i+1 < len(pattern) {
				i++ // skip backslash
				lo = pattern[i]
			} else {
				lo = pattern[i]
			}
			i++
			// Check for a-b range syntax.
			if i < len(pattern) && pattern[i] == '-' && i+1 < len(pattern) && pattern[i+1] != ']' {
				i++ // skip '-'
				var hi byte
				if pattern[i] == '\\' && i+1 < len(pattern) {
					i++ // skip backslash
					hi = pattern[i]
				} else {
					hi = pattern[i]
				}
				i++
				if lo > hi {
					return fmt.Errorf(
						"malformed glob %q: reversed character range [%c-%c] never matches — did you mean [%c-%c]?",
						pattern, lo, hi, hi, lo)
				}
			}
		}
		if i < len(pattern) {
			i++ // skip ']'
		}
	}
	return nil
}
