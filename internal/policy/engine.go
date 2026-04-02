package policy

import (
	"fmt"
	"strings"
)

// Request is the input to a policy evaluation.  All four fields are required
// for an accurate decision; an empty field matches any rule that uses "*".
type Request struct {
	// CallerID is the authenticated caller identity (from mTLS cert CN or token sub).
	CallerID string

	// TeamID is the team that owns the caller (from mTLS cert O or token tid).
	TeamID string

	// Operation is the action being requested.  Use the Operation* constants.
	Operation string

	// KeyID is the key involved in the operation.  May be empty for
	// operations that do not involve a key (e.g., list_keys with no filter).
	KeyID string
}

// Decision is the result of a policy evaluation.
type Decision struct {
	// Allowed is true if the operation is permitted.
	Allowed bool

	// MatchedRuleID is the ID of the rule that determined this decision.
	// Empty if no rule matched (deny-by-default path).
	MatchedRuleID string

	// DenyReason is a human-readable explanation when Allowed is false.
	// Must not contain key material or sensitive internal details.
	DenyReason string
}

// Engine evaluates policy rules against operation requests.
//
// SECURITY INVARIANT (P-04): The engine is deny-by-default.  An empty
// policy (no rules) denies ALL operations.  An operation is allowed only
// if at least one rule explicitly matches AND has effect "allow", AND no
// prior rule (in declaration order) matched with effect "deny".
//
// Evaluation model (first-match-wins / firewall semantics):
//  1. Rules are evaluated in declaration order.
//  2. For each rule, all four dimensions are checked: identity, team,
//     operation, key prefix.  All must match.
//  3. The first matching rule's effect (allow or deny) is applied immediately.
//  4. If no rule matches: DENY (deny-by-default).
//
// Concurrency: Engine is immutable after construction and safe for concurrent
// use by multiple goroutines.
type Engine struct {
	rules []Rule // immutable after NewEngine
}

// NewEngine creates a policy engine from the rules in pf.
// The rules slice is copied so the engine is unaffected by later changes.
func NewEngine(pf *PolicyFile) *Engine {
	rules := make([]Rule, len(pf.Rules))
	copy(rules, pf.Rules)
	return &Engine{rules: rules}
}

// Evaluate checks whether req is allowed by policy and returns a Decision.
//
// The caller should log the Decision.DenyReason in the audit event when
// Allowed is false.
func (e *Engine) Evaluate(req Request) Decision {
	for _, rule := range e.rules {
		if !matchesAny(rule.Identities, req.CallerID) {
			continue
		}
		if !matchesAny(rule.Teams, req.TeamID) {
			continue
		}
		if !matchesAny(rule.Operations, req.Operation) {
			continue
		}
		if !matchesKeyPrefix(rule.KeyPrefixes, req.KeyID) {
			continue
		}

		// First matching rule — apply its effect.
		if rule.Effect == EffectAllow {
			return Decision{
				Allowed:       true,
				MatchedRuleID: rule.ID,
			}
		}
		// Effect is "deny".
		return Decision{
			Allowed:       false,
			MatchedRuleID: rule.ID,
			DenyReason:    fmt.Sprintf("explicitly denied by policy rule %q", rule.ID),
		}
	}

	// No rule matched — deny by default.
	return Decision{
		Allowed: false,
		DenyReason: fmt.Sprintf("no policy rule permits operation %q for identity %q on key %q",
			req.Operation, req.CallerID, req.KeyID),
	}
}

// ── Matching helpers ──────────────────────────────────────────────────────────

// matchesAny reports whether value matches any pattern in patterns.
// The special pattern "*" matches any non-empty value.
// An empty value never matches any pattern (not even "*"), because an empty
// identity or team is a sign of an improperly extracted or zero-value request.
func matchesAny(patterns []string, value string) bool {
	if value == "" {
		return false
	}
	for _, p := range patterns {
		if p == "*" || p == value {
			return true
		}
	}
	return false
}

// matchesKeyPrefix reports whether keyID matches any of the provided prefixes.
//
// Matching semantics:
//   - prefix "*"  matches any key ID (including empty) — explicit wildcard.
//   - prefix ""   also matches any key ID — same as "*".  DefaultDevPolicy
//                 uses "" to mean "all keys"; this is intentional for local
//                 dev convenience and is documented here so the behaviour is
//                 explicit rather than accidental.  Production policies should
//                 use explicit prefixes ("payments/", "ml/") or "*".
//   - any other prefix: keyID must start with it (strings.HasPrefix).
//
// SECURITY NOTE: In a fully hardened production deployment the "" wildcard
// should be disallowed in policy files.  Tracking item P-09 covers adding
// strict prefix validation in the loader.  For the dev backend "" == "*" is
// acceptable because the dev server only ever holds non-production keys.
func matchesKeyPrefix(prefixes []string, keyID string) bool {
	for _, prefix := range prefixes {
		// "*" and "" are both explicit wildcards — match any key ID.
		if prefix == "*" || prefix == "" {
			return true
		}
		if strings.HasPrefix(keyID, prefix) {
			return true
		}
	}
	return false
}
