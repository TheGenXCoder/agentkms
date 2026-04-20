package policy

// engine.go — P-03 + P-04 + P-06: Policy evaluator with deny-by-default and
// per-rule rate limiting.
//
// SECURITY INVARIANT (P-04):
//
//	An Engine constructed from a Policy with zero rules MUST deny every
//	(identity, operation, key-id) triple.  This is not a default that can be
//	overridden by configuration; it is a structural guarantee enforced by the
//	evaluation loop in Evaluate / EvaluateAt.
//
// Evaluation model: first-match semantics.
//
//  1. Rules are tested in declaration order.
//  2. The first rule whose Match conditions all pass determines the outcome.
//     - If the rule has a RateLimit and the limit is exceeded → deny (rate
//       limit denial; the matched rule "owns" the decision — no fallthrough).
//     - Effect "deny"  → return Decision{Allow: false, ...}
//     - Effect "allow" → return Decision{Allow: true, ...}
//  3. If no rule matches, return Decision{Allow: false, DenyReason: denyByDefaultReason}.
//
// Thread safety: Engine is safe for concurrent reads and writes.
//   - Policy reads: RWMutex — concurrent Evaluate calls are goroutine-safe.
//   - Rate-limit state: Mutex — serialises counter updates.
//   - Reload: acquires both write locks; in-flight Evaluate calls complete
//     with the old policy before the swap takes effect.
//
// Rate limit state is NOT reset by Reload.  Counters persist across policy
// reloads so that a rapid succession of policy changes cannot be used to
// reset an attacker's rate limit.

import (
	"context"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/agentkms/agentkms/pkg/identity"
)

// EngineI is the interface that API handlers use to evaluate and manage policy.
// It accepts a context and string operation, returning (Decision, error).
type EngineI interface {
	Evaluate(ctx context.Context, id identity.Identity, operation string, keyID string) (Decision, error)
	GetPolicy() Policy
	Reload(p Policy) error
}

// DenyAllEngine denies every operation. Safe default before policy is loaded.
type DenyAllEngine struct{}

func (DenyAllEngine) Evaluate(_ context.Context, _ identity.Identity, _, _ string) (Decision, error) {
	return Decision{Allow: false, DenyReason: "policy: no policy configured — all operations denied"}, nil
}

func (DenyAllEngine) GetPolicy() Policy { return Policy{Version: "1"} }
func (DenyAllEngine) Reload(_ Policy) error {
	return fmt.Errorf("policy: DenyAllEngine does not support Reload")
}

// AllowAllEngine permits every operation. For tests only — never production.
type AllowAllEngine struct{}

func (AllowAllEngine) Evaluate(_ context.Context, _ identity.Identity, _, _ string) (Decision, error) {
	return Decision{Allow: true}, nil
}

func (AllowAllEngine) GetPolicy() Policy { return Policy{Version: "1"} }
func (AllowAllEngine) Reload(_ Policy) error {
	return fmt.Errorf("policy: AllowAllEngine does not support Reload")
}

// AsEngineI wraps *Engine as an EngineI for injection into api.NewServer.
func AsEngineI(e *Engine) EngineI { return &engineIAdapter{e: e} }

type engineIAdapter struct{ e *Engine }

func (a *engineIAdapter) Evaluate(ctx context.Context, id identity.Identity, operation string, keyID string) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	return a.e.Evaluate(id, Operation(operation), keyID), nil
}

func (a *engineIAdapter) GetPolicy() Policy {
	return a.e.GetPolicy()
}

func (a *engineIAdapter) Reload(p Policy) error {
	return a.e.Reload(p)
}

// denyByDefaultReason is the DenyReason returned when no rule matched.
// It is exported as a constant so tests can assert the exact string without
// hardcoding it in multiple places.
const denyByDefaultReason = "policy: no rule allows this operation (deny by default)"

// ── Decision ──────────────────────────────────────────────────────────────────

// Decision is the result returned by Engine.Evaluate for a given triple of
// (identity, operation, key-id).
type Decision struct {
	// Allow is true only when an explicit allow rule matched and no earlier
	// deny rule matched.  It is false for all denied or defaulted decisions.
	Allow bool

	// DenyReason explains why the operation was denied.  Empty when Allow is
	// true.  Must not contain key material, plaintext, or stack traces — it
	// is safe to include verbatim in an AuditEvent.DenyReason field.
	DenyReason string

	// MatchedRuleID is the ID of the rule that produced this decision.
	// Empty when the decision is the deny-by-default fallback (no rule matched).
	// Included in audit events so operators can trace a denial to its source rule.
	MatchedRuleID string

	// Anomalies is the list of detected anomalies associated with this
	// decision.  Anomalies do not necessarily cause an Allow=false decision
	// (unless the policy explicitly says so); they are intended to be
	// logged to the audit system for further review.
	Anomalies []AnomalyRecord

	// AllowedBounds is the maximum scope the matched rule permits for this
	// operation.  Nil when Allow is false (deny decisions have no scope).
	// The credential vending pipeline uses this to narrow the caller's
	// requested scope to what policy actually authorises.  Added in B1.
	AllowedBounds *ScopeBounds
}

// ScopeBounds is the maximum scope a policy rule allows for a given
// (identity, operation) pair.  Populated by the rule's `bounds:` section
// when present; nil otherwise (meaning "no scope restriction beyond the
// Kind's defaults").
type ScopeBounds struct {
	Kind      string         `json:"kind,omitempty"`
	MaxParams map[string]any `json:"max_params,omitempty"`
	MaxTTL    time.Duration  `json:"max_ttl,omitempty"`
}

// ── Rate limiter ──────────────────────────────────────────────────────────────

// rateLimitBucket tracks the timestamps of recent operations for a single
// (ruleID, callerID) pair.  Entries are kept in sorted order (oldest first)
// so that pruning and counting are efficient.
type rateLimitBucket struct {
	timestamps []time.Time
}

// rateLimitState holds all rate-limit counters.  It is protected by its own
// mutex so that counter updates do not contend with policy reads.
type rateLimitState struct {
	mu      sync.Mutex
	buckets map[string]*rateLimitBucket // key: ruleID + "\x00" + callerID
}

func newRateLimitState() *rateLimitState {
	return &rateLimitState{
		buckets: make(map[string]*rateLimitBucket),
	}
}

// checkAndRecord tests whether the (ruleID, callerID) bucket has exceeded
// maxRequests within the last window.  If not exceeded, it records the
// current timestamp and returns (allowed, remaining).
//
// If exceeded, it does NOT record the timestamp (the denied request does not
// consume a slot — this prevents an attacker from filling the window with
// denied requests to displace legitimate ones).
func (rls *rateLimitState) checkAndRecord(ruleID, callerID string, maxRequests int, window time.Duration, now time.Time) (allowed bool, remaining int) {
	rls.mu.Lock()
	defer rls.mu.Unlock()

	key := ruleID + "\x00" + callerID
	bucket, exists := rls.buckets[key]
	if !exists {
		bucket = &rateLimitBucket{}
		rls.buckets[key] = bucket
	}

	// Prune expired entries.
	cutoff := now.Add(-window)
	pruned := bucket.timestamps[:0]
	for _, ts := range bucket.timestamps {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	bucket.timestamps = pruned

	// Check limit.
	count := len(bucket.timestamps)
	if count >= maxRequests {
		return false, 0
	}

	// Record this request.
	bucket.timestamps = append(bucket.timestamps, now)
	return true, maxRequests - count - 1
}

// reset clears all rate-limit buckets.  Used in tests and when the operator
// explicitly wants to reset counters (e.g. after a configuration change that
// invalidates the old limits).
func (rls *rateLimitState) reset() {
	rls.mu.Lock()
	rls.buckets = make(map[string]*rateLimitBucket)
	rls.mu.Unlock()
}

// bucketCount returns the number of active buckets.  Used in tests.
// ── Engine ────────────────────────────────────────────────────────────────────

// Engine evaluates (identity, operation, key-id) triples against a Policy.
//
// Construct with New; reload atomically with Reload.
type Engine struct {
	policyMu   sync.RWMutex
	policy     Policy
	rateLimits *rateLimitState
	anomalies  *anomalyState
}

// New constructs a new Engine backed by the given Policy.
// p is copied into the Engine; subsequent changes to p have no effect.
//
// IMPORTANT: New does NOT validate p.  Callers MUST call p.Validate()
// before passing a Policy to New, or construct via LoadFromFile/LoadFromBytes
// which validate automatically.  Passing an invalid policy is safe (unknown
// Effects → deny; malformed patterns → no match → deny) but may produce
// unexpected evaluation results.
func New(p Policy) *Engine {
	return &Engine{
		policy:     copyPolicy(p),
		rateLimits: newRateLimitState(),
		anomalies:  newAnomalyState(),
	}
}

// GetPolicy returns a copy of the engine's current policy.
func (e *Engine) GetPolicy() Policy {
	e.policyMu.RLock()
	defer e.policyMu.RUnlock()
	return copyPolicy(e.policy)
}

// Reload atomically replaces the engine's policy with p.
// In-flight Evaluate calls complete with the old policy before the swap takes
// effect.  p is validated before being accepted; if validation fails, the
// existing policy is unchanged and an error is returned.
//
// Rate-limit state is NOT reset by Reload.  Use ResetRateLimits() explicitly
// if counter reset is desired.
//
// TOCTOU note: copyPolicy runs BEFORE Validate so that validation is
// performed on exactly the snapshot that will be installed.  If Validate ran
// first on the caller's p, a concurrent mutation of the caller's inner slices
// between Validate and copyPolicy could install a policy that differs from
// the validated one.
func (e *Engine) Reload(p Policy) error {
	cp := copyPolicy(p) // snapshot first; validate the snapshot
	if err := cp.Validate(); err != nil {
		return fmt.Errorf("policy engine: reload rejected: %w", err)
	}
	e.policyMu.Lock()
	e.policy = cp
	e.policyMu.Unlock()
	return nil
}

// ResetRateLimits clears all rate-limit counters.  This is useful in tests
// and when an operator explicitly resets counters after a policy change.
func (e *Engine) ResetRateLimits() {
	e.rateLimits.reset()
}

// Evaluate tests whether id is allowed to perform op on keyID.
//
// It is equivalent to EvaluateAt(id, op, keyID, time.Now().UTC()).
// All callers in production should use Evaluate; use EvaluateAt in tests to
// inject a controlled timestamp for time-window and rate-limit testing.
func (e *Engine) Evaluate(id identity.Identity, op Operation, keyID string) Decision {
	return e.EvaluateAt(id, op, keyID, time.Now().UTC())
}

// EvaluateAt is the time-injectable variant of Evaluate.  now must be UTC.
//
// This is the canonical implementation; Evaluate delegates here.
//
// SECURITY INVARIANT (P-04): if e.policy.Rules is empty (or nil), the loop
// below executes zero iterations and the function falls through to the
// deny-by-default return.  This is the provably correct implementation of
// deny-by-default: there is no code path that returns Allow=true when no
// rule explicitly grants the operation.
func (e *Engine) EvaluateAt(id identity.Identity, op Operation, keyID string, now time.Time) Decision {
	// ── Scope Enforcement (FX-02) ─────────────────────────────────────────────────
	//
	// If the identity has scopes, the operation MUST match at least one scope.
	// Scopes are an additional "outer" filter: they cannot grant what the
	// policy denies, but they can deny what the policy would otherwise allow.
	if len(id.Scopes) > 0 {
		scoped := false
		for _, s := range id.Scopes {
			if matchesScope(s, op, keyID) {
				scoped = true
				break
			}
		}
		if !scoped {
			return Decision{
				Allow:      false,
				DenyReason: fmt.Sprintf("policy: operation %q on %q is not within delegated scopes", op, keyID),
			}
		}
	}

	e.policyMu.RLock()
	rules := e.policy.Rules // slice header copy; entries are read-only
	e.policyMu.RUnlock()

	var decision Decision
	var matched bool

	for _, rule := range rules {
		if !matchesIdentity(rule.Match.Identity, id) {
			continue
		}
		if !matchesOperation(rule.Match.Operations, op) {
			continue
		}
		if !matchesKey(rule.Match, keyID) {
			continue
		}
		if !matchesTimeWindow(rule.TimeWindow, now) {
			continue
		}

		// All match conditions satisfied.  Check rate limit before effect.
		if rule.RateLimit != nil {
			allowed, remaining := e.rateLimits.checkAndRecord(
				rule.ID, id.CallerID,
				rule.RateLimit.MaxRequests,
				rule.RateLimit.WindowDuration,
				now,
			)
			if !allowed {
				decision = Decision{
					Allow: false,
					DenyReason: fmt.Sprintf(
						"policy: rate limit exceeded for rule %q (max %d per %s for caller %q)",
						rule.ID, rule.RateLimit.MaxRequests, rule.RateLimit.Window, id.CallerID,
					),
					MatchedRuleID: rule.ID,
				}
				matched = true
				break
			}
			_ = remaining // available for future Decision field if needed
		}

		// Apply the rule's effect.
		switch rule.Effect {
		case EffectDeny:
			decision = Decision{
				Allow:         false,
				DenyReason:    fmt.Sprintf("policy: denied by rule %q: %s", rule.ID, rule.Description),
				MatchedRuleID: rule.ID,
			}
			matched = true
		case EffectAllow:
			decision = Decision{
				Allow:         true,
				MatchedRuleID: rule.ID,
			}
			if rule.Bounds != nil {
				decision.AllowedBounds = &ScopeBounds{
					Kind:      rule.Bounds.Kind,
					MaxParams: rule.Bounds.MaxParams,
					MaxTTL:    rule.Bounds.MaxTTLDuration,
				}
			}
			matched = true
		default:
			// Unreachable: Validate() rejects unknown effects.
			// Treat as deny to fail safe.
			decision = Decision{
				Allow:         false,
				DenyReason:    fmt.Sprintf("policy: rule %q has unrecognised effect %q (treating as deny)", rule.ID, rule.Effect),
				MatchedRuleID: rule.ID,
			}
			matched = true
		}
		break
	}

	if !matched {
		// No rule matched.  Deny by default.
		decision = Decision{
			Allow:      false,
			DenyReason: denyByDefaultReason,
		}
	}

	// ── Anomaly Detection (P-07) ───────────────────────────────────────────────────

	// Detect anomalies based on the decision and caller history.
	// Anomalies do not change the Allow/Deny decision here — they are purely
	// informational/logging context for the audit system.
	anomalies := e.anomalies.Detect(id, decision, now)
	decision.Anomalies = anomalies

	return decision
}

// ── Match helpers ─────────────────────────────────────────────────────────────

// matchesScope returns true if s (format "op:resource") matches op and keyID.
func matchesScope(s string, op Operation, keyID string) bool {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return false
	}
	scopeOp, scopeRes := parts[0], parts[1]

	// Operation match (allow "*" or exact match).
	if scopeOp != "*" && scopeOp != string(op) {
		return false
	}

	// Resource match (allow "*" or exact match).
	if scopeRes != "*" && scopeRes != keyID {
		return false
	}

	return true
}

// matchesIdentity returns true if all non-empty fields of im match id.
func matchesIdentity(im IdentityMatch, id identity.Identity) bool {
	// TeamID: exact match; empty means any team.
	if im.TeamID != "" && im.TeamID != id.TeamID {
		return false
	}

	// CallerIDPattern: glob match; empty means any caller.
	if im.CallerIDPattern != "" {
		matched, err := path.Match(im.CallerIDPattern, id.CallerID)
		if err != nil {
			// path.Match returns an error only for a malformed pattern.
			// Validate() already rejects malformed patterns, but we handle
			// the error defensively here in case a Policy was passed to
			// New() without prior validation (New() does not call Validate()).
			return false
		}
		if !matched {
			return false
		}
	}

	// Roles: caller's role must be one of the listed roles; empty means any.
	if len(im.Roles) > 0 {
		found := false
		callerRole := strings.ToLower(string(id.Role))
		for _, r := range im.Roles {
			if strings.ToLower(r) == callerRole {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// matchesOperation returns true if op is in the ops list, or if ops is empty
// (meaning "all operations").
func matchesOperation(ops []Operation, op Operation) bool {
	if len(ops) == 0 {
		return true // empty = all operations
	}
	for _, allowed := range ops {
		if allowed == op {
			return true
		}
	}
	return false
}

// matchesKey returns true if keyID satisfies the key constraint in m.
//
// Resolution order:
//  1. If m.KeyIDs is non-empty, keyID must appear exactly in the list.
//  2. Else if m.KeyPrefix is non-empty, keyID must have the prefix.
//  3. Else (both empty): matches any key, including an empty keyID.
func matchesKey(m Match, keyID string) bool {
	if len(m.KeyIDs) > 0 {
		for _, id := range m.KeyIDs {
			if id == keyID {
				return true
			}
		}
		return false
	}
	if m.KeyPrefix != "" {
		return strings.HasPrefix(keyID, m.KeyPrefix)
	}
	return true // no key constraint
}

// matchesTimeWindow returns true if now falls within the rule's time window.
// A nil TimeWindow means no temporal constraint (always matches).
//
// The time window is evaluated in UTC.  The caller must supply a UTC time.
//
// Hour matching is [StartUTC, EndUTC) — StartUTC is inclusive, EndUTC
// exclusive.  A TimeWindow with both StartUTC and EndUTC equal to zero is
// treated as "no time constraint" (same as nil).
func matchesTimeWindow(tw *TimeWindow, now time.Time) bool {
	if tw == nil {
		return true
	}
	// Zero-value sentinel: both fields zero → no constraint.
	if tw.StartUTC == 0 && tw.EndUTC == 0 && len(tw.Days) == 0 {
		return true
	}

	// Day-of-week check.
	if len(tw.Days) > 0 {
		// Go's Weekday().String() returns "Monday", "Tuesday", etc.
		// We want the first 3 lowercase letters.
		dayName := strings.ToLower(now.UTC().Weekday().String()[:3])
		found := false
		for _, d := range tw.Days {
			if strings.ToLower(d) == dayName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Hour check: [StartUTC, EndUTC).
	// Skip if both are zero (handled as sentinel above).
	if tw.StartUTC != 0 || tw.EndUTC != 0 {
		hour := now.UTC().Hour()
		if hour < tw.StartUTC || hour >= tw.EndUTC {
			return false
		}
	}

	return true
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// copyPolicy returns a deep copy of p.  All slices — including the inner
// slices within each Rule (Operations, KeyIDs, Roles, TimeWindow.Days) — are
// re-allocated so that neither the caller nor any concurrent writer can
// mutate the engine's in-use policy by holding a reference to the original
// Policy object.
//
// SECURITY: shallow-copying inner slices would allow a caller that retains
// the source *Policy to silently mutate the engine's view of a rule after
// calling New() or Reload().  Under concurrent Evaluate calls this is a data
// race; it also opens a window for a privilege-escalation bug where a rule's
// Operations, KeyIDs, or Roles set is expanded after policy validation has
// already accepted the policy.
func copyPolicy(p Policy) Policy {
	cp := Policy{
		Version: p.Version,
	}
	if len(p.Rules) == 0 {
		return cp
	}
	cp.Rules = make([]Rule, len(p.Rules))
	for i, r := range p.Rules {
		cr := Rule{
			ID:          r.ID,
			Description: r.Description,
			Effect:      r.Effect,
			Match: Match{
				Identity: IdentityMatch{
					TeamID:          r.Match.Identity.TeamID,
					CallerIDPattern: r.Match.Identity.CallerIDPattern,
				},
				KeyPrefix: r.Match.KeyPrefix,
			},
		}
		// Deep-copy all inner slices.
		if len(r.Match.Identity.Roles) > 0 {
			cr.Match.Identity.Roles = make([]string, len(r.Match.Identity.Roles))
			copy(cr.Match.Identity.Roles, r.Match.Identity.Roles)
		}
		if len(r.Match.Operations) > 0 {
			cr.Match.Operations = make([]Operation, len(r.Match.Operations))
			copy(cr.Match.Operations, r.Match.Operations)
		}
		if len(r.Match.KeyIDs) > 0 {
			cr.Match.KeyIDs = make([]string, len(r.Match.KeyIDs))
			copy(cr.Match.KeyIDs, r.Match.KeyIDs)
		}
		if r.RateLimit != nil {
			rl := *r.RateLimit // value copy; WindowDuration is a time.Duration (int64) — safe.
			cr.RateLimit = &rl
		}
		if r.Bounds != nil {
			b := RuleBounds{
				Kind:           r.Bounds.Kind,
				MaxTTL:         r.Bounds.MaxTTL,
				MaxTTLDuration: r.Bounds.MaxTTLDuration,
			}
			if len(r.Bounds.MaxParams) > 0 {
				b.MaxParams = make(map[string]any, len(r.Bounds.MaxParams))
				for k, v := range r.Bounds.MaxParams {
					b.MaxParams[k] = v
				}
			}
			cr.Bounds = &b
		}
		if r.TimeWindow != nil {
			tw := TimeWindow{
				StartUTC: r.TimeWindow.StartUTC,
				EndUTC:   r.TimeWindow.EndUTC,
			}
			if len(r.TimeWindow.Days) > 0 {
				tw.Days = make([]string, len(r.TimeWindow.Days))
				copy(tw.Days, r.TimeWindow.Days)
			}
			cr.TimeWindow = &tw
		}
		cp.Rules[i] = cr
	}
	return cp
}
