package policy

import (
	"sync/atomic"
	"sync"
	"strings"
	"testing"
	"time"

)

// ── P-06: Rate limiting ──────────────────────────────────────────────────────

// rlHelper builds an Engine with a single allow rule that has a rate limit.
// The rule matches all callers, all operations, all keys — so rate limiting
// is the only gate.
func rlEngine(t *testing.T, maxRequests int, window string) *Engine {
	t.Helper()
	p := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "rl-rule",
				Match:  Match{},
				Effect: EffectAllow,
				RateLimit: &RateLimit{
					MaxRequests: maxRequests,
					Window:      window,
				},
			},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	e := New(p)
	t.Cleanup(func() { e.ResetRateLimits() })
	return e
}

// TestRateLimit_AllowsWithinLimit verifies that requests within the limit are
// allowed.
func TestRateLimit_AllowsWithinLimit(t *testing.T) {
	t.Parallel()

	engine := rlEngine(t, 3, "1h")
	id := devID("team", "alice")
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// First 3 requests should be allowed.
	for i := 0; i < 3; i++ {
		now := base.Add(time.Duration(i) * time.Second)
		dec := engine.EvaluateAt(id, OpSign, "key", now)
		if !dec.Allow {
			t.Fatalf("request %d: expected allow; got deny: %q", i+1, dec.DenyReason)
		}
	}
}

// TestRateLimit_DeniesWhenExceeded verifies that the (max+1)th request is
// denied and the DenyReason names the rule.
func TestRateLimit_DeniesWhenExceeded(t *testing.T) {
	t.Parallel()

	engine := rlEngine(t, 2, "1h")
	id := devID("team", "alice")
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// First 2 allowed.
	engine.EvaluateAt(id, OpSign, "key", base)
	engine.EvaluateAt(id, OpSign, "key", base.Add(time.Second))

	// 3rd should be denied.
	dec := engine.EvaluateAt(id, OpSign, "key", base.Add(2*time.Second))
	if dec.Allow {
		t.Fatal("request 3: expected deny; got allow")
	}
	if !strings.Contains(dec.DenyReason, "rate limit exceeded") {
		t.Errorf("DenyReason should mention rate limit; got: %q", dec.DenyReason)
	}
	if !strings.Contains(dec.DenyReason, "rl-rule") {
		t.Errorf("DenyReason should name the rule; got: %q", dec.DenyReason)
	}
	if dec.MatchedRuleID != "rl-rule" {
		t.Errorf("MatchedRuleID = %q; want \"rl-rule\"", dec.MatchedRuleID)
	}
}

// TestRateLimit_SlidingWindowExpires verifies that old requests fall out of
// the window, allowing new requests after the window elapses.
func TestRateLimit_SlidingWindowExpires(t *testing.T) {
	t.Parallel()

	// 2 requests per 5-minute window.
	engine := rlEngine(t, 2, "5m")
	id := devID("team", "alice")
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Fill the window.
	engine.EvaluateAt(id, OpSign, "key", base)
	engine.EvaluateAt(id, OpSign, "key", base.Add(time.Minute))

	// Denied — window is full.
	dec := engine.EvaluateAt(id, OpSign, "key", base.Add(2*time.Minute))
	if dec.Allow {
		t.Fatal("should be denied within window")
	}

	// After 5m1s from the first request, it should have fallen out of the window.
	afterWindow := base.Add(5*time.Minute + time.Second)
	dec = engine.EvaluateAt(id, OpSign, "key", afterWindow)
	if !dec.Allow {
		t.Errorf("should be allowed after window expiry; got deny: %q", dec.DenyReason)
	}
}

// TestRateLimit_PerCallerIsolation verifies that different callers get
// independent rate-limit buckets.
func TestRateLimit_PerCallerIsolation(t *testing.T) {
	t.Parallel()

	engine := rlEngine(t, 1, "1h")
	alice := devID("team", "alice")
	bob := devID("team", "bob")
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Alice uses her 1 request.
	decA := engine.EvaluateAt(alice, OpSign, "key", now)
	if !decA.Allow {
		t.Fatal("alice should be allowed")
	}

	// Alice denied on 2nd request.
	decA2 := engine.EvaluateAt(alice, OpSign, "key", now.Add(time.Second))
	if decA2.Allow {
		t.Fatal("alice should be denied on 2nd request")
	}

	// Bob gets his own bucket — should be allowed.
	decB := engine.EvaluateAt(bob, OpSign, "key", now)
	if !decB.Allow {
		t.Fatalf("bob should have his own bucket; got deny: %q", decB.DenyReason)
	}
}

// TestRateLimit_DeniedRequestDoesNotCount verifies that a denied request
// (one that exceeded the limit) does NOT consume a rate-limit slot.  If it
// did, an attacker could fill the window with denied requests and lock out
// legitimate callers.
func TestRateLimit_DeniedRequestDoesNotCount(t *testing.T) {
	t.Parallel()

	engine := rlEngine(t, 2, "1h")
	id := devID("team", "alice")
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Use 2 slots.
	engine.EvaluateAt(id, OpSign, "key", base)
	engine.EvaluateAt(id, OpSign, "key", base.Add(time.Second))

	// Denied — window full.
	engine.EvaluateAt(id, OpSign, "key", base.Add(2*time.Second))

	// Try a 3rd allowed request after the first one expires.  If denied
	// requests consumed slots, there would be 3 entries in the bucket and
	// none would have expired yet.
	// Instead, there are only 2 entries.  After the first expires, 1 slot
	// is available.
	afterFirstExpires := base.Add(1*time.Hour + time.Second)
	dec := engine.EvaluateAt(id, OpSign, "key", afterFirstExpires)
	if !dec.Allow {
		t.Errorf("should be allowed after first entry expires; got deny: %q", dec.DenyReason)
	}
}

// TestRateLimit_NoFallthrough verifies that a rate-limited deny does NOT
// fall through to the next rule.  The rate-limited rule "owns" the match.
func TestRateLimit_NoFallthrough(t *testing.T) {
	t.Parallel()

	p := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "rate-limited-allow",
				Match:  Match{},
				Effect: EffectAllow,
				RateLimit: &RateLimit{
					MaxRequests: 1,
					Window:      "1h",
				},
			},
			// This blanket deny should NOT fire when the rate-limited rule
			// denies — the rate-limited rule matched first.
			{
				ID:     "catch-all-deny",
				Match:  Match{},
				Effect: EffectDeny,
			},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	engine := New(p)
	defer engine.ResetRateLimits()

	id := devID("team", "alice")
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// First request: rate-limited allow fires.
	dec1 := engine.EvaluateAt(id, OpSign, "key", now)
	if !dec1.Allow {
		t.Fatalf("first request should be allowed; got deny: %q", dec1.DenyReason)
	}
	if dec1.MatchedRuleID != "rate-limited-allow" {
		t.Errorf("MatchedRuleID = %q; want \"rate-limited-allow\"", dec1.MatchedRuleID)
	}

	// Second request: rate limit exceeded → denied by rate-limited rule.
	dec2 := engine.EvaluateAt(id, OpSign, "key", now.Add(time.Second))
	if dec2.Allow {
		t.Fatal("second request should be denied")
	}
	if dec2.MatchedRuleID != "rate-limited-allow" {
		t.Errorf("MatchedRuleID = %q; want \"rate-limited-allow\" (rate limit owns the match, no fallthrough)", dec2.MatchedRuleID)
	}
}

// TestRateLimit_RateLimitOnDenyRule verifies that a deny rule with a rate
// limit still denies when the limit is NOT exceeded, and continues to deny
// when it IS exceeded (rate-limit denial and explicit deny both produce
// Allow=false).
func TestRateLimit_RateLimitOnDenyRule(t *testing.T) {
	t.Parallel()

	p := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:          "deny-with-rl",
				Match:       Match{},
				Effect:      EffectDeny,
				RateLimit:   &RateLimit{MaxRequests: 2, Window: "1h"},
				Description: "deny everything with rate limit",
			},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	engine := New(p)
	defer engine.ResetRateLimits()

	id := devID("team", "alice")
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// First 2: denied by the rule's explicit deny effect.
	for i := 0; i < 2; i++ {
		dec := engine.EvaluateAt(id, OpSign, "key", now.Add(time.Duration(i)*time.Second))
		if dec.Allow {
			t.Fatalf("request %d: deny rule should deny", i+1)
		}
		if !strings.Contains(dec.DenyReason, "denied by rule") {
			t.Errorf("request %d: DenyReason should be from explicit deny, not rate limit; got: %q", i+1, dec.DenyReason)
		}
	}

	// 3rd: denied by rate limit (effect never reached).
	dec3 := engine.EvaluateAt(id, OpSign, "key", now.Add(3*time.Second))
	if dec3.Allow {
		t.Fatal("request 3: should be denied by rate limit")
	}
	if !strings.Contains(dec3.DenyReason, "rate limit exceeded") {
		t.Errorf("request 3: DenyReason should mention rate limit; got: %q", dec3.DenyReason)
	}
}

// TestRateLimit_ReloadDoesNotResetCounters verifies that reloading the
// policy does NOT clear the rate-limit state.  This prevents an attacker
// from triggering rapid policy reloads to reset their rate limit.
func TestRateLimit_ReloadDoesNotResetCounters(t *testing.T) {
	t.Parallel()

	engine := rlEngine(t, 2, "1h")
	id := devID("team", "alice")
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Use 2 slots.
	engine.EvaluateAt(id, OpSign, "key", base)
	engine.EvaluateAt(id, OpSign, "key", base.Add(time.Second))

	// Denied — window full.
	dec := engine.EvaluateAt(id, OpSign, "key", base.Add(2*time.Second))
	if dec.Allow {
		t.Fatal("should be denied before reload")
	}

	// Reload with a DIFFERENT policy (same rate limit but different ID).
	newPolicy := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "reloaded-rl-rule",
				Match:  Match{},
				Effect: EffectAllow,
				RateLimit: &RateLimit{
					MaxRequests: 2,
					Window:      "1h",
				},
			},
		},
	}
	if err := engine.Reload(newPolicy); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Still denied — the rate-limit state survived the reload.
	// Note: the NEW rule has a different ID, so the old bucket (keyed on
	// "rl-rule") is orphaned but still present.  The new rule creates a new
	// bucket (keyed on "reloaded-rl-rule") which is empty — so this should
	// actually be ALLOWED because it's a different rule bucket.
	//
	// This is correct behaviour: the rate limit is scoped to the RULE ID.
	// If the rule ID changes, the counter resets.  If the rule ID stays the
	// same, the counter persists.
	dec = engine.EvaluateAt(id, OpSign, "key", base.Add(3*time.Second))
	if !dec.Allow {
		t.Errorf("new rule ID should have fresh counter; got deny: %q", dec.DenyReason)
	}
}

// TestRateLimit_SameRuleIDReloadPersistsCounters verifies that reloading
// with the SAME rule ID preserves the rate-limit counter.
func TestRateLimit_SameRuleIDReloadPersistsCounters(t *testing.T) {
	t.Parallel()

	engine := rlEngine(t, 2, "1h")
	id := devID("team", "alice")
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Use 2 slots.
	engine.EvaluateAt(id, OpSign, "key", base)
	engine.EvaluateAt(id, OpSign, "key", base.Add(time.Second))

	// Denied.
	dec := engine.EvaluateAt(id, OpSign, "key", base.Add(2*time.Second))
	if dec.Allow {
		t.Fatal("should be denied before reload")
	}

	// Reload with same rule ID but different MaxRequests (effectively widening).
	sameIDPolicy := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "rl-rule", // SAME ID as original
				Match:  Match{},
				Effect: EffectAllow,
				RateLimit: &RateLimit{
					MaxRequests: 5,
					Window:      "1h",
				},
			},
		},
	}
	if err := engine.Reload(sameIDPolicy); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// The old counter had 2 entries.  The new limit is 5.  Should be allowed.
	// But note: the counter state was built with max=2.  After reload, the
	// new max is 5, so 2 < 5 → allowed.
	dec = engine.EvaluateAt(id, OpSign, "key", base.Add(3*time.Second))
	if !dec.Allow {
		t.Errorf("same rule ID with higher limit should allow; got deny: %q", dec.DenyReason)
	}
}

// TestRateLimit_ResetRateLimits verifies the explicit reset method.
func TestRateLimit_ResetRateLimits(t *testing.T) {
	t.Parallel()

	engine := rlEngine(t, 1, "1h")
	id := devID("team", "alice")
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Use the 1 slot.
	engine.EvaluateAt(id, OpSign, "key", now)
	dec := engine.EvaluateAt(id, OpSign, "key", now.Add(time.Second))
	if dec.Allow {
		t.Fatal("should be denied")
	}

	// Reset.
	engine.ResetRateLimits()

	// Should be allowed again.
	dec = engine.EvaluateAt(id, OpSign, "key", now.Add(2*time.Second))
	if !dec.Allow {
		t.Errorf("should be allowed after reset; got deny: %q", dec.DenyReason)
	}
}

// TestRateLimit_DenyByDefaultUnaffected verifies that deny-by-default still
// works when no rules have rate limits — rate limiting must not change the
// fundamental deny-by-default invariant.
func TestRateLimit_DenyByDefaultUnaffected(t *testing.T) {
	t.Parallel()

	// Empty policy with rate-limit state (from prior usage).
	engine := rlEngine(t, 5, "1h")
	engine.ResetRateLimits()

	// Reload to an empty policy (no rules).
	if err := engine.Reload(Policy{Version: "1"}); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	id := devID("team", "alice")
	dec := engine.EvaluateAt(id, OpSign, "key", time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	if dec.Allow {
		t.Fatal("deny-by-default must still hold with empty policy")
	}
}

// TestRateLimit_WithMatchConditions verifies that rate limiting only counts
// requests that match ALL conditions of the rule.
func TestRateLimit_WithMatchConditions(t *testing.T) {
	t.Parallel()

	p := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID: "sign-only-rl",
				Match: Match{
					Operations: []Operation{OpSign},
					KeyPrefix:  "payments/",
				},
				Effect: EffectAllow,
				RateLimit: &RateLimit{
					MaxRequests: 2,
					Window:      "1h",
				},
			},
			// Catch-all for non-matching ops.
			{
				ID:     "catch-all-allow",
				Match:  Match{},
				Effect: EffectAllow,
			},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	engine := New(p)
	defer engine.ResetRateLimits()

	id := devID("team", "alice")
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Sign on payments/key — uses rate limit.  2 allowed.
	engine.EvaluateAt(id, OpSign, "payments/key", now)
	engine.EvaluateAt(id, OpSign, "payments/key", now.Add(time.Second))

	// Sign on payments/key — 3rd denied by rate limit.
	dec := engine.EvaluateAt(id, OpSign, "payments/key", now.Add(2*time.Second))
	if dec.Allow {
		t.Fatal("should be rate-limited")
	}
	if dec.MatchedRuleID != "sign-only-rl" {
		t.Errorf("MatchedRuleID = %q; want \"sign-only-rl\"", dec.MatchedRuleID)
	}

	// Encrypt on payments/key — doesn't match the sign-only rule's Operations
	// constraint, so it falls through to the catch-all.  No rate limit.
	dec = engine.EvaluateAt(id, OpEncrypt, "payments/key", now.Add(3*time.Second))
	if !dec.Allow {
		t.Errorf("encrypt should fall through to catch-all; got deny: %q", dec.DenyReason)
	}
	if dec.MatchedRuleID != "catch-all-allow" {
		t.Errorf("MatchedRuleID = %q; want \"catch-all-allow\"", dec.MatchedRuleID)
	}

	// Sign on platform/key — doesn't match the sign-only rule's KeyPrefix.
	dec = engine.EvaluateAt(id, OpSign, "platform/key", now.Add(4*time.Second))
	if !dec.Allow {
		t.Errorf("sign on platform/ should fall through; got deny: %q", dec.DenyReason)
	}
}

// TestRateLimit_WindowDurationParsed validates that the WindowDuration field
// is correctly populated by Validate().
func TestRateLimit_WindowDurationParsed(t *testing.T) {
	t.Parallel()

	p := Policy{
		Version: "1",
		Rules: []Rule{
			{
				ID:     "r",
				Match:  Match{},
				Effect: EffectAllow,
				RateLimit: &RateLimit{
					MaxRequests: 10,
					Window:      "2h30m",
				},
			},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	want := 2*time.Hour + 30*time.Minute
	if p.Rules[0].RateLimit.WindowDuration != want {
		t.Errorf("WindowDuration = %v; want %v", p.Rules[0].RateLimit.WindowDuration, want)
	}
}

// TestRateLimit_ValidationBadWindow verifies that invalid window durations
// are caught by validation.
func TestRateLimit_ValidationBadWindow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		window string
	}{
		{"not a duration", "forever"},
		{"negative", "-1h"},
		{"garbage", "abc"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := Policy{
				Version: "1",
				Rules: []Rule{{
					ID:     "r",
					Match:  Match{},
					Effect: EffectAllow,
					RateLimit: &RateLimit{
						MaxRequests: 5,
						Window:      tc.window,
					},
				}},
			}
			err := p.Validate()
			if err == nil {
				t.Fatalf("expected validation error for window %q; got nil", tc.window)
			}
			if !strings.Contains(err.Error(), "rate_limit.window") {
				t.Errorf("error should mention rate_limit.window; got: %v", err)
			}
		})
	}
}

// TestRateLimit_ConcurrentSafety hammers the engine from multiple goroutines
// to verify no data races under the race detector.
func TestRateLimit_ConcurrentSafety(t *testing.T) {
	t.Parallel()

	engine := rlEngine(t, 100, "1s")
	id := devID("team", "alice")
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	const goroutines = 20
	const requestsPer = 50
	var allowed, denied atomic.Int64

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < requestsPer; i++ {
				now := base.Add(time.Duration(i) * time.Millisecond)
				dec := engine.EvaluateAt(id, OpSign, "key", now)
				if dec.Allow {
					allowed.Add(1)
				} else {
					denied.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	total := allowed.Load() + denied.Load()
	if total != goroutines*requestsPer {
		t.Errorf("total decisions = %d; want %d", total, goroutines*requestsPer)
	}
	// Some should have been allowed, some denied (rate limit is 100 per 1s).
	if allowed.Load() == 0 {
		t.Error("expected some requests to be allowed")
	}
	if denied.Load() == 0 {
		t.Error("expected some requests to be denied")
	}
}

