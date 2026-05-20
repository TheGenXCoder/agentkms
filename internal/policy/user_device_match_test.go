package policy

// user_device_match_test.go — Phase 1 zero-trust identity rollout: verify
// that policy rules can match on the new UserID and DeviceID dimensions and
// that a user_id-pinned rule matches the same human across multiple device
// certs.

import (
	"context"
	"testing"

	"github.com/agentkms/agentkms/pkg/identity"
)

// userDeviceIdentity is a focused test helper that builds an Identity with
// the new UserID/DeviceID fields populated.  We can't reuse devID() here
// because it pre-dates the new fields and intentionally leaves them empty
// to model legacy CN-only callers.
func userDeviceIdentity(team, user, device string) identity.Identity {
	return identity.Identity{
		CallerID: user, // new-style: CallerID resolves to user
		UserID:   user,
		DeviceID: device,
		TeamID:   team,
		Role:     identity.RoleDeveloper,
	}
}

// TestIdentityMatch_UserID_MatchesAcrossDevices is the focused proof for
// Phase 1 of the user/device split:
//
//	A policy rule pinned to a logical user (user_id: "bert") MUST match
//	every session that user starts, regardless of which device cert
//	authenticated.  Without this, the same human enrolling a second laptop
//	silently loses access to policy-gated operations until each rule is
//	duplicated for the new device.
//
// The rule under test pins user_id only.  We then evaluate two identities
// that share the user but differ in their device cert, and assert both
// match.  For symmetry we also assert that a *different* user does NOT match.
func TestIdentityMatch_UserID_MatchesAcrossDevices(t *testing.T) {
	t.Parallel()

	rulePolicy := Policy{
		Version: "1",
		Rules: []Rule{{
			ID: "allow-bert-sign",
			Match: Match{
				Identity:   IdentityMatch{UserID: "bert"},
				Operations: []Operation{OpSign},
			},
			Effect: EffectAllow,
		}},
	}
	engine := mustEngine(t, rulePolicy)

	// Two identities for the same human, different device certs.
	bertThinkpad := userDeviceIdentity("platform-team", "bert", "bert-tp-dev")
	bertMacbook := userDeviceIdentity("platform-team", "bert", "bert-thinkpad")
	// A different user; same team and role but their UserID is different.
	alice := userDeviceIdentity("platform-team", "alice", "alice-laptop")

	ctx := context.Background()

	t.Run("first device matches", func(t *testing.T) {
		dec, err := AsEngineI(engine).Evaluate(ctx, bertThinkpad, string(OpSign), "key-1")
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !dec.Allow {
			t.Fatalf("expected allow for bert on bert-tp-dev; got %+v", dec)
		}
		if dec.MatchedRuleID != "allow-bert-sign" {
			t.Errorf("MatchedRuleID = %q, want %q", dec.MatchedRuleID, "allow-bert-sign")
		}
	})

	t.Run("second device also matches (same user)", func(t *testing.T) {
		dec, err := AsEngineI(engine).Evaluate(ctx, bertMacbook, string(OpSign), "key-1")
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !dec.Allow {
			t.Fatalf("expected allow for bert on bert-thinkpad; got %+v", dec)
		}
		if dec.MatchedRuleID != "allow-bert-sign" {
			t.Errorf("MatchedRuleID = %q, want %q", dec.MatchedRuleID, "allow-bert-sign")
		}
	})

	t.Run("different user does not match", func(t *testing.T) {
		dec, err := AsEngineI(engine).Evaluate(ctx, alice, string(OpSign), "key-1")
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if dec.Allow {
			t.Fatalf("expected deny for alice; got %+v", dec)
		}
	})
}

// TestIdentityMatch_DeviceID_MatchesExactDevice locks in the symmetric
// behaviour: a rule pinned to a specific DeviceID matches only that device,
// regardless of which user is on it.  This is the "admin workstation" or
// "hardware-token reader" use case.
func TestIdentityMatch_DeviceID_MatchesExactDevice(t *testing.T) {
	t.Parallel()

	rulePolicy := Policy{
		Version: "1",
		Rules: []Rule{{
			ID: "allow-on-hwtoken-reader",
			Match: Match{
				Identity:   IdentityMatch{DeviceID: "hwtoken-reader-01"},
				Operations: []Operation{OpSign},
			},
			Effect: EffectAllow,
		}},
	}
	engine := mustEngine(t, rulePolicy)

	onReader := userDeviceIdentity("platform-team", "bert", "hwtoken-reader-01")
	elsewhere := userDeviceIdentity("platform-team", "bert", "bert-tp-dev")

	ctx := context.Background()

	t.Run("matching device allows", func(t *testing.T) {
		dec, err := AsEngineI(engine).Evaluate(ctx, onReader, string(OpSign), "key-1")
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !dec.Allow {
			t.Fatalf("expected allow on hwtoken-reader-01; got %+v", dec)
		}
	})

	t.Run("non-matching device denies", func(t *testing.T) {
		dec, err := AsEngineI(engine).Evaluate(ctx, elsewhere, string(OpSign), "key-1")
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if dec.Allow {
			t.Fatalf("expected deny on bert-tp-dev; got %+v", dec)
		}
	})
}
