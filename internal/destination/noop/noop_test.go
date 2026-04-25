package noop

// noop_test.go — tests for the no-op DestinationDeliverer implementation.
//
// Covers:
//  5. Deliver round-trip: Deliver records the call, returns no error.
//  6. Deliver idempotency: same delivery_id and generation produces same outcome.
//  7. Deliver with GENERATION_REGRESSION: lower generation returns permanent error.
//  8. Revoke is idempotent: second call returns nil.
//  9. (Registry tests are in internal/plugin/capabilities_test.go)
// 10. Health always returns nil.

import (
	"context"
	"testing"

	"github.com/agentkms/agentkms/internal/destination"
)

func TestNoopDeliverer_Kind(t *testing.T) {
	n := NewNoopDeliverer()
	if got := n.Kind(); got != "noop" {
		t.Errorf("Kind() = %q, want %q", got, "noop")
	}
}

func TestNoopDeliverer_Capabilities(t *testing.T) {
	n := NewNoopDeliverer()
	caps := n.Capabilities()

	has := func(s string) bool {
		for _, c := range caps {
			if c == s {
				return true
			}
		}
		return false
	}

	if !has("health") {
		t.Error("Capabilities() missing 'health'")
	}
	if !has("revoke") {
		t.Error("Capabilities() missing 'revoke'")
	}
}

func TestNoopDeliverer_Validate_AlwaysSucceeds(t *testing.T) {
	n := NewNoopDeliverer()
	ctx := context.Background()

	if err := n.Validate(ctx, nil); err != nil {
		t.Errorf("Validate(nil params) returned error: %v", err)
	}
	if err := n.Validate(ctx, map[string]any{"token": "ghp_test"}); err != nil {
		t.Errorf("Validate(with params) returned error: %v", err)
	}
}

// TestNoopDeliverer_Deliver_RecordsCall verifies that a Deliver call is
// recorded in the ring buffer and DeliveryCount increments.
func TestNoopDeliverer_Deliver_RecordsCall(t *testing.T) {
	n := NewNoopDeliverer()
	ctx := context.Background()

	req := destination.DeliverRequest{
		TargetID:       "owner/repo:SECRET_NAME",
		CredentialValue: []byte("super-secret"),
		Generation:     1,
		DeliveryID:     "uuid-1234",
		CredentialUUID: "cred-uuid-abcd",
	}

	isPerm, err := n.Deliver(ctx, req)
	if err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}
	if isPerm {
		t.Error("Deliver returned isPermanentError=true on success, want false")
	}

	if n.DeliveryCount() != 1 {
		t.Errorf("DeliveryCount() = %d, want 1", n.DeliveryCount())
	}

	rec, ok := n.LastDelivery()
	if !ok {
		t.Fatal("LastDelivery() returned false, want true")
	}
	if rec.TargetID != req.TargetID {
		t.Errorf("LastDelivery().TargetID = %q, want %q", rec.TargetID, req.TargetID)
	}
	if rec.Generation != req.Generation {
		t.Errorf("LastDelivery().Generation = %d, want %d", rec.Generation, req.Generation)
	}
	if rec.DeliveryID != req.DeliveryID {
		t.Errorf("LastDelivery().DeliveryID = %q, want %q", rec.DeliveryID, req.DeliveryID)
	}
}

// TestNoopDeliverer_Deliver_Idempotent verifies that delivering the same
// generation twice (same delivery_id, same generation) succeeds both times
// and produces the same observable outcome. This models idempotent retry.
func TestNoopDeliverer_Deliver_Idempotent(t *testing.T) {
	n := NewNoopDeliverer()
	ctx := context.Background()

	req := destination.DeliverRequest{
		TargetID:       "namespace/secret:key",
		CredentialValue: []byte("credential"),
		Generation:     3,
		DeliveryID:     "retry-uuid-5678",
	}

	// First call.
	if _, err := n.Deliver(ctx, req); err != nil {
		t.Fatalf("first Deliver returned error: %v", err)
	}

	// Second call with identical parameters (retry scenario).
	isPerm, err := n.Deliver(ctx, req)
	if err != nil {
		t.Fatalf("second Deliver (retry) returned error: %v", err)
	}
	if isPerm {
		t.Error("second Deliver returned isPermanentError=true, want false")
	}

	// Both calls succeed; count is 2.
	if n.DeliveryCount() != 2 {
		t.Errorf("DeliveryCount() = %d, want 2 after two identical calls", n.DeliveryCount())
	}

	// The last generation stored is still 3 (no regression).
	rec, _ := n.LastDelivery()
	if rec.Generation != 3 {
		t.Errorf("LastDelivery().Generation = %d, want 3", rec.Generation)
	}
}

// TestNoopDeliverer_Deliver_GenerationRegression verifies that sending a
// generation lower than the last delivered generation returns a permanent error
// with no side effects.
func TestNoopDeliverer_Deliver_GenerationRegression(t *testing.T) {
	n := NewNoopDeliverer()
	ctx := context.Background()
	target := "myservice.service:CRED"

	// Deliver generation 5.
	_, err := n.Deliver(ctx, destination.DeliverRequest{
		TargetID:   target,
		Generation: 5,
		DeliveryID: "first",
	})
	if err != nil {
		t.Fatalf("Deliver gen=5: %v", err)
	}

	// Deliver generation 3 — regression.
	isPerm, err := n.Deliver(ctx, destination.DeliverRequest{
		TargetID:   target,
		Generation: 3,
		DeliveryID: "regression-retry",
	})
	if err == nil {
		t.Fatal("Deliver gen=3 after gen=5: expected GENERATION_REGRESSION error, got nil")
	}
	if !isPerm {
		t.Error("GENERATION_REGRESSION should be a permanent error, got isPermanentError=false")
	}

	// DeliveryCount should still be 1 (the regression was rejected).
	if n.DeliveryCount() != 1 {
		t.Errorf("DeliveryCount() = %d, want 1 (regression not counted)", n.DeliveryCount())
	}
}

// TestNoopDeliverer_Deliver_ZeroGenerationInvalid verifies that generation=0
// is rejected as a permanent error.
func TestNoopDeliverer_Deliver_ZeroGenerationInvalid(t *testing.T) {
	n := NewNoopDeliverer()
	ctx := context.Background()

	isPerm, err := n.Deliver(ctx, destination.DeliverRequest{
		TargetID:   "any-target",
		Generation: 0,
		DeliveryID: "bad-gen",
	})
	if err == nil {
		t.Fatal("Deliver gen=0: expected error, got nil")
	}
	if !isPerm {
		t.Error("generation=0 should be a permanent error, got isPermanentError=false")
	}
}

// TestNoopDeliverer_Revoke_RecordsCall verifies that a Revoke call is recorded
// and RevocationCount increments.
func TestNoopDeliverer_Revoke_RecordsCall(t *testing.T) {
	n := NewNoopDeliverer()
	ctx := context.Background()

	isPerm, err := n.Revoke(ctx, "owner/repo:SECRET", 1, nil)
	if err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	if isPerm {
		t.Error("Revoke returned isPermanentError=true, want false")
	}
	if n.RevocationCount() != 1 {
		t.Errorf("RevocationCount() = %d, want 1", n.RevocationCount())
	}

	rec, ok := n.LastRevocation()
	if !ok {
		t.Fatal("LastRevocation() returned false, want true")
	}
	if rec.TargetID != "owner/repo:SECRET" {
		t.Errorf("LastRevocation().TargetID = %q, want %q", rec.TargetID, "owner/repo:SECRET")
	}
}

// TestNoopDeliverer_Revoke_Idempotent verifies that revoking twice for the
// same target and generation both return nil (idempotent).
func TestNoopDeliverer_Revoke_Idempotent(t *testing.T) {
	n := NewNoopDeliverer()
	ctx := context.Background()

	// First revoke.
	_, err := n.Revoke(ctx, "vault/secret:mykey", 5, nil)
	if err != nil {
		t.Fatalf("first Revoke: %v", err)
	}

	// Second revoke (idempotent — credential already absent).
	_, err = n.Revoke(ctx, "vault/secret:mykey", 5, nil)
	if err != nil {
		t.Errorf("second Revoke (idempotent): %v", err)
	}

	if n.RevocationCount() != 2 {
		t.Errorf("RevocationCount() = %d, want 2", n.RevocationCount())
	}
}

// TestNoopDeliverer_Health_AlwaysNil verifies Health always returns nil.
func TestNoopDeliverer_Health_AlwaysNil(t *testing.T) {
	n := NewNoopDeliverer()
	ctx := context.Background()

	if err := n.Health(ctx); err != nil {
		t.Errorf("Health() returned error: %v", err)
	}
}

// TestNoopDeliverer_NoDeliveryRecord_BeforeAnyCall verifies the initial state.
func TestNoopDeliverer_NoDeliveryRecord_BeforeAnyCall(t *testing.T) {
	n := NewNoopDeliverer()

	if n.DeliveryCount() != 0 {
		t.Errorf("initial DeliveryCount() = %d, want 0", n.DeliveryCount())
	}
	if n.RevocationCount() != 0 {
		t.Errorf("initial RevocationCount() = %d, want 0", n.RevocationCount())
	}
	if _, ok := n.LastDelivery(); ok {
		t.Error("LastDelivery() returned true before any delivery, want false")
	}
	if _, ok := n.LastRevocation(); ok {
		t.Error("LastRevocation() returned true before any revocation, want false")
	}
}

// TestNoopDeliverer_MultipleTargets_IndependentGenerations verifies that
// generation tracking is per-target, not global.
func TestNoopDeliverer_MultipleTargets_IndependentGenerations(t *testing.T) {
	n := NewNoopDeliverer()
	ctx := context.Background()

	// Deliver gen=5 to target A.
	if _, err := n.Deliver(ctx, destination.DeliverRequest{
		TargetID: "target-A", Generation: 5, DeliveryID: "d1",
	}); err != nil {
		t.Fatalf("Deliver target-A gen=5: %v", err)
	}

	// Deliver gen=1 to target B — should succeed (independent counter).
	if _, err := n.Deliver(ctx, destination.DeliverRequest{
		TargetID: "target-B", Generation: 1, DeliveryID: "d2",
	}); err != nil {
		t.Fatalf("Deliver target-B gen=1: %v", err)
	}

	// Deliver gen=3 to target A — regression (5 > 3), should fail.
	isPerm, err := n.Deliver(ctx, destination.DeliverRequest{
		TargetID: "target-A", Generation: 3, DeliveryID: "d3",
	})
	if err == nil {
		t.Error("Deliver target-A gen=3 after gen=5: expected error, got nil")
	}
	if !isPerm {
		t.Error("expected permanent error for regression on target-A")
	}

	// Deliver gen=2 to target B — valid (1 < 2).
	if _, err := n.Deliver(ctx, destination.DeliverRequest{
		TargetID: "target-B", Generation: 2, DeliveryID: "d4",
	}); err != nil {
		t.Fatalf("Deliver target-B gen=2: %v", err)
	}
}

// TestNoopDeliverer_ImplementsInterface is a compile-time check embedded in a
// runtime test to make the failure mode obvious.
func TestNoopDeliverer_ImplementsInterface(t *testing.T) {
	var _ destination.DestinationDeliverer = NewNoopDeliverer()
}
