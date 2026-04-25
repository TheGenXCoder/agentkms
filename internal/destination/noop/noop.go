// Package noop provides a no-op DestinationDeliverer implementation for use
// as a test fixture and orchestrator development aid.
//
// The no-op destination:
//   - Returns Kind() = "noop"
//   - Returns Capabilities() = ["health", "revoke"]
//   - Validate always succeeds
//   - Deliver records the call to an in-memory ring buffer, returns no error
//   - Revoke records the call to an in-memory ring buffer, returns no error
//   - Health always returns nil (healthy)
//
// The ring buffer capacity is fixed at ringBufferSize deliveries. Older entries
// are overwritten when the buffer fills. The buffer is safe for concurrent use.
//
// This is NOT a production implementation. It performs no I/O against any target
// system and stores no credentials. It is used by:
//   - Unit and integration tests for the orchestrator (T5 task)
//   - Local development to test rotation pipelines end-to-end
package noop

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/agentkms/agentkms/internal/destination"
)

const (
	ringBufferSize = 64
	noopKind       = "noop"
)

// DeliveryRecord captures the inputs of a single Deliver call for test inspection.
type DeliveryRecord struct {
	TargetID       string
	Generation     uint64
	DeliveryID     string
	CredentialUUID string
	RecordedAt     time.Time
}

// RevokeRecord captures the inputs of a single Revoke call for test inspection.
type RevokeRecord struct {
	TargetID   string
	Generation uint64
	RecordedAt time.Time
}

// NoopDeliverer is the no-op DestinationDeliverer implementation.
// Zero value is not usable; use NewNoopDeliverer().
type NoopDeliverer struct {
	mu              sync.Mutex
	deliveries      [ringBufferSize]DeliveryRecord
	deliveryCount   int // total deliveries recorded (wraps to ringBufferSize)
	revocations     [ringBufferSize]RevokeRecord
	revocationCount int

	// lastGeneration tracks the last successfully delivered generation per
	// target to enforce the GENERATION_REGRESSION check.
	lastGeneration map[string]uint64
}

// NewNoopDeliverer creates a new NoopDeliverer ready for use.
func NewNoopDeliverer() *NoopDeliverer {
	return &NoopDeliverer{
		lastGeneration: make(map[string]uint64),
	}
}

// Ensure NoopDeliverer implements DestinationDeliverer at compile time.
var _ destination.DestinationDeliverer = (*NoopDeliverer)(nil)

// Kind returns "noop".
func (n *NoopDeliverer) Kind() string { return noopKind }

// Validate performs a no-op pre-flight check. Always returns nil.
func (n *NoopDeliverer) Validate(_ context.Context, _ map[string]any) error {
	return nil
}

// Deliver records the delivery to the in-memory ring buffer and returns
// DESTINATION_OK (no error). Enforces the generation regression check.
//
// Returns (true, err) for GENERATION_REGRESSION (permanent).
// Returns (false, nil) on success.
func (n *NoopDeliverer) Deliver(_ context.Context, req destination.DeliverRequest) (bool, error) {
	if req.Generation == 0 {
		return true, fmt.Errorf("noop: generation 0 is invalid")
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Check for generation regression.
	if last, ok := n.lastGeneration[req.TargetID]; ok && req.Generation < last {
		return true, fmt.Errorf("noop: generation regression: got %d, last delivered %d for target %q",
			req.Generation, last, req.TargetID)
	}

	// Record delivery.
	slot := n.deliveryCount % ringBufferSize
	n.deliveries[slot] = DeliveryRecord{
		TargetID:       req.TargetID,
		Generation:     req.Generation,
		DeliveryID:     req.DeliveryID,
		CredentialUUID: req.CredentialUUID,
		RecordedAt:     time.Now(),
	}
	n.deliveryCount++
	n.lastGeneration[req.TargetID] = req.Generation

	return false, nil
}

// Revoke records the revocation to the in-memory ring buffer and returns nil.
// Idempotent: always succeeds, even if the target is already absent.
//
// Returns (false, nil) always.
func (n *NoopDeliverer) Revoke(_ context.Context, targetID string, generation uint64, _ map[string]any) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	slot := n.revocationCount % ringBufferSize
	n.revocations[slot] = RevokeRecord{
		TargetID:   targetID,
		Generation: generation,
		RecordedAt: time.Now(),
	}
	n.revocationCount++

	return false, nil
}

// Health always returns nil (healthy).
func (n *NoopDeliverer) Health(_ context.Context) error { return nil }

// ── Test inspection helpers ───────────────────────────────────────────────────

// DeliveryCount returns the total number of Deliver calls recorded.
func (n *NoopDeliverer) DeliveryCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.deliveryCount
}

// RevocationCount returns the total number of Revoke calls recorded.
func (n *NoopDeliverer) RevocationCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.revocationCount
}

// LastDelivery returns the most recent DeliveryRecord, and a bool indicating
// whether any delivery has been recorded.
func (n *NoopDeliverer) LastDelivery() (DeliveryRecord, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.deliveryCount == 0 {
		return DeliveryRecord{}, false
	}
	slot := (n.deliveryCount - 1) % ringBufferSize
	return n.deliveries[slot], true
}

// LastRevocation returns the most recent RevokeRecord, and a bool indicating
// whether any revocation has been recorded.
func (n *NoopDeliverer) LastRevocation() (RevokeRecord, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.revocationCount == 0 {
		return RevokeRecord{}, false
	}
	slot := (n.revocationCount - 1) % ringBufferSize
	return n.revocations[slot], true
}

// Capabilities returns the static capability set for the no-op deliverer.
// This is the Go-level capability list, not the proto RPC — used by tests
// to verify capability negotiation behaviour.
func (n *NoopDeliverer) Capabilities() []string {
	return []string{"health", "revoke"}
}
