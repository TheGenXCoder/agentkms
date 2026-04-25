// Package destination defines the Go interface for credential delivery plugins.
//
// A destination plugin receives a vended credential from the AgentKMS
// orchestrator and writes it into a consumer-side target — a GitHub Actions
// repository secret, a Kubernetes Secret, a .env file, a Vault KV path, etc.
// The plugin owns every byte of I/O against that target system. The orchestrator
// owns policy, ordering, audit, and retry decisions.
//
// See docs/specs/2026-04-25-destination-plugin-interface.md for the full spec.
package destination

import (
	"context"
	"time"
)

// DestinationDeliverer writes credential values to a consumer-side target.
// Implementations must be safe for concurrent use.
//
// Interface mirrors the DestinationDelivererService wire protocol defined in
// api/plugin/v1/destination.proto.
type DestinationDeliverer interface {
	// Kind returns the destination kind this deliverer handles (e.g. "github-secret").
	// Called once at startup; the result is stored on the adapter and used to
	// register the plugin in the destination registry.
	Kind() string

	// Validate performs a pre-flight connectivity and permission check.
	// Must not write any secret material. Must complete within 10 seconds.
	// A non-nil return is treated as a permanent configuration error by the
	// orchestrator — there is no transient pre-flight failure.
	Validate(ctx context.Context, params map[string]any) error

	// Deliver writes value to the target identified by targetID.
	// Idempotent: multiple calls with the same deliveryID and generation produce
	// the same observable outcome. Plugins must not create duplicate entries.
	//
	// Returns (false, nil) on success.
	// Returns (false, err) for transient errors (orchestrator will retry).
	// Returns (true, err) for permanent errors (orchestrator will not retry).
	Deliver(ctx context.Context, req DeliverRequest) (isPermanentError bool, err error)

	// Revoke removes the credential from the target identified by targetID.
	// Idempotent: returns nil if the credential is already absent.
	// Returns (false, err) for transient; (true, err) for permanent errors.
	Revoke(ctx context.Context, targetID string, generation uint64, params map[string]any) (isPermanentError bool, err error)

	// Health returns nil if the destination is reachable and writeable.
	// Must complete within 5 seconds. Must not write any data.
	// Called by the host health loop every 30 seconds.
	Health(ctx context.Context) error
}

// DeliverRequest is the input to DestinationDeliverer.Deliver.
// Mirrors the DeliverRequest proto message in api/plugin/v1/destination.proto.
type DeliverRequest struct {
	// TargetID is the opaque, kind-scoped identifier for the specific secret slot.
	// Format is defined per plugin kind (see spec §7.3).
	TargetID string

	// CredentialValue is the raw credential bytes to write to the target.
	// SECURITY: Implementations must not log this field.
	// Zero the buffer after use where the runtime allows it.
	CredentialValue []byte

	// Generation is a monotonically increasing rotation counter.
	// Starts at 1 for the first delivery; increments by 1 on each rotation.
	// Plugins must reject requests where Generation < last successfully delivered
	// generation with a permanent error.
	Generation uint64

	// DeliveryID is a UUID v4 assigned by the orchestrator for this rotation
	// event (not this individual RPC call). Retries of the same rotation carry
	// the same DeliveryID so plugins can detect and de-duplicate retry calls.
	DeliveryID string

	// TTL is the credential's expected lifetime from issuance.
	// Informational hint only. Zero if not specified.
	TTL time.Duration

	// ExpiresAt is the wall-clock expiry of the credential.
	// Informational hint. Zero value if not specified.
	ExpiresAt time.Time

	// RequesterID is the stable identity string of the entity that triggered
	// this vend (from mTLS cert CN or AgentKMS identity token).
	RequesterID string

	// CredentialUUID is the UUID of the VendedCredential this delivery
	// corresponds to. Used for audit correlation.
	CredentialUUID string

	// Params holds kind-specific delivery parameters.
	// Shape is defined per plugin kind.
	Params map[string]any
}
