package webhooks

import (
	"context"
	"errors"
)

// ErrNoBinding indicates the credential is not managed by any binding.
// The webhook orchestrator falls back to its existing revoker-only
// behavior when this error is returned.
var ErrNoBinding = errors.New("webhooks: credential not managed by any binding")

// RotationHook is an optional extension point for AlertOrchestrator.
// When registered, it is called in place of the provider-level
// revocation during the LiveRevokedBranch path — the hook implementation
// owns the full rotate-then-revoke-old lifecycle.
//
// Implementations are typically supplied by license-gated plugins
// (e.g., the Pro rotation orchestrator), but the interface is public
// and any third-party plugin may implement it.
type RotationHook interface {
	// TriggerRotation initiates an emergency rotation for the credential
	// identified by credentialUUID. Returns immediately; rotation
	// proceeds asynchronously. The caller MUST NOT also call
	// Revoker.Revoke — the rotation hook owns revocation of the old
	// credential after delivery completes.
	//
	// Returns nil on successful trigger (rotation may still fail
	// asynchronously; see audit log). Returns a non-nil error if the
	// rotation could not be triggered at all.
	TriggerRotation(ctx context.Context, credentialUUID string) error

	// BindingForCredential returns the binding name associated with a
	// given credentialUUID, or ("", ErrNoBinding) if the credential is
	// not managed by any binding.
	//
	// The webhook orchestrator uses this to decide whether to delegate
	// to TriggerRotation (binding exists) or fall back to revoker-only
	// (no binding).
	BindingForCredential(ctx context.Context, credentialUUID string) (string, error)

	// RotateBinding executes a synchronous, full rotation for the named
	// binding — vend new credential, deliver to all destinations, update
	// metadata, revoke old credential per grace-period policy.
	//
	// Called by the OSS rotate handler (POST /bindings/{name}/rotate) when
	// the Pro orchestrator is loaded. Unlike TriggerRotation (credential UUID,
	// async), RotateBinding takes a binding name and blocks until the
	// rotation state machine completes (or fails). The handler uses the
	// returned error to determine whether to return 200 OK or 500 to the CLI.
	//
	// Implementations must emit the full audit chain (binding_rotate_start,
	// binding_rotate, destination_deliver events) via HostService.EmitAudit
	// so forensics queries see a unified stream. The OSS rotate handler does
	// NOT emit an additional OperationBindingRotate after this call returns.
	//
	// Returns nil on success (including degraded/partial-success). Returns a
	// non-nil error only when the rotation failed completely (all destinations
	// failed, vend failed, or the orchestrator was not yet initialized).
	RotateBinding(ctx context.Context, bindingName string) error
}
