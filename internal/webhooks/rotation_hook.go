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
}
