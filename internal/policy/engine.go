// Package policy implements the AgentKMS policy engine.
//
// Every operation is evaluated against policy before it reaches the Backend.
// The engine is deny-by-default: an empty policy denies ALL operations.
// Policy dimensions: identity, key scope, operation type, rate, time window.
//
// Backlog: P-01 to P-08.
package policy

import (
	"context"
	"fmt"

	"github.com/agentkms/agentkms/pkg/identity"
)

// Decision is the result of a policy evaluation.
type Decision struct {
	// Allow is true if the operation is permitted by policy.
	Allow bool

	// DenyReason explains why the operation was denied.  Empty when Allow
	// is true.  This string is written to the audit log only — it is NEVER
	// included in HTTP responses to callers (which would leak policy
	// structure).
	DenyReason string
}

// Engine evaluates policy for every (identity, operation, key-id) triple.
//
// SECURITY CONTRACT:
//  1. Deny-by-default: if no rule explicitly allows an operation, Evaluate
//     must return Decision{Allow: false}.
//  2. Evaluate must be safe for concurrent use by multiple goroutines.
//  3. Evaluate must not perform any Backend or I/O operations that could
//     block indefinitely; it must respect the context deadline.
//
// Full implementation: backlog P-01 to P-04.
// Current T0 implementations: DenyAllEngine (production-safe default),
// AllowAllEngine (unit tests only — never use in production).
type Engine interface {
	Evaluate(ctx context.Context, id identity.Identity, operation string, keyID string) (Decision, error)
}

// ── DenyAllEngine ─────────────────────────────────────────────────────────────

// DenyAllEngine is the safe default Engine used until the real policy engine
// (backlog P-01 to P-04) is implemented.
//
// It denies every operation regardless of identity, operation type, or key ID.
// This is the correct safe default: no operation succeeds without explicit
// policy configuration.
//
// TODO(P-01,P-02,P-03): Replace with the full policy engine implementation.
// Replace the DenyAllEngine in cmd/server/main.go once P-03 is complete.
type DenyAllEngine struct{}

// Evaluate always returns a denial with a clear reason.
func (DenyAllEngine) Evaluate(_ context.Context, id identity.Identity, operation, keyID string) (Decision, error) {
	return Decision{
		Allow: false,
		DenyReason: fmt.Sprintf(
			"policy engine not configured: no rules permit %s on key %q for identity %q (pending P-01 to P-04)",
			operation, keyID, id.CallerID,
		),
	}, nil
}

// ── AllowAllEngine ────────────────────────────────────────────────────────────

// AllowAllEngine is a test-only Engine that permits every operation
// unconditionally.
//
// ⚠️  NEVER use AllowAllEngine in production or staging environments.
// It bypasses all access controls.  It exists solely to allow handler unit
// tests to reach the Backend layer without a fully implemented policy engine.
//
// Tests should use AllowAllEngine only via explicit construction in test files;
// production wiring must use DenyAllEngine until P-01 to P-04 are complete.
type AllowAllEngine struct{}

// Evaluate always returns allow.
func (AllowAllEngine) Evaluate(_ context.Context, _ identity.Identity, _, _ string) (Decision, error) {
	return Decision{Allow: true}, nil
}
