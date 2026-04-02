package api

import (
	"context"

	"github.com/agentkms/agentkms/pkg/identity"
)

// contextKey is an unexported type for context keys within this package.
// Using a package-scoped type prevents key collisions with other packages
// that also use context values.
type contextKey string

const (
	// identityKey is the context key under which the caller's verified
	// Identity is stored by the authentication middleware.
	identityKey contextKey = "agentkms.identity"
)

// setIdentityInContext returns a new context carrying the given Identity.
// Called by the authentication middleware after the session token is
// validated.
//
// The identity must be fully populated (CallerID, TeamID, Role at minimum)
// before being stored.  Handlers must call identityFromContext to retrieve it.
func setIdentityInContext(ctx context.Context, id identity.Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// identityFromContext retrieves the caller Identity from ctx.
//
// Returns the zero-value Identity if no identity has been set (which should
// not happen in production once A-04 middleware is active, but may happen in
// tests that bypass the middleware chain).
func identityFromContext(ctx context.Context) identity.Identity {
	id, _ := ctx.Value(identityKey).(identity.Identity)
	return id
}
