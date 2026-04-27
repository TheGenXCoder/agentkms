package githubapp

import (
	"context"
	"errors"
)

// ErrNotFound is returned by Store.Get when no App is registered under the
// requested name.
var ErrNotFound = errors.New("githubapp: app not found")

// Store is the read/write interface for GitHub App registrations.
// Implementations must be safe for concurrent use.
type Store interface {
	// Save creates or replaces the GitHub App registration for app.Name.
	Save(ctx context.Context, app GithubApp) error

	// Get retrieves the full GithubApp (including private key) by name.
	// Returns ErrNotFound when no App with that name is registered.
	Get(ctx context.Context, name string) (*GithubApp, error)

	// List returns a summary (no private key) of all registered Apps.
	List(ctx context.Context) ([]Summary, error)

	// Delete removes the registration for the named App.
	// Returns nil (not ErrNotFound) when the App is already absent, so that
	// callers can treat Delete as idempotent.
	Delete(ctx context.Context, name string) error
}
