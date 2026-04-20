package plugin

import "github.com/agentkms/agentkms/internal/credentials"

// Registry maps credential Kinds to their ScopeValidator implementations.
type Registry struct{}

// NewRegistry creates a new empty Registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a plugin's ScopeValidator to the registry under the given Kind.
func (r *Registry) Register(kind string, validator credentials.ScopeValidator) error {
	return nil
}

// Lookup returns the ScopeValidator for a given Kind. Returns an error if not found.
func (r *Registry) Lookup(kind string) (credentials.ScopeValidator, error) {
	return nil, nil
}

// Kinds returns all registered Kinds.
func (r *Registry) Kinds() []string {
	return nil
}
