package plugin

import (
	"fmt"
	"sync"

	"github.com/agentkms/agentkms/internal/credentials"
)

// Registry maps credential Kinds to their ScopeValidator implementations.
type Registry struct {
	mu          sync.RWMutex
	validators  map[string]credentials.ScopeValidator
	pluginInfos map[string]PluginInfo
}

// NewRegistry creates a new empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		validators:  make(map[string]credentials.ScopeValidator),
		pluginInfos: make(map[string]PluginInfo),
	}
}

// Register adds a plugin's ScopeValidator to the registry under the given Kind.
func (r *Registry) Register(kind string, validator credentials.ScopeValidator) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.validators[kind]; exists {
		return fmt.Errorf("plugin kind %q already registered", kind)
	}
	r.validators[kind] = validator
	return nil
}

// Lookup returns the ScopeValidator for a given Kind. Returns an error if not found.
func (r *Registry) Lookup(kind string) (credentials.ScopeValidator, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, ok := r.validators[kind]
	if !ok {
		return nil, fmt.Errorf("plugin kind %q not registered", kind)
	}
	return v, nil
}

// Kinds returns all registered Kinds.
func (r *Registry) Kinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	kinds := make([]string, 0, len(r.validators))
	for k := range r.validators {
		kinds = append(kinds, k)
	}
	return kinds
}
