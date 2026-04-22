package plugin

import (
	"fmt"
	"sync"

	"github.com/agentkms/agentkms/internal/credentials"
)

// Registry maps credential Kinds to their implementations.
// Each interface type (ScopeValidator, ScopeAnalyzer, ScopeSerializer,
// CredentialVender) has its own independent map — registering the same Kind
// in multiple maps is legal and expected.
//
// All maps are guarded by a single sync.RWMutex. Reads use RLock;
// writes use Lock.
type Registry struct {
	mu          sync.RWMutex
	validators  map[string]credentials.ScopeValidator
	analyzers   map[string]credentials.ScopeAnalyzer
	serializers map[string]credentials.ScopeSerializer
	venders     map[string]credentials.CredentialVender
	pluginInfos map[string]PluginInfo
}

// NewRegistry creates a new empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		validators:  make(map[string]credentials.ScopeValidator),
		analyzers:   make(map[string]credentials.ScopeAnalyzer),
		serializers: make(map[string]credentials.ScopeSerializer),
		venders:     make(map[string]credentials.CredentialVender),
		pluginInfos: make(map[string]PluginInfo),
	}
}

// ── ScopeValidator ────────────────────────────────────────────────────────────

// Register adds a plugin's ScopeValidator to the registry under the given Kind.
// Returns an error if the Kind is already registered.
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

// Kinds returns all registered ScopeValidator Kinds.
func (r *Registry) Kinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	kinds := make([]string, 0, len(r.validators))
	for k := range r.validators {
		kinds = append(kinds, k)
	}
	return kinds
}

// ── ScopeAnalyzer ─────────────────────────────────────────────────────────────

// RegisterAnalyzer adds a ScopeAnalyzer to the registry under the given Kind.
// Returns an error if the Kind is already registered in the analyzer map.
func (r *Registry) RegisterAnalyzer(kind string, a credentials.ScopeAnalyzer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.analyzers[kind]; exists {
		return fmt.Errorf("analyzer kind %q already registered", kind)
	}
	r.analyzers[kind] = a
	return nil
}

// LookupAnalyzer returns the ScopeAnalyzer for a given Kind.
// Returns an error if not found.
func (r *Registry) LookupAnalyzer(kind string) (credentials.ScopeAnalyzer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	a, ok := r.analyzers[kind]
	if !ok {
		return nil, fmt.Errorf("analyzer kind %q not registered", kind)
	}
	return a, nil
}

// AnalyzerKinds returns all registered ScopeAnalyzer Kinds.
func (r *Registry) AnalyzerKinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	kinds := make([]string, 0, len(r.analyzers))
	for k := range r.analyzers {
		kinds = append(kinds, k)
	}
	return kinds
}

// ── ScopeSerializer ───────────────────────────────────────────────────────────

// RegisterSerializer adds a ScopeSerializer to the registry under the given Kind.
// Returns an error if the Kind is already registered in the serializer map.
func (r *Registry) RegisterSerializer(kind string, s credentials.ScopeSerializer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.serializers[kind]; exists {
		return fmt.Errorf("serializer kind %q already registered", kind)
	}
	r.serializers[kind] = s
	return nil
}

// LookupSerializer returns the ScopeSerializer for a given Kind.
// Returns an error if not found.
func (r *Registry) LookupSerializer(kind string) (credentials.ScopeSerializer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	s, ok := r.serializers[kind]
	if !ok {
		return nil, fmt.Errorf("serializer kind %q not registered", kind)
	}
	return s, nil
}

// SerializerKinds returns all registered ScopeSerializer Kinds.
func (r *Registry) SerializerKinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	kinds := make([]string, 0, len(r.serializers))
	for k := range r.serializers {
		kinds = append(kinds, k)
	}
	return kinds
}

// ── CredentialVender ──────────────────────────────────────────────────────────

// RegisterVender adds a CredentialVender to the registry under the given Kind.
// Returns an error if the Kind is already registered in the vender map.
func (r *Registry) RegisterVender(kind string, v credentials.CredentialVender) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.venders[kind]; exists {
		return fmt.Errorf("vender kind %q already registered", kind)
	}
	r.venders[kind] = v
	return nil
}

// LookupVender returns the CredentialVender for a given Kind.
// Returns an error if not found.
func (r *Registry) LookupVender(kind string) (credentials.CredentialVender, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, ok := r.venders[kind]
	if !ok {
		return nil, fmt.Errorf("vender kind %q not registered", kind)
	}
	return v, nil
}

// VenderKinds returns all registered CredentialVender Kinds.
func (r *Registry) VenderKinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	kinds := make([]string, 0, len(r.venders))
	for k := range r.venders {
		kinds = append(kinds, k)
	}
	return kinds
}
