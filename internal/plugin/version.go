package plugin

import (
	"fmt"

	"github.com/agentkms/agentkms/internal/credentials"
)

// CurrentAPIVersion is the plugin API version supported by this host.
const CurrentAPIVersion = 1

// PluginInfo is the metadata a plugin provides at registration time.
type PluginInfo struct {
	Kind       string // credential kind discriminator
	APIVersion int    // plugin API version the plugin was built against
	Name       string // human-readable plugin name
	Version    string // plugin's own semver
}

// RegisterWithInfo registers a plugin with full metadata including API version.
// Returns error if API version is incompatible.
func (r *Registry) RegisterWithInfo(info PluginInfo, validator credentials.ScopeValidator) error {
	// STUB: always returns error so tests fail until implemented.
	return fmt.Errorf("RegisterWithInfo not implemented")
}

// LookupInfo returns both the validator and its registration info.
func (r *Registry) LookupInfo(kind string) (credentials.ScopeValidator, *PluginInfo, error) {
	// STUB: always returns error so tests fail until implemented.
	return nil, nil, fmt.Errorf("LookupInfo not implemented")
}
