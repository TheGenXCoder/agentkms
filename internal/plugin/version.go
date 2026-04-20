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
	if info.APIVersion == 0 {
		return fmt.Errorf("plugin %q did not declare API version", info.Kind)
	}
	if info.APIVersion > CurrentAPIVersion {
		return fmt.Errorf("plugin %q requires newer API version %d (host supports %d)", info.Kind, info.APIVersion, CurrentAPIVersion)
	}
	if info.APIVersion < CurrentAPIVersion {
		return fmt.Errorf("plugin %q uses outdated API version %d (host requires %d)", info.Kind, info.APIVersion, CurrentAPIVersion)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.validators[info.Kind]; exists {
		return fmt.Errorf("plugin kind %q already registered", info.Kind)
	}
	r.validators[info.Kind] = validator
	r.pluginInfos[info.Kind] = info
	return nil
}

// LookupInfo returns both the validator and its registration info.
func (r *Registry) LookupInfo(kind string) (credentials.ScopeValidator, *PluginInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, ok := r.validators[kind]
	if !ok {
		return nil, nil, fmt.Errorf("plugin kind %q not registered", kind)
	}
	info, hasInfo := r.pluginInfos[kind]
	if !hasInfo {
		return v, nil, nil
	}
	return v, &info, nil
}
