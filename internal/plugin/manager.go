package plugin

// Manager handles plugin installation, removal, and listing.
type Manager struct {
	pluginDir string
	registry  *Registry
}

// NewManager creates a Manager that manages plugins in pluginDir.
func NewManager(pluginDir string, registry *Registry) *Manager {
	return &Manager{
		pluginDir: pluginDir,
		registry:  registry,
	}
}

// Install copies a plugin binary from sourcePath to the plugin directory.
func (m *Manager) Install(sourcePath string) (*PluginMeta, error) {
	return nil, nil
}

// Remove deletes a plugin binary from the plugin directory.
func (m *Manager) Remove(name string) error {
	return nil
}

// Installed returns metadata for all installed plugins.
func (m *Manager) Installed() ([]PluginMeta, error) {
	return nil, nil
}

// Search returns plugin names from the registry matching query.
func (m *Manager) Search(query string) ([]string, error) {
	return nil, nil
}
