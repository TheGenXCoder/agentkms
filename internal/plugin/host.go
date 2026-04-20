package plugin

// PluginMeta describes a discovered plugin.
type PluginMeta struct {
	Name         string
	Path         string   // filesystem path to the binary
	APIVersion   int      // major version
	Capabilities []string // which interfaces it implements
}

// Host manages plugin discovery, lifecycle, and dispatch.
type Host struct{}

// NewHost creates a plugin host that discovers plugins in dir.
func NewHost(dir string) (*Host, error) { return nil, nil }

// Discover scans the plugin directory and returns metadata for each
// found plugin binary. Does not start them.
func (h *Host) Discover() ([]PluginMeta, error) { return nil, nil }

// Start launches a plugin subprocess and performs the handshake.
func (h *Host) Start(name string) error { return nil }

// Stop gracefully shuts down a running plugin.
func (h *Host) Stop(name string) error { return nil }

// StopAll gracefully shuts down all running plugins.
func (h *Host) StopAll() {}

// IsRunning returns true if the named plugin is alive.
func (h *Host) IsRunning(name string) bool { return false }

// List returns metadata for all discovered plugins.
func (h *Host) List() []PluginMeta { return nil }
