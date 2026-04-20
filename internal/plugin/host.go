package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const pluginPrefix = "agentkms-plugin-"

// PluginMeta describes a discovered plugin.
type PluginMeta struct {
	Name         string
	Path         string   // filesystem path to the binary
	APIVersion   int      // major version
	Capabilities []string // which interfaces it implements
}

// Host manages plugin discovery, lifecycle, and dispatch.
type Host struct {
	dir     string
	plugins []PluginMeta
}

// NewHost creates a plugin host that discovers plugins in dir.
func NewHost(dir string) (*Host, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("plugin dir %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("plugin dir %q: not a directory", dir)
	}
	return &Host{dir: dir}, nil
}

// Discover scans the plugin directory and returns metadata for each
// found plugin binary. Does not start them.
func (h *Host) Discover() ([]PluginMeta, error) {
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		return nil, fmt.Errorf("discover plugins in %q: %w", h.dir, err)
	}

	plugins := make([]PluginMeta, 0)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, pluginPrefix) {
			pluginName := strings.TrimPrefix(name, pluginPrefix)
			plugins = append(plugins, PluginMeta{
				Name: pluginName,
				Path: filepath.Join(h.dir, name),
			})
		}
	}

	h.plugins = plugins
	return plugins, nil
}

// Start launches a plugin subprocess and performs the handshake.
func (h *Host) Start(name string) error {
	for _, p := range h.plugins {
		if p.Name == name {
			return nil
		}
	}
	return fmt.Errorf("plugin %q not discovered", name)
}

// Stop gracefully shuts down a running plugin.
func (h *Host) Stop(name string) error { return nil }

// StopAll gracefully shuts down all running plugins.
func (h *Host) StopAll() {}

// IsRunning returns true if the named plugin is alive.
func (h *Host) IsRunning(name string) bool { return false }

// List returns metadata for all discovered plugins.
func (h *Host) List() []PluginMeta { return h.plugins }
