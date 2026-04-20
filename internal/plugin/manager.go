package plugin

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

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
	// Verify source exists.
	if _, err := os.Stat(sourcePath); err != nil {
		return nil, fmt.Errorf("source plugin not found: %w", err)
	}

	// Extract plugin name from filename.
	base := filepath.Base(sourcePath)
	name := base
	if strings.HasPrefix(base, pluginPrefix) {
		name = strings.TrimPrefix(base, pluginPrefix)
	}

	// Destination path always uses the canonical prefix.
	destName := pluginPrefix + name
	destPath := filepath.Join(m.pluginDir, destName)

	// Copy the file.
	src, err := os.Open(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("open source: %w", err)
	}
	defer src.Close()

	srcInfo, err := src.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat source: %w", err)
	}

	dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return nil, fmt.Errorf("create destination: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return nil, fmt.Errorf("copy plugin binary: %w", err)
	}

	return &PluginMeta{
		Name: name,
		Path: destPath,
	}, nil
}

// Remove deletes a plugin binary from the plugin directory.
func (m *Manager) Remove(name string) error {
	path := filepath.Join(m.pluginDir, pluginPrefix+name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("plugin %q not installed", name)
	}
	return os.Remove(path)
}

// Installed returns metadata for all installed plugins.
func (m *Manager) Installed() ([]PluginMeta, error) {
	entries, err := os.ReadDir(m.pluginDir)
	if err != nil {
		return nil, fmt.Errorf("read plugin dir: %w", err)
	}

	plugins := make([]PluginMeta, 0)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), pluginPrefix) {
			name := strings.TrimPrefix(e.Name(), pluginPrefix)
			plugins = append(plugins, PluginMeta{
				Name: name,
				Path: filepath.Join(m.pluginDir, e.Name()),
			})
		}
	}
	return plugins, nil
}

// Search returns plugin names from the registry matching query.
func (m *Manager) Search(query string) ([]string, error) {
	return []string{}, nil
}
