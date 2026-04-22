package plugin

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	hclog "github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

const pluginPrefix = "agentkms-plugin-"

// ErrUntrustedPlugin is returned by Host.Start when signature verification fails.
var ErrUntrustedPlugin = errors.New("plugin signature verification failed")

// ErrNotDiscovered is returned by Host.Start when the named plugin was not found
// during the most recent Discover() call.
var ErrNotDiscovered = errors.New("plugin not discovered")

// healthCheckInterval is how often the host pings each running plugin.
const healthCheckInterval = 30 * time.Second

// PluginMeta describes a discovered plugin.
type PluginMeta struct {
	Name         string
	Path         string   // filesystem path to the binary
	APIVersion   int      // major version
	Capabilities []string // which interfaces it implements
}

// pluginEntry tracks a running go-plugin client alongside its cancel function.
type pluginEntry struct {
	client *goplugin.Client
	cancel context.CancelFunc
}

// Host manages plugin discovery, lifecycle, and dispatch.
//
// Subprocess lifecycle:
//   - Plugins are started on demand via Start(name).
//   - A background goroutine pings each plugin every 30 s.
//   - On ping failure the host attempts one restart; on second failure the plugin
//     is marked failed and removed from active dispatch.
//   - StopAll() kills every running subprocess on host shutdown.
type Host struct {
	dir      string
	plugins  []PluginMeta
	verifier *Verifier  // Ed25519 verifier; nil = signing disabled (with warning)
	registry *Registry  // optional: populated with gRPC adapters after Start

	mu      sync.Mutex
	clients map[string]*pluginEntry // keyed by plugin name
}

// NewHost creates a plugin host that discovers plugins in dir.
// Signature verification is disabled (verifier = nil).
func NewHost(dir string) (*Host, error) {
	return NewHostWithVerifier(dir, nil)
}

// NewHostWithVerifier creates a plugin host with Ed25519 signature verification.
// If verifier is nil, unsigned plugins are permitted with a log warning.
func NewHostWithVerifier(dir string, verifier *Verifier) (*Host, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("plugin dir %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("plugin dir %q: not a directory", dir)
	}
	return &Host{
		dir:      dir,
		verifier: verifier,
		clients:  make(map[string]*pluginEntry),
	}, nil
}

// NewHostWithRegistry creates a plugin host that registers gRPC adapters into
// registry after each successful Start() call. Verifier is nil (no signing).
func NewHostWithRegistry(dir string, registry *Registry) (*Host, error) {
	h, err := NewHostWithVerifier(dir, nil)
	if err != nil {
		return nil, err
	}
	h.registry = registry
	return h, nil
}

// Discover scans the plugin directory and returns metadata for each found plugin
// binary. Does not start them.
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
			// Skip .sig sidecar files.
			if strings.HasSuffix(name, ".sig") {
				continue
			}
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

// Start launches a plugin subprocess using hashicorp/go-plugin and performs
// the gRPC handshake. If the host has a Verifier, the binary signature is
// checked before launch — a failed verification returns ErrUntrustedPlugin.
//
// Start is idempotent: calling it on an already-running plugin is a no-op.
//
// After a successful handshake the host calls Kind() on the ScopeValidatorService
// and registers a ScopeValidatorGRPC adapter into the Registry (if configured).
func (h *Host) Start(name string) error {
	// Find the plugin path from the most recent Discover() call.
	pluginPath, err := h.findPluginPath(name)
	if err != nil {
		return err
	}

	h.mu.Lock()
	// Idempotency: already running?
	if entry, ok := h.clients[name]; ok {
		if !entry.client.Exited() {
			h.mu.Unlock()
			return nil
		}
		// Clean up the stale entry.
		entry.cancel()
		delete(h.clients, name)
	}
	h.mu.Unlock()

	// Signature verification (before subprocess launch).
	if h.verifier != nil {
		sigPath := pluginPath + ".sig"
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			return fmt.Errorf("%w: cannot read .sig sidecar %q: %v", ErrUntrustedPlugin, sigPath, err)
		}
		if err := h.verifier.Verify(pluginPath, sig); err != nil {
			return fmt.Errorf("%w: %v", ErrUntrustedPlugin, err)
		}
	} else {
		log.Printf("[plugin] WARNING: no verifier configured for %q — running unsigned binary", name)
	}

	// Build the go-plugin client.
	ctx, cancel := context.WithCancel(context.Background())
	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig:  HandshakeConfig,
		Plugins:          PluginMap,
		Cmd:              pluginCommand(pluginPath),
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		Logger:           newPluginLogger(name),
		StartTimeout:     30 * time.Second,
	})

	// Connect and perform the handshake. This forks the subprocess.
	rpcClient, err := client.Client()
	if err != nil {
		cancel()
		client.Kill()
		return fmt.Errorf("plugin %q handshake failed: %w", name, err)
	}

	// Dispense the ScopeValidatorService to verify connectivity and obtain
	// the Kind the plugin handles.
	raw, err := rpcClient.Dispense("scope_validator")
	if err != nil {
		cancel()
		client.Kill()
		return fmt.Errorf("plugin %q: dispense scope_validator: %w", name, err)
	}

	// The dispensed value is a *ScopeValidatorGRPC adapter.
	adapter, ok := raw.(*ScopeValidatorGRPC)
	if !ok {
		cancel()
		client.Kill()
		return fmt.Errorf("plugin %q: dispensed value is %T, want *ScopeValidatorGRPC", name, raw)
	}

	// Ask the plugin what Kind it handles.
	kindResp, err := adapter.client.Kind(ctx, &pluginv1.KindRequest{})
	if err != nil {
		cancel()
		client.Kill()
		return fmt.Errorf("plugin %q: Kind() RPC failed: %w", name, err)
	}
	adapter.kind = kindResp.Kind

	// Register the adapter in the registry (if configured).
	if h.registry != nil && adapter.kind != "" {
		// Best-effort: ignore duplicate registration (plugin may have been
		// registered by a prior Start call that was followed by a crash-restart).
		_ = h.registry.Register(adapter.kind, adapter)
	}

	// Store the running client.
	entry := &pluginEntry{client: client, cancel: cancel}
	h.mu.Lock()
	h.clients[name] = entry
	h.mu.Unlock()

	// Start background health checker.
	go h.healthLoop(name, entry)

	return nil
}

// Stop gracefully shuts down a running plugin subprocess.
func (h *Host) Stop(name string) error {
	h.mu.Lock()
	entry, ok := h.clients[name]
	if ok {
		delete(h.clients, name)
	}
	h.mu.Unlock()

	if !ok {
		return nil
	}
	entry.cancel()
	entry.client.Kill()
	return nil
}

// StopAll gracefully shuts down all running plugin subprocesses.
func (h *Host) StopAll() {
	h.mu.Lock()
	entries := make(map[string]*pluginEntry, len(h.clients))
	for k, v := range h.clients {
		entries[k] = v
	}
	h.clients = make(map[string]*pluginEntry)
	h.mu.Unlock()

	for _, entry := range entries {
		entry.cancel()
		entry.client.Kill()
	}
}

// IsRunning returns true if the named plugin subprocess is alive.
func (h *Host) IsRunning(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	entry, ok := h.clients[name]
	if !ok {
		return false
	}
	return !entry.client.Exited()
}

// List returns metadata for all discovered plugins.
func (h *Host) List() []PluginMeta { return h.plugins }

// ── Internal helpers ───────────────────────────────────────────────────────────

// pluginCommand returns an *exec.Cmd for the given plugin binary path.
func pluginCommand(path string) *exec.Cmd {
	return exec.Command(path) //nolint:gosec // path is validated by Discover + verifier
}

// newPluginLogger returns a silent go-hclog logger for use in plugin clients.
// Plugin subprocess stderr is discarded to keep test output clean. In production
// a caller should configure a real logger via NewClient options.
func newPluginLogger(name string) hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Name:   fmt.Sprintf("plugin.%s", name),
		Level:  hclog.Error,
		Output: hclog.DefaultOutput,
	})
}

// findPluginPath resolves the filesystem path for a plugin name from the
// most recent Discover() result.
func (h *Host) findPluginPath(name string) (string, error) {
	for _, p := range h.plugins {
		if p.Name == name {
			return p.Path, nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrNotDiscovered, name)
}

// healthLoop runs in a goroutine and pings the plugin at healthCheckInterval.
// On ping failure it attempts one restart. On second failure the entry is removed.
// The loop exits when the context associated with the entry is cancelled (i.e. Stop
// or StopAll was called).
func (h *Host) healthLoop(name string, entry *pluginEntry) {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Check if Stop/StopAll removed our entry.
		h.mu.Lock()
		_, stillOurs := h.clients[name]
		h.mu.Unlock()
		if !stillOurs {
			return
		}

		// Check if the subprocess exited on its own.
		if entry.client.Exited() {
			log.Printf("[plugin] %q exited unexpectedly — attempting restart", name)
			if err := h.attemptRestart(name); err != nil {
				log.Printf("[plugin] %q restart failed: %v — marking failed", name, err)
				h.mu.Lock()
				delete(h.clients, name)
				h.mu.Unlock()
			}
			return // The restarted Start() launches a new healthLoop goroutine.
		}

		// Ping the running subprocess.
		rpcClient, err := entry.client.Client()
		if err != nil || rpcClient.Ping() != nil {
			log.Printf("[plugin] %q health check failed — attempting restart", name)
			entry.client.Kill()
			if err := h.attemptRestart(name); err != nil {
				log.Printf("[plugin] %q restart failed: %v — marking failed", name, err)
				h.mu.Lock()
				delete(h.clients, name)
				h.mu.Unlock()
			}
			return
		}
	}
}

// attemptRestart tries to restart a plugin that has exited or failed pings.
func (h *Host) attemptRestart(name string) error {
	return h.Start(name)
}
