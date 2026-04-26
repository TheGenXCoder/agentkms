package plugin

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/credentials/binding"
	"github.com/agentkms/agentkms/internal/destination"
	"github.com/agentkms/agentkms/internal/webhooks"
	hclog "github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
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
// HostServiceDeps bundles the OSS-internal dependencies needed to serve the
// HostService callback to the Pro rotation orchestrator plugin.
// If HostServiceDeps is nil when StartOrchestrator is called, the host creates
// a degraded HostService that returns HOST_PERMANENT on all calls requiring
// internal state — this is the graceful degradation path for test environments.
type HostServiceDeps struct {
	Store   binding.BindingStore
	Auditor audit.Auditor
	KV      credentials.KVWriter
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

	// hostServiceDeps is set via SetHostServiceDeps before calling StartOrchestrator.
	// Used to construct the HostService server for the rotation orchestrator plugin.
	hostServiceDeps *HostServiceDeps

	mu      sync.Mutex
	clients map[string]*pluginEntry // keyed by plugin name
}

// SetHostServiceDeps provides the OSS-internal dependencies needed to serve the
// HostService callback to the Pro rotation orchestrator plugin. Must be called
// before StartOrchestrator.
func (h *Host) SetHostServiceDeps(deps *HostServiceDeps) {
	h.hostServiceDeps = deps
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

	// Negotiate capabilities. Plugins that predate this RPC return Unimplemented;
	// treat that as an empty capability set (backwards compatible).
	capsResp, err := adapter.client.Capabilities(ctx, &pluginv1.CapabilitiesRequest{})
	if err != nil {
		log.Printf("[plugin] %q: Capabilities() RPC failed (assuming legacy plugin, no capabilities): %v", name, err)
		adapter.capabilities = nil
	} else {
		adapter.capabilities = capsResp.GetCapabilities()
	}

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

// ── Destination plugin startup ─────────────────────────────────────────────────

// StartDestination launches a destination plugin subprocess, performs the
// capability handshake (Kind → Capabilities → Validate), and registers the
// adapter in the registry under the plugin's declared kind.
//
// The plugin binary must have been found by a prior Discover() call and must
// implement DestinationDelivererService via the shared HandshakeConfig.
//
// Start is idempotent for the same name: if the subprocess is already running,
// this is a no-op.
func (h *Host) StartDestination(name string) error {
	pluginPath, err := h.findPluginPath(name)
	if err != nil {
		return err
	}

	h.mu.Lock()
	if entry, ok := h.clients[name]; ok {
		if !entry.client.Exited() {
			h.mu.Unlock()
			return nil // already running
		}
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

	ctx, cancel := context.WithCancel(context.Background())
	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig:  HandshakeConfig,
		Plugins:          PluginMap,
		Cmd:              pluginCommand(pluginPath),
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		Logger:           newPluginLogger(name),
		StartTimeout:     30 * time.Second,
	})

	rpcClient, err := client.Client()
	if err != nil {
		cancel()
		client.Kill()
		return fmt.Errorf("destination plugin %q handshake failed: %w", name, err)
	}

	raw, err := rpcClient.Dispense("destination_deliverer")
	if err != nil {
		cancel()
		client.Kill()
		return fmt.Errorf("destination plugin %q: dispense destination_deliverer: %w", name, err)
	}

	adapter, ok := raw.(*destination.DestinationDelivererGRPC)
	if !ok {
		cancel()
		client.Kill()
		return fmt.Errorf("destination plugin %q: dispensed value is %T, want *destination.DestinationDelivererGRPC", name, raw)
	}

	// Kind negotiation.
	kindResp, err := adapter.Client().Kind(ctx, &pluginv1.KindRequest{})
	if err != nil {
		cancel()
		client.Kill()
		return fmt.Errorf("destination plugin %q: Kind() RPC failed: %w", name, err)
	}
	adapter.SetKind(kindResp.Kind)

	// Capability negotiation.
	capsResp, err := adapter.Client().Capabilities(ctx, &pluginv1.CapabilitiesRequest{})
	if err != nil {
		log.Printf("[plugin] destination %q: Capabilities() RPC failed (assuming legacy, no capabilities): %v", name, err)
		adapter.SetCapabilities(nil)
	} else {
		adapter.SetCapabilities(capsResp.GetCapabilities())
	}

	// Startup health check via Validate (with nil params as a connectivity probe).
	// Spec §4.2: Validate must complete in under 10 seconds. Use a dedicated
	// timeout context so a hung plugin cannot block server startup indefinitely.
	validateCtx, validateCancel := context.WithTimeout(ctx, 10*time.Second)
	defer validateCancel()
	if err := adapter.Validate(validateCtx, nil); err != nil {
		log.Printf("[plugin] destination %q: startup Validate failed — plugin not registered: %v", name, err)
		cancel()
		client.Kill()
		return fmt.Errorf("destination plugin %q: startup Validate failed: %w", name, err)
	}

	// Register in the deliverer registry.
	if h.registry != nil && adapter.Kind() != "" {
		if err := h.registry.RegisterDeliverer(adapter.Kind(), adapter); err != nil {
			log.Printf("[plugin] destination %q: RegisterDeliverer failed: %v", name, err)
		}
	}

	entry := &pluginEntry{client: client, cancel: cancel}
	h.mu.Lock()
	h.clients[name] = entry
	h.mu.Unlock()

	go h.destinationHealthLoop(name, entry, adapter)

	return nil
}

// destinationHealthErrorThreshold is the number of consecutive Health() RPC
// failures that trigger a restart attempt, matching the provider healthLoop's
// "one failure → restart" threshold (each ping failure is its own trigger).
// For Health() failures we allow one failure before restarting, consistent
// with the provider pattern of "one failure → attempt one restart → if that
// fails, mark failed."
const destinationHealthErrorThreshold = 1

// destinationHealthLoop runs in a goroutine and calls Health() on the
// destination plugin at healthCheckInterval. Mirrors the provider healthLoop
// but calls the destination-specific Health() RPC in addition to the
// protocol-level ping.
//
// Restart semantics mirror the provider healthLoop:
//   - Subprocess exits   → attempt one restart; if restart fails, mark failed.
//   - Protocol ping fails → attempt one restart; if restart fails, mark failed.
//   - Health() RPC fails  → after destinationHealthErrorThreshold consecutive
//     failures, attempt one restart; if restart fails, mark failed.
//
// The adapter parameter accepts any DestinationDeliverer so that tests can
// inject a mock without forking a subprocess.
func (h *Host) destinationHealthLoop(name string, entry *pluginEntry, adapter destination.DestinationDeliverer) {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	healthErrors := 0

	for range ticker.C {
		h.mu.Lock()
		_, stillOurs := h.clients[name]
		h.mu.Unlock()
		if !stillOurs {
			return
		}

		if entry.client.Exited() {
			log.Printf("[plugin] destination %q exited unexpectedly — attempting restart", name)
			if err := h.StartDestination(name); err != nil {
				log.Printf("[plugin] destination %q restart failed: %v — marking failed", name, err)
				h.mu.Lock()
				delete(h.clients, name)
				h.mu.Unlock()
			}
			return
		}

		// Protocol-level ping.
		rpcClient, err := entry.client.Client()
		if err != nil || rpcClient.Ping() != nil {
			log.Printf("[plugin] destination %q protocol ping failed — attempting restart", name)
			entry.client.Kill()
			if err := h.StartDestination(name); err != nil {
				log.Printf("[plugin] destination %q restart failed: %v — marking failed", name, err)
				h.mu.Lock()
				delete(h.clients, name)
				h.mu.Unlock()
			}
			return
		}

		// Destination-level Health RPC.
		healthCtx, healthCancel := context.WithTimeout(context.Background(), 5*time.Second)
		healthErr := adapter.Health(healthCtx)
		healthCancel()
		if healthErr != nil {
			healthErrors++
			log.Printf("[plugin] destination %q Health() failed (error #%d): %v", name, healthErrors, healthErr)

			// After reaching the threshold, attempt one restart — same
			// contract as the provider healthLoop.
			if healthErrors >= destinationHealthErrorThreshold {
				log.Printf("[plugin] destination %q Health() failure threshold reached — attempting restart", name)
				entry.client.Kill()
				if restartErr := h.StartDestination(name); restartErr != nil {
					log.Printf("[plugin] destination %q restart after Health() failure failed: %v — marking failed", name, restartErr)
					h.mu.Lock()
					delete(h.clients, name)
					h.mu.Unlock()
				}
				return
			}
		} else {
			if healthErrors > 0 {
				log.Printf("[plugin] destination %q Health() recovered after %d errors", name, healthErrors)
			}
			healthErrors = 0
		}
	}
}

// ── Orchestrator plugin startup ───────────────────────────────────────────────

// StartOrchestrator launches the Pro rotation orchestrator plugin subprocess.
// It sets up the GRPCBroker HostService side channel, passes the broker ID to
// the plugin via the Init RPC, and returns the OrchestratorGRPC adapter that
// the host can use as a webhooks.RotationHook.
//
// Fail-fast design (HC-5): if the HostService broker cannot be established or
// the plugin's Init fails, StartOrchestrator returns an error immediately.
// The host does NOT register a RotationHook and OSS webhook handling falls back
// to its existing revoker-only path.
//
// Startup race (HC-6): the ~1s window between OSS host start and this method
// returning is accepted. If a webhook arrives before the RotationHook is
// registered, the OSS AlertOrchestrator falls back gracefully.
func (h *Host) StartOrchestrator(name string) (*OrchestratorGRPC, error) {
	pluginPath, err := h.findPluginPath(name)
	if err != nil {
		return nil, err
	}

	h.mu.Lock()
	if entry, ok := h.clients[name]; ok {
		if !entry.client.Exited() {
			h.mu.Unlock()
			return nil, fmt.Errorf("orchestrator plugin %q is already running", name)
		}
		entry.cancel()
		delete(h.clients, name)
	}
	h.mu.Unlock()

	// Signature verification before subprocess launch.
	if h.verifier != nil {
		sigPath := pluginPath + ".sig"
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot read .sig sidecar %q: %v", ErrUntrustedPlugin, sigPath, err)
		}
		if err := h.verifier.Verify(pluginPath, sig); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUntrustedPlugin, err)
		}
	} else {
		log.Printf("[plugin] WARNING: no verifier configured for orchestrator %q — running unsigned binary", name)
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig:  HandshakeConfig,
		Plugins:          PluginMap,
		Cmd:              pluginCommand(pluginPath),
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		Logger:           newPluginLogger(name),
		StartTimeout:     30 * time.Second,
		GRPCBrokerMultiplex: true, // required for broker side channels
	})

	rpcClient, err := client.Client()
	if err != nil {
		cancel()
		client.Kill()
		return nil, fmt.Errorf("orchestrator plugin %q handshake failed: %w", name, err)
	}

	raw, err := rpcClient.Dispense("rotation_orchestrator")
	if err != nil {
		cancel()
		client.Kill()
		return nil, fmt.Errorf("orchestrator plugin %q: dispense rotation_orchestrator: %w", name, err)
	}

	orchestrator, ok := raw.(*OrchestratorGRPC)
	if !ok {
		cancel()
		client.Kill()
		return nil, fmt.Errorf("orchestrator plugin %q: dispensed value is %T, want *OrchestratorGRPC", name, raw)
	}

	// Set up the HostService gRPC broker side channel.
	// The host allocates a broker ID, launches AcceptAndServe in a goroutine,
	// then passes the broker ID to the plugin via Init.
	var hsSrv *hostServiceServer
	if deps := h.hostServiceDeps; deps != nil {
		hsSrv = newHostServiceServer(deps.Store, h.registry, deps.Auditor, deps.KV)
	} else {
		log.Printf("[plugin] WARNING: HostServiceDeps not configured — orchestrator plugin %q will have degraded access", name)
		hsSrv = &hostServiceServer{} // empty server returns HOST_PERMANENT on all calls
	}

	broker := orchestrator.broker
	brokerID := broker.NextId()
	go broker.AcceptAndServe(brokerID, func(opts []grpc.ServerOption) *grpc.Server {
		srv := grpc.NewServer(opts...)
		pluginv1.RegisterHostServiceServer(srv, hsSrv)
		return srv
	})

	// Call Init on the orchestrator plugin with the broker ID (fail-fast).
	initCtx, initCancel := context.WithTimeout(ctx, 30*time.Second)
	defer initCancel()
	resp, err := orchestrator.client.Init(initCtx, &pluginv1.OrchestratorInitRequest{
		HostBrokerId: brokerID,
	})
	if err != nil {
		cancel()
		client.Kill()
		return nil, fmt.Errorf("orchestrator plugin %q: Init RPC failed: %w", name, err)
	}
	if msg := resp.GetErrorMessage(); msg != "" {
		cancel()
		client.Kill()
		return nil, fmt.Errorf("orchestrator plugin %q: Init failed: %s", name, msg)
	}

	// Store the running client.
	entry := &pluginEntry{client: client, cancel: cancel}
	h.mu.Lock()
	h.clients[name] = entry
	h.mu.Unlock()

	log.Printf("[plugin] orchestrator %q started successfully", name)
	return orchestrator, nil
}

// RotationHookFor returns a webhooks.RotationHook adapter that wraps the
// OrchestratorGRPC client. The adapter translates the Go interface calls
// (TriggerRotation, BindingForCredential) to OrchestratorService gRPC RPCs.
//
// This is used by the host after StartOrchestrator succeeds to register the
// Pro orchestrator as the RotationHook with the OSS AlertOrchestrator.
func (h *Host) RotationHookFor(orchestrator *OrchestratorGRPC) webhooks.RotationHook {
	return &orchestratorRotationHook{client: orchestrator}
}

// orchestratorRotationHook implements webhooks.RotationHook by calling the
// OrchestratorService gRPC client. It is used by the OSS AlertOrchestrator
// to delegate emergency rotations to the Pro plugin without knowing about Pro.
type orchestratorRotationHook struct {
	client *OrchestratorGRPC
}

func (h *orchestratorRotationHook) TriggerRotation(ctx context.Context, credentialUUID string) error {
	resp, err := h.client.client.TriggerRotation(ctx, &pluginv1.TriggerRotationRequest{
		CredentialUuid: credentialUUID,
	})
	if err != nil {
		return fmt.Errorf("orchestrator TriggerRotation RPC: %w", err)
	}
	if msg := resp.GetErrorMessage(); msg != "" {
		return fmt.Errorf("orchestrator TriggerRotation: %s", msg)
	}
	return nil
}

func (h *orchestratorRotationHook) BindingForCredential(ctx context.Context, credentialUUID string) (string, error) {
	resp, err := h.client.client.BindingForCredential(ctx, &pluginv1.BindingForCredentialRequest{
		CredentialUuid: credentialUUID,
	})
	if err != nil {
		return "", fmt.Errorf("orchestrator BindingForCredential RPC: %w", err)
	}
	if msg := resp.GetErrorMessage(); msg != "" {
		return "", fmt.Errorf("orchestrator BindingForCredential: %s", msg)
	}
	if resp.GetNotFound() {
		return "", webhooks.ErrNoBinding
	}
	return resp.GetBindingName(), nil
}

// orchestratorHealthLoop is similar to destinationHealthLoop but for the orchestrator.
// For now it uses basic process liveness — the orchestrator doesn't expose a Health RPC.
func (h *Host) orchestratorHealthLoop(name string, entry *pluginEntry) {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		h.mu.Lock()
		_, stillOurs := h.clients[name]
		h.mu.Unlock()
		if !stillOurs {
			return
		}

		if entry.client.Exited() {
			log.Printf("[plugin] orchestrator %q exited unexpectedly", name)
			// Do not attempt automatic restart for the orchestrator —
			// the host operator should restart the whole server or investigate.
			h.mu.Lock()
			delete(h.clients, name)
			h.mu.Unlock()
			return
		}

		rpcClient, err := entry.client.Client()
		if err != nil || rpcClient.Ping() != nil {
			log.Printf("[plugin] orchestrator %q protocol ping failed", name)
			entry.client.Kill()
			h.mu.Lock()
			delete(h.clients, name)
			h.mu.Unlock()
			return
		}
	}
}

// noopListener is a do-nothing net.Listener used to satisfy the broker API signature.
type noopListener struct{}
func (noopListener) Accept() (net.Conn, error)  { return nil, fmt.Errorf("noop listener") }
func (noopListener) Close() error                { return nil }
func (noopListener) Addr() net.Addr              { return &net.TCPAddr{} }

