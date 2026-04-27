// agentkms-plugin-github is the OSS GitHub App credential vender plugin for AgentKMS.
//
// It implements the CredentialVenderService gRPC service (defined in
// api/plugin/v1/plugin.proto) and is loaded by the AgentKMS host as a
// hashicorp/go-plugin subprocess under the PluginMap key "credential_vender".
//
// The plugin supports N GitHub Apps registered by name. Apps are configured
// at runtime via the HostService.GetGithubApp RPC (UX-B), fetched lazily on
// first vend per app_name and cached for 5 minutes. The private key PEM is
// NEVER written to the filesystem.
//
// app_name selection:
//
//	The app_name field in the Scope.Params map selects which registered App to
//	use when vending. Example: {"app_name": "agentkms-blog-audit-rotator"}.
//
// Migration from legacy github-apps.yaml:
//
//	If AGENTKMS_GITHUB_APPS_CONFIG is set or ~/.agentkms/plugins/github-apps.yaml
//	exists, the plugin logs a deprecation warning and ignores the file.
//	Register Apps via 'kpm gh-app register' instead.
//
// HandshakeConfig matches the OSS host (internal/plugin/plugins.go):
//
//	ProtocolVersion:  1
//	MagicCookieKey:   "PLUGIN_MAGIC_COOKIE"
//	MagicCookieValue: "agentkms_plugin_v1"
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/dynsecrets/github"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// cacheTTL is how long a fetched App config stays valid before the plugin
// re-fetches from the HostService.
const cacheTTL = 5 * time.Minute

// cachedApp records the time an App was last fetched.
// We don't store the config here because RegisterApp puts it in the plugin.
type cachedApp struct {
	fetchedAt time.Time
}

// githubVenderServer adapts github.Plugin to the gRPC CredentialVenderServiceServer interface.
// Apps are loaded lazily from the HostService and cached with a 5-minute TTL.
type githubVenderServer struct {
	pluginv1.UnimplementedCredentialVenderServiceServer

	plugin *github.Plugin

	// hostClient is the HostService gRPC client, available after InitProvider.
	hostMu         sync.RWMutex
	hostClient     pluginv1.HostServiceClient
	hostConn       *grpc.ClientConn                     // kept to close on shutdown
	brokerDialFunc func(uint32) (*grpc.ClientConn, error) // set by GRPCServer

	// cache maps app_name → last fetch time (plugin.RegisterApp holds the config).
	cacheMu sync.RWMutex
	cache   map[string]*cachedApp
}

func newGithubVenderServer() *githubVenderServer {
	// Warn if the legacy config file is present but do NOT read it.
	legacyPath := os.Getenv("AGENTKMS_GITHUB_APPS_CONFIG")
	if legacyPath == "" {
		legacyPath = filepath.Join(os.Getenv("HOME"), ".agentkms", "plugins", "github-apps.yaml")
	}
	if _, err := os.Stat(legacyPath); err == nil {
		log.Printf("[github-plugin] DEPRECATED: found legacy config file %q — it is ignored in this release. "+
			"Register GitHub Apps via 'kpm gh-app register' instead.", legacyPath)
	}

	return &githubVenderServer{
		plugin: github.NewMulti(),
		cache:  make(map[string]*cachedApp),
	}
}

// InitProvider is called by the host after startup to hand the HostService
// GRPCBroker ID to the plugin. The plugin dials the broker and stores the
// HostServiceClient for lazy App fetching.
func (s *githubVenderServer) InitProvider(_ context.Context, req *pluginv1.InitProviderRequest) (*pluginv1.InitProviderResponse, error) {
	brokerID := req.GetHostBrokerId()
	if brokerID == 0 {
		// Pre-UX-B host: no broker available. All Vend calls will fail with NotFound.
		log.Printf("[github-plugin] InitProvider: host_broker_id=0 — no HostService available; all Vend calls will fail until Apps are registered server-side")
		return &pluginv1.InitProviderResponse{}, nil
	}

	// The broker is provided by the go-plugin framework through GRPCServer's broker
	// parameter. We store it during GRPCServer and use it here to dial back.
	s.hostMu.Lock()
	defer s.hostMu.Unlock()

	if s.hostConn != nil {
		// Already initialised (e.g. on restart). Re-dial is fine.
		_ = s.hostConn.Close()
		s.hostConn = nil
		s.hostClient = nil
	}

	// brokerDialFunc is set during GRPCServer by the plugin framework.
	if s.brokerDialFunc == nil {
		return &pluginv1.InitProviderResponse{
			ErrorMessage: "InitProvider called before GRPCServer: broker not available",
		}, nil
	}

	conn, err := s.brokerDialFunc(brokerID)
	if err != nil {
		return &pluginv1.InitProviderResponse{
			ErrorMessage: fmt.Sprintf("broker.Dial(%d): %v", brokerID, err),
		}, nil
	}

	s.hostConn = conn
	s.hostClient = pluginv1.NewHostServiceClient(conn)
	log.Printf("[github-plugin] InitProvider: connected to HostService (broker_id=%d)", brokerID)
	return &pluginv1.InitProviderResponse{}, nil
}

// setBrokerDial sets the broker dial function captured from GRPCServer.
// Called once at plugin startup before InitProvider is invoked.
func (s *githubVenderServer) setBrokerDial(fn func(uint32) (*grpc.ClientConn, error)) {
	s.hostMu.Lock()
	s.brokerDialFunc = fn
	s.hostMu.Unlock()
}

func (s *githubVenderServer) Kind(_ context.Context, _ *pluginv1.KindRequest) (*pluginv1.KindResponse, error) {
	return &pluginv1.KindResponse{Kind: s.plugin.Kind()}, nil
}

func (s *githubVenderServer) Capabilities(_ context.Context, _ *pluginv1.CapabilitiesRequest) (*pluginv1.CapabilitiesResponse, error) {
	return &pluginv1.CapabilitiesResponse{
		Capabilities:     []string{"health"},
		ApiVersion:       1,
		ApiVersionCompat: ">=1",
	}, nil
}

// ensureApp fetches and caches an App from the HostService, with a 5-minute TTL.
// On cache hit within TTL, the already-registered plugin entry is used.
// On cache miss or TTL expiry, re-fetches from HostService and re-registers.
func (s *githubVenderServer) ensureApp(ctx context.Context, appName string) error {
	// Check cache first.
	s.cacheMu.RLock()
	entry, ok := s.cache[appName]
	s.cacheMu.RUnlock()
	if ok && time.Since(entry.fetchedAt) < cacheTTL {
		return nil // still fresh
	}

	// Cache miss or TTL expired — fetch from HostService.
	s.hostMu.RLock()
	hc := s.hostClient
	s.hostMu.RUnlock()

	if hc == nil {
		// If the App is already registered in the plugin (from a previous fetch
		// before the connection was lost), we can still vend — just log a warning.
		s.cacheMu.RLock()
		_, cached := s.cache[appName]
		s.cacheMu.RUnlock()
		if cached {
			log.Printf("[github-plugin] WARN: HostService not available; using stale cached config for app %q", appName)
			return nil
		}
		return fmt.Errorf("HostService not available (InitProvider not called or failed); cannot fetch app %q", appName)
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := hc.GetGithubApp(fetchCtx, &pluginv1.GetGithubAppRequest{Name: appName})
	if err != nil {
		return fmt.Errorf("GetGithubApp RPC for %q: %w", appName, err)
	}
	if resp.GetErrorCode() != pluginv1.HostCallbackErrorCode_HOST_OK {
		return fmt.Errorf("GetGithubApp %q: %s (code=%v)", appName, resp.GetErrorMessage(), resp.GetErrorCode())
	}

	// Re-register (idempotent; existing clients are replaced with fresh config).
	if err := s.plugin.RegisterApp(appName, resp.GetAppId(), resp.GetInstallationId(), resp.GetPrivateKeyPem()); err != nil {
		log.Printf("[github-plugin] RegisterApp %q: %v (may be duplicate — continuing)", appName, err)
	}

	// Update cache.
	s.cacheMu.Lock()
	s.cache[appName] = &cachedApp{fetchedAt: time.Now()}
	s.cacheMu.Unlock()

	log.Printf("[github-plugin] fetched App %q from HostService (app_id=%d installation_id=%d)",
		appName, resp.GetAppId(), resp.GetInstallationId())
	return nil
}

func (s *githubVenderServer) Vend(ctx context.Context, req *pluginv1.VendRequest) (*pluginv1.VendResponse, error) {
	scope := protoToScope(req.GetScope())

	// Extract app_name from scope params. If not present, fall back to default.
	appName, _ := scope.Params["app_name"].(string)
	if appName == "" {
		return &pluginv1.VendResponse{Error: "scope.params.app_name is required for github-app-token provider"}, nil
	}

	// Ensure the App is registered (lazy fetch with cache).
	if err := s.ensureApp(ctx, appName); err != nil {
		return &pluginv1.VendResponse{Error: err.Error()}, nil
	}

	cred, err := s.plugin.Vend(ctx, scope)
	if err != nil {
		return &pluginv1.VendResponse{Error: err.Error()}, nil
	}

	hash := sha256.Sum256(cred.APIKey)
	hashHex := hex.EncodeToString(hash[:])

	return &pluginv1.VendResponse{
		Credential: &pluginv1.VendedCredential{
			ApiKey:            cred.APIKey,
			Uuid:              cred.UUID,
			ProviderTokenHash: hashHex,
			ExpiresAt:         timestamppb.New(cred.ExpiresAt),
		},
	}, nil
}

// githubVenderPlugin wires the gRPC server on the plugin side.
// It captures the broker so that InitProvider can dial back to the HostService.
type githubVenderPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	impl *githubVenderServer
}

func (p *githubVenderPlugin) GRPCServer(broker *goplugin.GRPCBroker, s *grpc.Server) error {
	// Set the broker dial function so InitProvider can use it.
	p.impl.setBrokerDial(func(id uint32) (*grpc.ClientConn, error) {
		return broker.Dial(id)
	})
	pluginv1.RegisterCredentialVenderServiceServer(s, p.impl)
	return nil
}

func (p *githubVenderPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, _ *grpc.ClientConn) (interface{}, error) {
	panic("GRPCClient called on server-side plugin binary")
}

// handshakeConfig must match the host exactly (internal/plugin/plugins.go).
var handshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "agentkms_plugin_v1",
}

func main() {
	impl := newGithubVenderServer()
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins: goplugin.PluginSet{
			"credential_vender": &githubVenderPlugin{impl: impl},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}

// ── proto conversion helpers ──────────────────────────────────────────────────
// These mirror the unexported helpers in internal/plugin/convert.go.

func protoToScope(p *pluginv1.Scope) credentials.Scope {
	if p == nil {
		return credentials.Scope{}
	}
	ttl := time.Duration(p.GetTtlSeconds()) * time.Second
	return credentials.Scope{
		Kind:   p.GetKind(),
		Params: structToMap(p.GetParams()),
		TTL:    ttl,
	}
}

func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	m := make(map[string]any, len(s.GetFields()))
	for k, v := range s.GetFields() {
		m[k] = v.AsInterface()
	}
	return m
}

// ── stub for pre-UX-B hosts ───────────────────────────────────────────────────

// Ensure InitProvider returns Unimplemented on hosts that call it via the
// UnimplementedCredentialVenderServiceServer base. The real implementation
// above overrides it.
var _ = status.Error(codes.Unimplemented, "")
