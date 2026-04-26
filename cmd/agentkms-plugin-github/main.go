// agentkms-plugin-github is the OSS GitHub App credential vender plugin for AgentKMS.
//
// It implements the CredentialVenderService gRPC service (defined in
// api/plugin/v1/plugin.proto) and is loaded by the AgentKMS host as a
// hashicorp/go-plugin subprocess under the PluginMap key "credential_vender".
//
// The plugin supports N GitHub Apps registered by name. Apps are configured
// from a YAML file at startup; the app_name field in a Scope.Params selects
// which App to use when vending.
//
// Configuration:
//
//	AGENTKMS_GITHUB_APPS_CONFIG — path to the apps config YAML file.
//	Default: ~/.agentkms/plugins/github-apps.yaml
//
// Config file schema (YAML):
//
//	apps:
//	  - app_name: blog-audit
//	    private_key_path: /tmp/blog-audit-app.pem
//	    app_id: 1234567
//	    installation_id: 127321567
//
// If the config file is missing or has zero apps, the plugin starts with an
// empty registry (all Vend calls return NotFound until apps are registered).
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
	"log"
	"os"
	"path/filepath"
	"time"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/dynsecrets/github"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

// defaultConfigPath is the fallback config location when AGENTKMS_GITHUB_APPS_CONFIG is unset.
var defaultConfigPath = filepath.Join(os.Getenv("HOME"), ".agentkms", "plugins", "github-apps.yaml")

// appsConfig is the YAML schema for the apps configuration file.
type appsConfig struct {
	Apps []appEntry `yaml:"apps"`
}

// appEntry describes a single GitHub App in the config file.
type appEntry struct {
	AppName        string `yaml:"app_name"`
	PrivateKeyPath string `yaml:"private_key_path"`
	AppID          int64  `yaml:"app_id"`
	InstallationID int64  `yaml:"installation_id"`
}

// githubVenderServer adapts github.Plugin to the gRPC CredentialVenderServiceServer interface.
type githubVenderServer struct {
	pluginv1.UnimplementedCredentialVenderServiceServer
	plugin *github.Plugin
}

// newGithubVenderServer builds the server, reads the config file, and registers
// all configured Apps. Missing config file is non-fatal (logs a warning).
func newGithubVenderServer() *githubVenderServer {
	p := github.NewMulti()

	configPath := os.Getenv("AGENTKMS_GITHUB_APPS_CONFIG")
	if configPath == "" {
		configPath = defaultConfigPath
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[github-plugin] WARN: config file not found at %q; starting with zero apps. Set AGENTKMS_GITHUB_APPS_CONFIG or create the file. All Vend calls will fail until apps are registered.", configPath)
		} else {
			log.Printf("[github-plugin] WARN: cannot read config file %q: %v; starting with zero apps.", configPath, err)
		}
		return &githubVenderServer{plugin: p}
	}

	var cfg appsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Printf("[github-plugin] WARN: cannot parse config file %q: %v; starting with zero apps.", configPath, err)
		return &githubVenderServer{plugin: p}
	}

	for _, entry := range cfg.Apps {
		if entry.AppName == "" {
			log.Printf("[github-plugin] WARN: skipping app entry with empty app_name")
			continue
		}
		if entry.PrivateKeyPath == "" {
			log.Printf("[github-plugin] WARN: skipping app %q: private_key_path is empty", entry.AppName)
			continue
		}
		keyPEM, err := os.ReadFile(entry.PrivateKeyPath)
		if err != nil {
			log.Printf("[github-plugin] WARN: skipping app %q: cannot read private_key_path %q: %v", entry.AppName, entry.PrivateKeyPath, err)
			continue
		}
		if err := p.RegisterApp(entry.AppName, entry.AppID, entry.InstallationID, keyPEM); err != nil {
			log.Printf("[github-plugin] WARN: skipping app %q: RegisterApp failed: %v", entry.AppName, err)
			continue
		}
		log.Printf("[github-plugin] registered app %q (app_id=%d installation_id=%d)", entry.AppName, entry.AppID, entry.InstallationID)
	}

	apps := p.ListApps()
	log.Printf("[github-plugin] startup complete: %d app(s) registered", len(apps))

	return &githubVenderServer{plugin: p}
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

func (s *githubVenderServer) Vend(ctx context.Context, req *pluginv1.VendRequest) (*pluginv1.VendResponse, error) {
	scope := protoToScope(req.GetScope()) // returns credentials.Scope

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
type githubVenderPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	impl *githubVenderServer
}

func (p *githubVenderPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
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
// Plugin binaries can't import from internal/plugin (would be a circular dep
// and internal is not exported to cmd anyway), so we duplicate the minimal
// subset needed here.

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
