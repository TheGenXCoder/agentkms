package plugin

// plugins.go — go-plugin HandshakeConfig, PluginMap, and PluginSet definitions.
//
// Python plugin compatibility:
// The Python reference plugin in examples/plugins/python-honeytoken-validator
// uses the go-plugin protocol. The exact HandshakeConfig values below must match
// what the Python plugin binary reads from its environment:
//
//	HandshakeConfig{
//	    ProtocolVersion:  1,
//	    MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
//	    MagicCookieValue: "agentkms_plugin_v1",
//	}
//
// The Python plugin:
//   - Expects env var PLUGIN_MAGIC_COOKIE=agentkms_plugin_v1
//   - Prints the address line: 1|1|tcp|127.0.0.1:{port}|grpc
//   - Fields: core_protocol|app_protocol|network|address|transport
//
// Once Host.Start() is implemented, any Python plugin built from the reference
// will connect with zero code changes on the Python side.

import (
	"context"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// HandshakeConfig is shared between the host and all plugin binaries.
// All plugin implementations (Go, Python, Rust, etc.) must use these exact values.
//
// Python plugin README specifies:
//   - MagicCookieKey:   "PLUGIN_MAGIC_COOKIE"
//   - MagicCookieValue: "agentkms_plugin_v1"
//   - ProtocolVersion:  1
var HandshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "agentkms_plugin_v1",
}

// PluginMap is the plugin set that the host can speak. Each entry maps a
// service name to its GRPCPlugin implementation. On the host side only
// GRPCClient is called; GRPCServer is called by plugin binaries only.
//
// For v0.3.1 the host only auto-registers ScopeValidator on Start(). The other
// three services can be registered manually via the appropriate Register* methods
// once capability negotiation (v0.3.2 .manifest files) is implemented.
var PluginMap = map[string]goplugin.Plugin{
	"scope_validator":        &ScopeValidatorPlugin{},
	"scope_analyzer":         &ScopeAnalyzerPlugin{},
	"scope_serializer":       &ScopeSerializerPlugin{},
	"credential_vender":      &CredentialVenderPlugin{},
	"destination_deliverer":  &DestinationDelivererPlugin{},
	"rotation_orchestrator":  &OrchestratorPlugin{},
}

// OrchestratorPlugin implements goplugin.GRPCPlugin for the OrchestratorService.
// On the host side GRPCClient wraps the OrchestratorServiceClient.
// On the plugin side GRPCServer registers the OrchestratorService implementation.
// This plugin entry is used ONLY by the Pro rotation orchestrator binary.
type OrchestratorPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	// Impl is only set on the plugin (server) side.
	Impl pluginv1.OrchestratorServiceServer
}

func (p *OrchestratorPlugin) GRPCServer(broker *goplugin.GRPCBroker, s *grpc.Server) error {
	if p.Impl == nil {
		return nil // host side: no server impl needed
	}
	pluginv1.RegisterOrchestratorServiceServer(s, p.Impl)
	return nil
}

func (p *OrchestratorPlugin) GRPCClient(ctx context.Context, broker *goplugin.GRPCBroker, cc *grpc.ClientConn) (interface{}, error) {
	return &OrchestratorGRPC{
		client: pluginv1.NewOrchestratorServiceClient(cc),
		broker: broker,
	}, nil
}

// OrchestratorGRPC wraps the generated gRPC client for the OrchestratorService.
// The host calls Init (passing the HostService broker ID) and then uses
// TriggerRotation / BindingForCredential to implement webhooks.RotationHook.
type OrchestratorGRPC struct {
	client pluginv1.OrchestratorServiceClient
	broker *goplugin.GRPCBroker
}
