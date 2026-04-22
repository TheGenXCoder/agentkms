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
	goplugin "github.com/hashicorp/go-plugin"
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
	"scope_validator":   &ScopeValidatorPlugin{},
	"scope_analyzer":    &ScopeAnalyzerPlugin{},
	"scope_serializer":  &ScopeSerializerPlugin{},
	"credential_vender": &CredentialVenderPlugin{},
}
