// Stub plugin binary for AgentKMS integration tests.
//
// Implements ScopeValidatorService for Kind="test-stub" using the
// hashicorp/go-plugin gRPC transport and the PLUGIN_MAGIC_COOKIE / agentkms_plugin_v1
// magic cookie protocol.
//
// Build this binary before running the subprocess or integration tests:
//
//	go build -o internal/plugin/testdata/stub-validator/agentkms-plugin-test-stub \
//	    ./internal/plugin/testdata/stub-validator/
//
// The binary reports Kind="test-stub". Validate() always returns success (empty error).
// Narrow() passes the requested scope through unchanged.
package main

import (
	"context"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// stubValidator implements ScopeValidatorServiceServer for Kind="test-stub".
// All validation passes — this is a test fixture, not a production validator.
type stubValidator struct {
	pluginv1.UnimplementedScopeValidatorServiceServer
}

func (s *stubValidator) Kind(_ context.Context, _ *pluginv1.KindRequest) (*pluginv1.KindResponse, error) {
	return &pluginv1.KindResponse{Kind: "test-stub"}, nil
}

func (s *stubValidator) Validate(_ context.Context, _ *pluginv1.ValidateRequest) (*pluginv1.ValidateResponse, error) {
	// Always valid — test fixture.
	return &pluginv1.ValidateResponse{}, nil
}

func (s *stubValidator) Narrow(_ context.Context, req *pluginv1.NarrowRequest) (*pluginv1.NarrowResponse, error) {
	// Pass through unchanged.
	return &pluginv1.NarrowResponse{NarrowedScope: req.Requested}, nil
}

// stubValidatorPlugin wires the gRPC server on the plugin side.
type stubValidatorPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
}

func (p *stubValidatorPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterScopeValidatorServiceServer(s, &stubValidator{})
	return nil
}

func (p *stubValidatorPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, _ *grpc.ClientConn) (interface{}, error) {
	panic("GRPCClient called on server-side plugin binary")
}

// HandshakeConfig must match the host exactly.
// Python plugin README documents: PLUGIN_MAGIC_COOKIE=agentkms_plugin_v1
var handshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "agentkms_plugin_v1",
}

func main() {
	// Wire encoding is standard protobuf binary (proto3).
	// hashicorp/go-plugin uses DefaultGRPCServer which registers the default
	// protobuf codec — no custom codec registration needed.
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins: goplugin.PluginSet{
			"scope_validator": &stubValidatorPlugin{},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
