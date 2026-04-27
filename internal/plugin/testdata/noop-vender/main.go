// Stub credential-vender plugin binary for AgentKMS integration tests.
//
// Implements CredentialVenderService for Kind="noop-vender" using the
// hashicorp/go-plugin gRPC transport and the agentkms_plugin_v1 magic cookie.
//
// Build this binary before running provider subprocess or integration tests:
//
//	go build -o internal/plugin/testdata/noop-vender/agentkms-plugin-noop-vender \
//	    ./internal/plugin/testdata/noop-vender/
//
// The binary reports:
//   - Kind = "noop-vender"
//   - Capabilities = ["health"]
//   - Vend always returns a synthetic VendedCredential with APIKey = "noop-api-key"
package main

import (
	"context"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

// noopVenderServer implements CredentialVenderServiceServer.
// All operations succeed — this is a test fixture, not a production plugin.
type noopVenderServer struct {
	pluginv1.UnimplementedCredentialVenderServiceServer
}

func (s *noopVenderServer) Kind(_ context.Context, _ *pluginv1.KindRequest) (*pluginv1.KindResponse, error) {
	return &pluginv1.KindResponse{Kind: "noop-vender"}, nil
}

func (s *noopVenderServer) Capabilities(_ context.Context, _ *pluginv1.CapabilitiesRequest) (*pluginv1.CapabilitiesResponse, error) {
	return &pluginv1.CapabilitiesResponse{
		Capabilities:     []string{"health"},
		ApiVersion:       1,
		ApiVersionCompat: ">=1",
	}, nil
}

func (s *noopVenderServer) Vend(_ context.Context, _ *pluginv1.VendRequest) (*pluginv1.VendResponse, error) {
	return &pluginv1.VendResponse{
		Credential: &pluginv1.VendedCredential{
			ApiKey:    []byte("noop-api-key"),
			Uuid:      "noop-uuid-0000",
			ExpiresAt: timestamppb.New(time.Now().Add(15 * time.Minute)),
		},
	}, nil
}

// noopVenderPlugin wires the gRPC server on the plugin side.
type noopVenderPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	impl *noopVenderServer
}

func (p *noopVenderPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterCredentialVenderServiceServer(s, p.impl)
	return nil
}

func (p *noopVenderPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, _ *grpc.ClientConn) (interface{}, error) {
	panic("GRPCClient called on server-side plugin binary")
}

// HandshakeConfig must match the host exactly.
var handshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "agentkms_plugin_v1",
}

func main() {
	impl := &noopVenderServer{}
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins: goplugin.PluginSet{
			"credential_vender": &noopVenderPlugin{impl: impl},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
