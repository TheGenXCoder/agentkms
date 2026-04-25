// slow-validate-deliverer is a test plugin binary that hangs forever inside
// the Validate RPC. Used by TestDestinationHost_ValidateTimeout to verify that
// StartDestination enforces the 10-second Validate deadline and does not hang
// indefinitely when a misbehaving plugin stalls during startup.
//
// Build this binary before running the timeout test:
//
//	go build -o internal/destination/testdata/slow-validate-deliverer/agentkms-plugin-slow-validate \
//	    ./internal/destination/testdata/slow-validate-deliverer/
//
// The binary reports:
//   - Kind = "slow-validate"
//   - Capabilities = []
//   - Validate blocks until its context is cancelled (simulates a hung plugin)
//   - Deliver/Revoke/Health are unreachable in tests
package main

import (
	"context"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// slowServer implements DestinationDelivererServiceServer.
// Validate blocks until the caller's context is cancelled.
type slowServer struct {
	pluginv1.UnimplementedDestinationDelivererServiceServer
}

func (s *slowServer) Kind(_ context.Context, _ *pluginv1.KindRequest) (*pluginv1.KindResponse, error) {
	return &pluginv1.KindResponse{Kind: "slow-validate"}, nil
}

func (s *slowServer) Capabilities(_ context.Context, _ *pluginv1.CapabilitiesRequest) (*pluginv1.CapabilitiesResponse, error) {
	return &pluginv1.CapabilitiesResponse{Capabilities: nil}, nil
}

// Validate blocks forever — it waits for the context deadline.
func (s *slowServer) Validate(ctx context.Context, _ *pluginv1.ValidateDestinationRequest) (*pluginv1.ValidateDestinationResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *slowServer) Deliver(_ context.Context, _ *pluginv1.DeliverRequest) (*pluginv1.DeliverResponse, error) {
	return &pluginv1.DeliverResponse{ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK}, nil
}

func (s *slowServer) Revoke(_ context.Context, _ *pluginv1.RevokeDestinationRequest) (*pluginv1.RevokeDestinationResponse, error) {
	return &pluginv1.RevokeDestinationResponse{ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK}, nil
}

func (s *slowServer) Health(_ context.Context, _ *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	return &pluginv1.HealthResponse{ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK}, nil
}

// slowDelivererPlugin wires the gRPC server on the plugin side.
type slowDelivererPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	impl *slowServer
}

func (p *slowDelivererPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterDestinationDelivererServiceServer(s, p.impl)
	return nil
}

func (p *slowDelivererPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, _ *grpc.ClientConn) (interface{}, error) {
	panic("GRPCClient called on server-side plugin binary")
}

var handshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "agentkms_plugin_v1",
}

func main() {
	impl := &slowServer{}
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins: goplugin.PluginSet{
			"destination_deliverer": &slowDelivererPlugin{impl: impl},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
