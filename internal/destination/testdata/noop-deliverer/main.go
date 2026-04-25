// Stub destination plugin binary for AgentKMS integration tests.
//
// Implements DestinationDelivererService for Kind="noop" using the
// hashicorp/go-plugin gRPC transport and the agentkms_plugin_v1 magic cookie.
//
// Build this binary before running destination subprocess or integration tests:
//
//	go build -o internal/destination/testdata/noop-deliverer/agentkms-plugin-noop-destination \
//	    ./internal/destination/testdata/noop-deliverer/
//
// The binary reports:
//   - Kind = "noop"
//   - Capabilities = ["health", "revoke"]
//   - Validate always succeeds
//   - Deliver records the call in-memory, returns DESTINATION_OK
//   - Revoke records the call in-memory, returns DESTINATION_OK
//   - Health always returns DESTINATION_OK
package main

import (
	"context"
	"sync"
	"sync/atomic"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// noopServer implements DestinationDelivererServiceServer.
// All operations succeed — this is a test fixture, not a production plugin.
type noopServer struct {
	pluginv1.UnimplementedDestinationDelivererServiceServer

	mu              sync.Mutex
	deliveryCount   int64
	revocationCount int64
	lastGeneration  map[string]uint64
}

func newNoopServer() *noopServer {
	return &noopServer{
		lastGeneration: make(map[string]uint64),
	}
}

func (s *noopServer) Kind(_ context.Context, _ *pluginv1.KindRequest) (*pluginv1.KindResponse, error) {
	return &pluginv1.KindResponse{Kind: "noop"}, nil
}

func (s *noopServer) Capabilities(_ context.Context, _ *pluginv1.CapabilitiesRequest) (*pluginv1.CapabilitiesResponse, error) {
	return &pluginv1.CapabilitiesResponse{
		Capabilities:     []string{"health", "revoke"},
		ApiVersion:       1,
		ApiVersionCompat: ">=1",
	}, nil
}

func (s *noopServer) Validate(_ context.Context, _ *pluginv1.ValidateDestinationRequest) (*pluginv1.ValidateDestinationResponse, error) {
	return &pluginv1.ValidateDestinationResponse{
		ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK,
	}, nil
}

func (s *noopServer) Deliver(_ context.Context, req *pluginv1.DeliverRequest) (*pluginv1.DeliverResponse, error) {
	if req.Generation == 0 {
		return &pluginv1.DeliverResponse{
			ErrorCode:    pluginv1.DestinationErrorCode_DESTINATION_PERMANENT,
			ErrorMessage: "generation 0 is invalid",
		}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Generation regression check.
	if last, ok := s.lastGeneration[req.TargetId]; ok && req.Generation < last {
		return &pluginv1.DeliverResponse{
			ErrorCode:    pluginv1.DestinationErrorCode_DESTINATION_GENERATION_REGRESSION,
			ErrorMessage: "generation regression",
		}, nil
	}

	s.lastGeneration[req.TargetId] = req.Generation
	atomic.AddInt64(&s.deliveryCount, 1)

	return &pluginv1.DeliverResponse{
		ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK,
	}, nil
}

func (s *noopServer) Revoke(_ context.Context, _ *pluginv1.RevokeDestinationRequest) (*pluginv1.RevokeDestinationResponse, error) {
	atomic.AddInt64(&s.revocationCount, 1)
	return &pluginv1.RevokeDestinationResponse{
		ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK,
	}, nil
}

func (s *noopServer) Health(_ context.Context, _ *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	return &pluginv1.HealthResponse{
		ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK,
	}, nil
}

// noopDelivererPlugin wires the gRPC server on the plugin side.
type noopDelivererPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	impl *noopServer
}

func (p *noopDelivererPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterDestinationDelivererServiceServer(s, p.impl)
	return nil
}

func (p *noopDelivererPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, _ *grpc.ClientConn) (interface{}, error) {
	panic("GRPCClient called on server-side plugin binary")
}

// HandshakeConfig must match the host exactly.
var handshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "agentkms_plugin_v1",
}

func main() {
	impl := newNoopServer()
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins: goplugin.PluginSet{
			"destination_deliverer": &noopDelivererPlugin{impl: impl},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
