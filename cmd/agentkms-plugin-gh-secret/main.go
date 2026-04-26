// agentkms-plugin-gh-secret is the OSS GitHub Secret destination plugin for AgentKMS.
//
// It implements the DestinationDelivererService gRPC service (defined in
// api/plugin/v1/destination.proto) and is loaded by the AgentKMS host as a
// hashicorp/go-plugin subprocess under the PluginMap key "destination_deliverer".
//
// This binary wires the ghsecret.Deliverer to the gRPC server-side stub.
// The binary is signed and placed in the plugin directory; the host loads it
// via StartDestination().
//
// Build and install with:
//
//	./scripts/deploy-oss-plugins.sh --no-sign
//
// Or build manually:
//
//	go build -o ~/.agentkms/plugins/agentkms-plugin-gh-secret \
//	    ./cmd/agentkms-plugin-gh-secret/
//
// The binary reports:
//   - Kind = "github-secret"
//   - Capabilities = ["health", "revoke"]
//
// Authentication, encryption, and GitHub API calls behave identically to the
// ghsecret.Deliverer. Override AGENTKMS_GH_BASE_URL in the environment to
// redirect API calls to an httptest server (useful for integration tests).
//
// Note: The original source for this binary lived at
// internal/destination/testdata/gh-secret-deliverer/main.go. That file has
// been superseded by this canonical location; the testdata copy is retained
// only for historical reference.
//
// HandshakeConfig matches the OSS host (internal/plugin/plugins.go):
//
//	ProtocolVersion:  1
//	MagicCookieKey:   "PLUGIN_MAGIC_COOKIE"
//	MagicCookieValue: "agentkms_plugin_v1"
package main

import (
	"context"
	"errors"
	"os"
	"time"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	"github.com/agentkms/agentkms/internal/destination"
	"github.com/agentkms/agentkms/internal/destination/ghsecret"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

// ghSecretServer adapts ghsecret.Deliverer to the gRPC DestinationDelivererServiceServer interface.
type ghSecretServer struct {
	pluginv1.UnimplementedDestinationDelivererServiceServer
	deliverer *ghsecret.Deliverer
}

func newGHSecretServer() *ghSecretServer {
	baseURL := os.Getenv("AGENTKMS_GH_BASE_URL")
	return &ghSecretServer{
		deliverer: ghsecret.NewDeliverer(baseURL, nil),
	}
}

func (s *ghSecretServer) Kind(_ context.Context, _ *pluginv1.KindRequest) (*pluginv1.KindResponse, error) {
	return &pluginv1.KindResponse{Kind: s.deliverer.Kind()}, nil
}

func (s *ghSecretServer) Capabilities(_ context.Context, _ *pluginv1.CapabilitiesRequest) (*pluginv1.CapabilitiesResponse, error) {
	return &pluginv1.CapabilitiesResponse{
		Capabilities:     s.deliverer.Capabilities(),
		ApiVersion:       1,
		ApiVersionCompat: ">=1",
	}, nil
}

func (s *ghSecretServer) Validate(ctx context.Context, req *pluginv1.ValidateDestinationRequest) (*pluginv1.ValidateDestinationResponse, error) {
	params := structToMap(req.GetParams())
	if err := s.deliverer.Validate(ctx, params); err != nil {
		return &pluginv1.ValidateDestinationResponse{
			ErrorCode:    pluginv1.DestinationErrorCode_DESTINATION_PERMANENT,
			ErrorMessage: err.Error(),
		}, nil
	}
	return &pluginv1.ValidateDestinationResponse{
		ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK,
	}, nil
}

func (s *ghSecretServer) Deliver(ctx context.Context, req *pluginv1.DeliverRequest) (*pluginv1.DeliverResponse, error) {
	dreq := protoToDeliverRequest(req)
	isPerm, err := s.deliverer.Deliver(ctx, dreq)
	if err != nil {
		code := classifyError(err, isPerm)
		return &pluginv1.DeliverResponse{
			ErrorCode:    code,
			ErrorMessage: err.Error(),
		}, nil
	}
	return &pluginv1.DeliverResponse{
		ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK,
	}, nil
}

func (s *ghSecretServer) Revoke(ctx context.Context, req *pluginv1.RevokeDestinationRequest) (*pluginv1.RevokeDestinationResponse, error) {
	params := structToMap(req.GetParams())
	isPerm, err := s.deliverer.Revoke(ctx, req.GetTargetId(), req.GetGeneration(), params)
	if err != nil {
		code := pluginv1.DestinationErrorCode_DESTINATION_TRANSIENT
		if isPerm {
			code = pluginv1.DestinationErrorCode_DESTINATION_PERMANENT
		}
		return &pluginv1.RevokeDestinationResponse{
			ErrorCode:    code,
			ErrorMessage: err.Error(),
		}, nil
	}
	return &pluginv1.RevokeDestinationResponse{
		ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK,
	}, nil
}

func (s *ghSecretServer) Health(ctx context.Context, _ *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	if err := s.deliverer.Health(ctx); err != nil {
		return &pluginv1.HealthResponse{
			ErrorCode:    pluginv1.DestinationErrorCode_DESTINATION_TRANSIENT,
			ErrorMessage: err.Error(),
		}, nil
	}
	return &pluginv1.HealthResponse{
		ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK,
	}, nil
}

// ghDelivererPlugin wires the gRPC server on the plugin side.
type ghDelivererPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	impl *ghSecretServer
}

func (p *ghDelivererPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterDestinationDelivererServiceServer(s, p.impl)
	return nil
}

func (p *ghDelivererPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, _ *grpc.ClientConn) (interface{}, error) {
	panic("GRPCClient called on server-side plugin binary")
}

// handshakeConfig must match the host exactly (internal/plugin/plugins.go).
var handshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "agentkms_plugin_v1",
}

func main() {
	impl := newGHSecretServer()
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins: goplugin.PluginSet{
			"destination_deliverer": &ghDelivererPlugin{impl: impl},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

func protoToDeliverRequest(req *pluginv1.DeliverRequest) destination.DeliverRequest {
	dreq := destination.DeliverRequest{
		TargetID:        req.GetTargetId(),
		CredentialValue: req.GetCredentialValue(),
		Generation:      req.GetGeneration(),
		DeliveryID:      req.GetDeliveryId(),
		RequesterID:     req.GetRequesterId(),
		CredentialUUID:  req.GetCredentialUuid(),
		Params:          structToMap(req.GetParams()),
	}
	if req.TtlSeconds > 0 {
		dreq.TTL = time.Duration(req.TtlSeconds) * time.Second
	}
	if req.ExpiresAt != nil {
		dreq.ExpiresAt = req.ExpiresAt.AsTime()
	}
	return dreq
}

// classifyError maps a delivery error to the appropriate DestinationErrorCode
// using errors.Is against the ghsecret sentinel errors. This replaces the
// previous string-matching approach, which was fragile and coupled to error
// message format.
//
// Sentinel-based classification is stable across refactors because it depends
// on ghError.Unwrap() returning the correct sentinel, not on message text.
func classifyError(err error, isPerm bool) pluginv1.DestinationErrorCode {
	switch {
	case errors.Is(err, ghsecret.ErrTargetNotFound):
		return pluginv1.DestinationErrorCode_DESTINATION_TARGET_NOT_FOUND
	case errors.Is(err, ghsecret.ErrPermissionDenied):
		return pluginv1.DestinationErrorCode_DESTINATION_PERMISSION_DENIED
	case errors.Is(err, ghsecret.ErrGenerationRegression):
		return pluginv1.DestinationErrorCode_DESTINATION_GENERATION_REGRESSION
	case errors.Is(err, ghsecret.ErrTransient):
		return pluginv1.DestinationErrorCode_DESTINATION_TRANSIENT
	default:
		if isPerm {
			return pluginv1.DestinationErrorCode_DESTINATION_PERMANENT
		}
		return pluginv1.DestinationErrorCode_DESTINATION_TRANSIENT
	}
}
