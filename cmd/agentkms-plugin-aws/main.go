// agentkms-plugin-aws is the OSS AWS STS credential vender plugin for AgentKMS.
//
// It implements CredentialVenderService (api/plugin/v1) and is loaded by the
// AgentKMS host as a hashicorp/go-plugin subprocess under PluginMap key
// "credential_vender".
//
// Build:
//
//	go build -o agentkms-plugin-aws ./cmd/agentkms-plugin-aws
//
// Install into the host plugin directory (see agentkms plugin install), then
// StartProvider("aws-sts") registers Kind aws-sts with the server registry.
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
	"time"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	"github.com/agentkms/agentkms/internal/credentials"
	aws "github.com/agentkms/agentkms/plugins/dynsecrets-aws"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// awsVenderServer adapts aws.Plugin to CredentialVenderServiceServer.
type awsVenderServer struct {
	pluginv1.UnimplementedCredentialVenderServiceServer
	plugin *aws.Plugin
}

func newAWSVenderServer() *awsVenderServer {
	// Default role/region from env so the binary can start without compile-time config.
	// Empty defaults are replaced at Vend time from scope params (role_arn is required there).
	role := os.Getenv("AGENTKMS_AWS_DEFAULT_ROLE_ARN")
	region := os.Getenv("AGENTKMS_AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}
	if role == "" {
		// Placeholder so New() succeeds; Validate on each Vend still requires scope role_arn.
		role = "arn:aws:iam::000000000000:role/agentkms-unconfigured"
	}
	p, err := aws.New(role, region)
	if err != nil {
		log.Fatalf("aws plugin: New: %v", err)
	}
	// Optional STS client can be wired here when an AWS SDK adapter is available.
	return &awsVenderServer{plugin: p}
}

func (s *awsVenderServer) Kind(_ context.Context, _ *pluginv1.KindRequest) (*pluginv1.KindResponse, error) {
	return &pluginv1.KindResponse{Kind: s.plugin.Kind()}, nil
}

func (s *awsVenderServer) Capabilities(_ context.Context, _ *pluginv1.CapabilitiesRequest) (*pluginv1.CapabilitiesResponse, error) {
	return &pluginv1.CapabilitiesResponse{
		Capabilities:     []string{"health"},
		ApiVersion:       1,
		ApiVersionCompat: ">=1",
	}, nil
}

func (s *awsVenderServer) Vend(ctx context.Context, req *pluginv1.VendRequest) (*pluginv1.VendResponse, error) {
	scope := protoToScope(req.GetScope())
	if scope.Kind == "" {
		scope.Kind = s.plugin.Kind()
	}
	cred, err := s.plugin.Vend(ctx, scope)
	if err != nil {
		return &pluginv1.VendResponse{Error: err.Error()}, nil
	}
	hash := sha256.Sum256(cred.APIKey)
	return &pluginv1.VendResponse{
		Credential: &pluginv1.VendedCredential{
			ApiKey:            cred.APIKey,
			Uuid:              cred.UUID,
			ProviderTokenHash: hex.EncodeToString(hash[:]),
			ExpiresAt:         timestamppb.New(cred.ExpiresAt),
		},
	}, nil
}

type awsVenderPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	impl *awsVenderServer
}

func (p *awsVenderPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterCredentialVenderServiceServer(s, p.impl)
	return nil
}

func (p *awsVenderPlugin) GRPCClient(context.Context, *goplugin.GRPCBroker, *grpc.ClientConn) (interface{}, error) {
	panic("GRPCClient called on server-side plugin binary")
}

var handshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "agentkms_plugin_v1",
}

func main() {
	impl := newAWSVenderServer()
	log.Printf("[aws-plugin] serving kind=%s (register with AgentKMS host as credential_vender)", impl.plugin.Kind())
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins: goplugin.PluginSet{
			"credential_vender": &awsVenderPlugin{impl: impl},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}

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

// silence unused import if toolchain strips — fmt used in logs only via log.Fatalf
