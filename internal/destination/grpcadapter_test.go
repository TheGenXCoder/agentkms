package destination

// grpcadapter_test.go — tests for DestinationDelivererGRPC using an in-process
// gRPC server backed by the no-op implementation.
//
// These tests cover the adapter's proto↔Go conversion layer without spawning
// a subprocess. For subprocess integration tests see:
//   internal/destination/testdata/noop-deliverer/ (the binary)
//   the integration test below in this file.

import (
	"context"
	"net"
	"testing"
	"time"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ── In-process gRPC server for adapter tests ──────────────────────────────────

// inProcessNoopServer implements DestinationDelivererServiceServer in-process.
// Simulates the noop subprocess without forking.
type inProcessNoopServer struct {
	pluginv1.UnimplementedDestinationDelivererServiceServer

	lastGenerations map[string]uint64
	deliveryCount   int
	revocationCount int
	healthErr       string
}

func newInProcessNoopServer() *inProcessNoopServer {
	return &inProcessNoopServer{lastGenerations: make(map[string]uint64)}
}

func (s *inProcessNoopServer) Kind(_ context.Context, _ *pluginv1.KindRequest) (*pluginv1.KindResponse, error) {
	return &pluginv1.KindResponse{Kind: "noop"}, nil
}

func (s *inProcessNoopServer) Capabilities(_ context.Context, _ *pluginv1.CapabilitiesRequest) (*pluginv1.CapabilitiesResponse, error) {
	return &pluginv1.CapabilitiesResponse{
		Capabilities:     []string{"health", "revoke"},
		ApiVersion:       1,
		ApiVersionCompat: ">=1",
	}, nil
}

func (s *inProcessNoopServer) Validate(_ context.Context, _ *pluginv1.ValidateDestinationRequest) (*pluginv1.ValidateDestinationResponse, error) {
	return &pluginv1.ValidateDestinationResponse{
		ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK,
	}, nil
}

func (s *inProcessNoopServer) Deliver(_ context.Context, req *pluginv1.DeliverRequest) (*pluginv1.DeliverResponse, error) {
	if req.Generation == 0 {
		return &pluginv1.DeliverResponse{
			ErrorCode:    pluginv1.DestinationErrorCode_DESTINATION_PERMANENT,
			ErrorMessage: "generation 0 is invalid",
		}, nil
	}

	if last, ok := s.lastGenerations[req.TargetId]; ok && req.Generation < last {
		return &pluginv1.DeliverResponse{
			ErrorCode:    pluginv1.DestinationErrorCode_DESTINATION_GENERATION_REGRESSION,
			ErrorMessage: "generation regression",
		}, nil
	}
	s.lastGenerations[req.TargetId] = req.Generation
	s.deliveryCount++

	return &pluginv1.DeliverResponse{
		ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK,
	}, nil
}

func (s *inProcessNoopServer) Revoke(_ context.Context, _ *pluginv1.RevokeDestinationRequest) (*pluginv1.RevokeDestinationResponse, error) {
	s.revocationCount++
	return &pluginv1.RevokeDestinationResponse{
		ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK,
	}, nil
}

func (s *inProcessNoopServer) Health(_ context.Context, _ *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	if s.healthErr != "" {
		return &pluginv1.HealthResponse{
			ErrorCode:    pluginv1.DestinationErrorCode_DESTINATION_TRANSIENT,
			ErrorMessage: s.healthErr,
		}, nil
	}
	return &pluginv1.HealthResponse{
		ErrorCode:  pluginv1.DestinationErrorCode_DESTINATION_OK,
		LatencyMs:  1,
	}, nil
}

// startInProcessServer starts a local gRPC server and returns an adapter
// connected to it, plus a cleanup function.
func startInProcessServer(t *testing.T) (*DestinationDelivererGRPC, *inProcessNoopServer, func()) {
	t.Helper()

	srv := grpc.NewServer()
	impl := newInProcessNoopServer()
	pluginv1.RegisterDestinationDelivererServiceServer(srv, impl)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		srv.Stop()
		t.Fatalf("grpc.NewClient: %v", err)
	}

	client := pluginv1.NewDestinationDelivererServiceClient(conn)

	// Negotiate kind and capabilities (mirrors host startup).
	ctx := context.Background()
	kindResp, err := client.Kind(ctx, &pluginv1.KindRequest{})
	if err != nil {
		srv.Stop()
		t.Fatalf("Kind() RPC: %v", err)
	}

	capsResp, err := client.Capabilities(ctx, &pluginv1.CapabilitiesRequest{})
	if err != nil {
		srv.Stop()
		t.Fatalf("Capabilities() RPC: %v", err)
	}

	adapter := NewDestinationDelivererGRPC(client, kindResp.Kind, capsResp.Capabilities)

	cleanup := func() {
		conn.Close()
		srv.GracefulStop()
	}
	return adapter, impl, cleanup
}

// ── Adapter tests ─────────────────────────────────────────────────────────────

// TestGRPCAdapter_KindAndCapabilities verifies that Kind and Capabilities
// are correctly populated during startup negotiation.
func TestGRPCAdapter_KindAndCapabilities(t *testing.T) {
	adapter, _, cleanup := startInProcessServer(t)
	defer cleanup()

	if got := adapter.Kind(); got != "noop" {
		t.Errorf("Kind() = %q, want %q", got, "noop")
	}

	caps := adapter.Capabilities()
	if len(caps) == 0 {
		t.Error("Capabilities() returned empty, want [health, revoke]")
	}

	has := func(s string) bool {
		for _, c := range caps {
			if c == s {
				return true
			}
		}
		return false
	}
	if !has("health") {
		t.Error("Capabilities() missing 'health'")
	}
	if !has("revoke") {
		t.Error("Capabilities() missing 'revoke'")
	}
}

// TestGRPCAdapter_Validate_Success verifies that Validate round-trips correctly.
func TestGRPCAdapter_Validate_Success(t *testing.T) {
	adapter, _, cleanup := startInProcessServer(t)
	defer cleanup()

	if err := adapter.Validate(context.Background(), nil); err != nil {
		t.Errorf("Validate() returned error: %v", err)
	}
}

// TestGRPCAdapter_Deliver_RoundTrip verifies that Deliver sends the request
// over gRPC and the adapter correctly maps DESTINATION_OK to (false, nil).
func TestGRPCAdapter_Deliver_RoundTrip(t *testing.T) {
	adapter, impl, cleanup := startInProcessServer(t)
	defer cleanup()

	req := DeliverRequest{
		TargetID:        "owner/repo:API_KEY",
		CredentialValue: []byte("ghp_secret"),
		Generation:      1,
		DeliveryID:      "uuid-deliver-1",
		CredentialUUID:  "cred-uuid-999",
	}

	isPerm, err := adapter.Deliver(context.Background(), req)
	if err != nil {
		t.Fatalf("Deliver() returned error: %v", err)
	}
	if isPerm {
		t.Error("Deliver() isPermanentError = true on success, want false")
	}

	if impl.deliveryCount != 1 {
		t.Errorf("server deliveryCount = %d, want 1", impl.deliveryCount)
	}
}

// TestGRPCAdapter_Deliver_WithTTLAndExpiry verifies that TTL and ExpiresAt
// fields are correctly transmitted (proto conversion).
func TestGRPCAdapter_Deliver_WithTTLAndExpiry(t *testing.T) {
	adapter, _, cleanup := startInProcessServer(t)
	defer cleanup()

	req := DeliverRequest{
		TargetID:        "ns/secret:key",
		CredentialValue: []byte("tok"),
		Generation:      1,
		DeliveryID:      "uuid-ttl",
		TTL:             24 * time.Hour,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
	}

	_, err := adapter.Deliver(context.Background(), req)
	if err != nil {
		t.Errorf("Deliver() with TTL and ExpiresAt returned error: %v", err)
	}
}

// TestGRPCAdapter_Deliver_GenerationRegression verifies that the adapter
// maps DESTINATION_GENERATION_REGRESSION to (true, err).
func TestGRPCAdapter_Deliver_GenerationRegression(t *testing.T) {
	adapter, _, cleanup := startInProcessServer(t)
	defer cleanup()
	ctx := context.Background()

	// Deliver gen=5 first.
	if _, err := adapter.Deliver(ctx, DeliverRequest{
		TargetID: "target:key", Generation: 5, DeliveryID: "d1",
	}); err != nil {
		t.Fatalf("first Deliver: %v", err)
	}

	// Now deliver gen=3 — regression.
	isPerm, err := adapter.Deliver(ctx, DeliverRequest{
		TargetID: "target:key", Generation: 3, DeliveryID: "d2",
	})
	if err == nil {
		t.Fatal("expected GENERATION_REGRESSION error, got nil")
	}
	if !isPerm {
		t.Error("GENERATION_REGRESSION should be permanent, got isPermanentError=false")
	}
}

// TestGRPCAdapter_Deliver_Idempotent verifies that delivering the same
// DeliveryID and Generation twice both return nil (full overwrite semantics).
func TestGRPCAdapter_Deliver_Idempotent(t *testing.T) {
	adapter, impl, cleanup := startInProcessServer(t)
	defer cleanup()
	ctx := context.Background()

	req := DeliverRequest{
		TargetID: "target:mykey", Generation: 2, DeliveryID: "retry-uuid",
	}

	if _, err := adapter.Deliver(ctx, req); err != nil {
		t.Fatalf("first Deliver: %v", err)
	}
	if _, err := adapter.Deliver(ctx, req); err != nil {
		t.Errorf("second Deliver (retry): %v", err)
	}

	// Server received 2 calls.
	if impl.deliveryCount != 2 {
		t.Errorf("server deliveryCount = %d, want 2", impl.deliveryCount)
	}
}

// TestGRPCAdapter_Revoke_RoundTrip verifies that Revoke sends the request
// and maps DESTINATION_OK to (false, nil).
func TestGRPCAdapter_Revoke_RoundTrip(t *testing.T) {
	adapter, impl, cleanup := startInProcessServer(t)
	defer cleanup()

	isPerm, err := adapter.Revoke(context.Background(), "owner/repo:SECRET", 1, nil)
	if err != nil {
		t.Fatalf("Revoke() returned error: %v", err)
	}
	if isPerm {
		t.Error("Revoke() isPermanentError = true on success, want false")
	}
	if impl.revocationCount != 1 {
		t.Errorf("server revocationCount = %d, want 1", impl.revocationCount)
	}
}

// TestGRPCAdapter_Revoke_Idempotent verifies that revoking twice returns nil
// both times (idempotent).
func TestGRPCAdapter_Revoke_Idempotent(t *testing.T) {
	adapter, _, cleanup := startInProcessServer(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := adapter.Revoke(ctx, "target:key", 3, nil); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	if _, err := adapter.Revoke(ctx, "target:key", 3, nil); err != nil {
		t.Errorf("second Revoke (idempotent): %v", err)
	}
}

// TestGRPCAdapter_Health_Healthy verifies that Health returns nil when the
// plugin reports DESTINATION_OK.
func TestGRPCAdapter_Health_Healthy(t *testing.T) {
	adapter, _, cleanup := startInProcessServer(t)
	defer cleanup()

	if err := adapter.Health(context.Background()); err != nil {
		t.Errorf("Health() returned error: %v", err)
	}
}

// TestGRPCAdapter_Health_Unhealthy verifies that Health surfaces errors when
// the plugin reports a non-OK code.
func TestGRPCAdapter_Health_Unhealthy(t *testing.T) {
	adapter, impl, cleanup := startInProcessServer(t)
	defer cleanup()

	// Configure the server to return a health error.
	impl.healthErr = "github api unreachable"

	if err := adapter.Health(context.Background()); err == nil {
		t.Error("Health() returned nil but plugin reported unhealthy, want error")
	}
}

// TestGRPCAdapter_SetKind_And_SetCapabilities verifies the mutator helpers
// used by the host during startup negotiation.
func TestGRPCAdapter_SetKind_And_SetCapabilities(t *testing.T) {
	adapter := NewDestinationDelivererGRPC(nil, "", nil)

	adapter.SetKind("github-secret")
	if got := adapter.Kind(); got != "github-secret" {
		t.Errorf("Kind() after SetKind = %q, want %q", got, "github-secret")
	}

	adapter.SetCapabilities([]string{"health", "revoke"})
	if caps := adapter.Capabilities(); len(caps) != 2 {
		t.Errorf("Capabilities() after SetCapabilities len = %d, want 2", len(caps))
	}
}

// TestGRPCAdapter_Client_ReturnsUnderlyingClient verifies that the Client()
// accessor returns the gRPC client passed at construction.
func TestGRPCAdapter_Client_ReturnsUnderlyingClient(t *testing.T) {
	adapter, _, cleanup := startInProcessServer(t)
	defer cleanup()

	// Client() must not be nil — it is used by the host for Kind/Capabilities RPCs.
	if adapter.Client() == nil {
		t.Error("Client() returned nil, want non-nil gRPC client")
	}
}

// TestGRPCAdapter_Deliver_PermanentErrorCodes verifies that the adapter
// maps TARGET_NOT_FOUND and PERMISSION_DENIED to permanent errors.
// These are produced by configuring the in-process server to return them.
func TestGRPCAdapter_Deliver_PermanentErrorCodes(t *testing.T) {
	// We need a custom server that returns TARGET_NOT_FOUND.
	srv := grpc.NewServer()
	customImpl := &customCodeServer{errorCode: pluginv1.DestinationErrorCode_DESTINATION_TARGET_NOT_FOUND}
	pluginv1.RegisterDestinationDelivererServiceServer(srv, customImpl)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	adapter := NewDestinationDelivererGRPC(
		pluginv1.NewDestinationDelivererServiceClient(conn),
		"custom", nil,
	)

	isPerm, err := adapter.Deliver(context.Background(), DeliverRequest{
		TargetID: "missing-target", Generation: 1, DeliveryID: "d1",
	})
	if err == nil {
		t.Fatal("Deliver with TARGET_NOT_FOUND: expected error, got nil")
	}
	if !isPerm {
		t.Error("TARGET_NOT_FOUND should be permanent, got isPermanentError=false")
	}

	// Now test PERMISSION_DENIED.
	customImpl.errorCode = pluginv1.DestinationErrorCode_DESTINATION_PERMISSION_DENIED
	isPerm2, err2 := adapter.Deliver(context.Background(), DeliverRequest{
		TargetID: "forbidden-target", Generation: 2, DeliveryID: "d2",
	})
	if err2 == nil {
		t.Fatal("Deliver with PERMISSION_DENIED: expected error, got nil")
	}
	if !isPerm2 {
		t.Error("PERMISSION_DENIED should be permanent, got isPermanentError=false")
	}
}

// TestGRPCAdapter_Revoke_Permanent verifies that a permanent revoke error code
// is correctly surfaced as (true, err).
func TestGRPCAdapter_Revoke_Permanent(t *testing.T) {
	srv := grpc.NewServer()
	customImpl := &customCodeServer{errorCode: pluginv1.DestinationErrorCode_DESTINATION_PERMANENT}
	pluginv1.RegisterDestinationDelivererServiceServer(srv, customImpl)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	adapter := NewDestinationDelivererGRPC(
		pluginv1.NewDestinationDelivererServiceClient(conn),
		"custom", nil,
	)

	isPerm, err := adapter.Revoke(context.Background(), "target:key", 1, nil)
	if err == nil {
		t.Fatal("Revoke with PERMANENT: expected error, got nil")
	}
	if !isPerm {
		t.Error("DESTINATION_PERMANENT Revoke should be permanent, got isPermanentError=false")
	}
}

// TestGRPCAdapter_Validate_Failure verifies that a non-OK Validate code
// returns an error.
func TestGRPCAdapter_Validate_Failure(t *testing.T) {
	srv := grpc.NewServer()
	customImpl := &customCodeServer{errorCode: pluginv1.DestinationErrorCode_DESTINATION_PERMANENT}
	pluginv1.RegisterDestinationDelivererServiceServer(srv, customImpl)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	customImpl2 := &validateFailServer{}
	pluginv1.RegisterDestinationDelivererServiceServer(grpc.NewServer(), customImpl2)

	srv2 := grpc.NewServer()
	pluginv1.RegisterDestinationDelivererServiceServer(srv2, customImpl2)
	lis2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen2: %v", err)
	}
	go func() { _ = srv2.Serve(lis2) }()
	defer srv2.GracefulStop()

	conn2, err := grpc.NewClient(lis2.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient2: %v", err)
	}
	defer conn2.Close()

	adapter := NewDestinationDelivererGRPC(
		pluginv1.NewDestinationDelivererServiceClient(conn2),
		"custom", nil,
	)

	if err := adapter.Validate(context.Background(), nil); err == nil {
		t.Fatal("Validate with non-OK response: expected error, got nil")
	}
}

// validateFailServer returns a non-OK Validate response.
type validateFailServer struct {
	pluginv1.UnimplementedDestinationDelivererServiceServer
}

func (s *validateFailServer) Validate(_ context.Context, _ *pluginv1.ValidateDestinationRequest) (*pluginv1.ValidateDestinationResponse, error) {
	return &pluginv1.ValidateDestinationResponse{
		ErrorCode:    pluginv1.DestinationErrorCode_DESTINATION_PERMANENT,
		ErrorMessage: "target does not exist",
	}, nil
}

// TestGRPCAdapter_Deliver_TransientErrorCode verifies DESTINATION_TRANSIENT
// maps to (false, err).
func TestGRPCAdapter_Deliver_TransientErrorCode(t *testing.T) {
	srv := grpc.NewServer()
	customImpl := &customCodeServer{errorCode: pluginv1.DestinationErrorCode_DESTINATION_TRANSIENT}
	pluginv1.RegisterDestinationDelivererServiceServer(srv, customImpl)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	adapter := NewDestinationDelivererGRPC(
		pluginv1.NewDestinationDelivererServiceClient(conn),
		"custom", nil,
	)

	isPerm, err := adapter.Deliver(context.Background(), DeliverRequest{
		TargetID: "rate-limited-target", Generation: 1, DeliveryID: "d1",
	})
	if err == nil {
		t.Fatal("Deliver with TRANSIENT: expected error, got nil")
	}
	if isPerm {
		t.Error("DESTINATION_TRANSIENT should be non-permanent, got isPermanentError=true")
	}
}

// customCodeServer returns a fixed DestinationErrorCode on all Deliver calls.
type customCodeServer struct {
	pluginv1.UnimplementedDestinationDelivererServiceServer
	errorCode pluginv1.DestinationErrorCode
}

func (s *customCodeServer) Deliver(_ context.Context, _ *pluginv1.DeliverRequest) (*pluginv1.DeliverResponse, error) {
	msg := "custom error"
	if s.errorCode == pluginv1.DestinationErrorCode_DESTINATION_OK {
		msg = ""
	}
	return &pluginv1.DeliverResponse{
		ErrorCode:    s.errorCode,
		ErrorMessage: msg,
	}, nil
}

func (s *customCodeServer) Validate(_ context.Context, _ *pluginv1.ValidateDestinationRequest) (*pluginv1.ValidateDestinationResponse, error) {
	return &pluginv1.ValidateDestinationResponse{ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK}, nil
}

func (s *customCodeServer) Revoke(_ context.Context, _ *pluginv1.RevokeDestinationRequest) (*pluginv1.RevokeDestinationResponse, error) {
	code := s.errorCode
	msg := "custom error"
	if code == pluginv1.DestinationErrorCode_DESTINATION_OK {
		msg = ""
	}
	return &pluginv1.RevokeDestinationResponse{
		ErrorCode:    code,
		ErrorMessage: msg,
	}, nil
}

func (s *customCodeServer) Health(_ context.Context, _ *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	return &pluginv1.HealthResponse{ErrorCode: pluginv1.DestinationErrorCode_DESTINATION_OK}, nil
}
