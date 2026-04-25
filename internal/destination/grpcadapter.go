package destination

// grpcadapter.go — gRPC adapter that wraps the generated DestinationDelivererService
// client stub and implements the DestinationDeliverer Go interface.
//
// This adapter is the transparency layer: the orchestrator sees only the Go
// interface and has no awareness of whether the implementation is in-process
// or over gRPC (hashicorp/go-plugin subprocess).
//
// Error classification:
//   - gRPC transport errors → wrapped Go errors (transient from orchestrator POV)
//   - DESTINATION_PERMANENT / DESTINATION_GENERATION_REGRESSION / etc. in response
//     error_code → permanent=true
//   - DESTINATION_TRANSIENT → permanent=false

import (
	"context"
	"fmt"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DestinationDelivererGRPC wraps the generated gRPC client and implements
// DestinationDeliverer. Returned by the destination registry for plugin-backed
// destination kinds.
type DestinationDelivererGRPC struct {
	client       pluginv1.DestinationDelivererServiceClient
	kind         string
	capabilities []string
}

// NewDestinationDelivererGRPC creates a new adapter wrapping the given gRPC client.
// kind and capabilities are populated by the host after startup negotiation.
func NewDestinationDelivererGRPC(
	client pluginv1.DestinationDelivererServiceClient,
	kind string,
	capabilities []string,
) *DestinationDelivererGRPC {
	return &DestinationDelivererGRPC{
		client:       client,
		kind:         kind,
		capabilities: capabilities,
	}
}

// Kind returns the destination kind discriminator (e.g. "github-secret").
func (a *DestinationDelivererGRPC) Kind() string { return a.kind }

// SetKind sets the kind after the host has called the Kind() RPC.
// Called by the host during startup handshake; not part of the DestinationDeliverer interface.
func (a *DestinationDelivererGRPC) SetKind(kind string) { a.kind = kind }

// Capabilities returns the feature tokens advertised by the plugin at startup.
func (a *DestinationDelivererGRPC) Capabilities() []string { return a.capabilities }

// SetCapabilities sets the capabilities after the host has called Capabilities() RPC.
// Called by the host during startup handshake; not part of the DestinationDeliverer interface.
func (a *DestinationDelivererGRPC) SetCapabilities(caps []string) { a.capabilities = caps }

// Client returns the underlying gRPC client for use by the host during startup
// negotiation (Kind, Capabilities RPCs). Not part of the DestinationDeliverer interface.
func (a *DestinationDelivererGRPC) Client() pluginv1.DestinationDelivererServiceClient {
	return a.client
}

// Validate performs a pre-flight connectivity and permission check against the
// target destination. Does not write any secret material.
func (a *DestinationDelivererGRPC) Validate(ctx context.Context, params map[string]any) error {
	resp, err := a.client.Validate(ctx, &pluginv1.ValidateDestinationRequest{
		Params: mapToStruct(params),
	})
	if err != nil {
		return fmt.Errorf("destination Validate RPC: %w", err)
	}
	if resp.ErrorCode != pluginv1.DestinationErrorCode_DESTINATION_OK {
		return fmt.Errorf("destination Validate: %s", resp.ErrorMessage)
	}
	return nil
}

// Deliver writes the credential value to the target identified by req.TargetID.
// Idempotent: multiple calls with the same DeliveryID and Generation are safe.
//
// Returns (false, nil) on success.
// Returns (false, err) for transient errors.
// Returns (true, err) for permanent errors.
func (a *DestinationDelivererGRPC) Deliver(ctx context.Context, req DeliverRequest) (bool, error) {
	pbReq := &pluginv1.DeliverRequest{
		TargetId:        req.TargetID,
		CredentialValue: req.CredentialValue,
		Generation:      req.Generation,
		DeliveryId:      req.DeliveryID,
		TtlSeconds:      int64(req.TTL.Seconds()),
		RequesterId:     req.RequesterID,
		CredentialUuid:  req.CredentialUUID,
		Params:          mapToStruct(req.Params),
	}
	if !req.ExpiresAt.IsZero() {
		pbReq.ExpiresAt = timestamppb.New(req.ExpiresAt)
	}

	resp, err := a.client.Deliver(ctx, pbReq)
	if err != nil {
		// gRPC transport error — treat as transient.
		return false, fmt.Errorf("destination Deliver RPC: %w", err)
	}

	if resp.ErrorCode == pluginv1.DestinationErrorCode_DESTINATION_OK {
		return false, nil
	}

	permanent := isPermanentCode(resp.ErrorCode)
	return permanent, fmt.Errorf("destination Deliver: %s", resp.ErrorMessage)
}

// Revoke removes the credential from the target identified by targetID.
// Idempotent: returns nil if the credential is already absent.
//
// Returns (false, err) for transient; (true, err) for permanent errors.
func (a *DestinationDelivererGRPC) Revoke(ctx context.Context, targetID string, generation uint64, params map[string]any) (bool, error) {
	resp, err := a.client.Revoke(ctx, &pluginv1.RevokeDestinationRequest{
		TargetId:   targetID,
		Generation: generation,
		Params:     mapToStruct(params),
	})
	if err != nil {
		// gRPC transport error — treat as transient.
		return false, fmt.Errorf("destination Revoke RPC: %w", err)
	}

	if resp.ErrorCode == pluginv1.DestinationErrorCode_DESTINATION_OK {
		return false, nil
	}

	permanent := isPermanentCode(resp.ErrorCode)
	return permanent, fmt.Errorf("destination Revoke: %s", resp.ErrorMessage)
}

// Health returns nil if the destination is reachable and the plugin's service
// account credentials are valid. Must complete within 5 seconds.
func (a *DestinationDelivererGRPC) Health(ctx context.Context) error {
	resp, err := a.client.Health(ctx, &pluginv1.HealthRequest{})
	if err != nil {
		return fmt.Errorf("destination Health RPC: %w", err)
	}
	if resp.ErrorCode != pluginv1.DestinationErrorCode_DESTINATION_OK {
		return fmt.Errorf("destination Health: %s", resp.ErrorMessage)
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// isPermanentCode returns true for error codes that represent permanent failures.
func isPermanentCode(code pluginv1.DestinationErrorCode) bool {
	switch code {
	case pluginv1.DestinationErrorCode_DESTINATION_PERMANENT,
		pluginv1.DestinationErrorCode_DESTINATION_GENERATION_REGRESSION,
		pluginv1.DestinationErrorCode_DESTINATION_TARGET_NOT_FOUND,
		pluginv1.DestinationErrorCode_DESTINATION_PERMISSION_DENIED:
		return true
	default:
		// DESTINATION_TRANSIENT, DESTINATION_ERROR_UNSPECIFIED → transient / unknown
		return false
	}
}

// mapToStruct converts a map[string]any to a *structpb.Struct.
// Returns nil for nil/empty maps (proto optional field).
func mapToStruct(m map[string]any) *structpb.Struct {
	if len(m) == 0 {
		return nil
	}
	s, err := structpb.NewStruct(m)
	if err != nil {
		// structpb.NewStruct only fails for non-JSON-serialisable values.
		// Params are always map[string]any from JSON; this should not occur.
		panic(fmt.Sprintf("destination: mapToStruct: %v", err))
	}
	return s
}

