// Package plugin — host_service.go
//
// HostService is the OSS-side gRPC server that the Pro rotation orchestrator
// plugin calls back into. It gives the plugin subprocess controlled access to
// OSS-internal state: binding store, provider registry, destination registry,
// audit chain, and the pending-revocation queue.
//
// Transport: go-plugin GRPCBroker side channel within the established plugin
// process pair. See internal/plugin/host.go StartOrchestrator for the host
// setup, and agentkms-pro/internal/host/client.go for the consumer.
//
// Wire format: standard protobuf binary (proto3). The generated types are in
// api/plugin/v1/host.pb.go and api/plugin/v1/host_grpc.pb.go.
//
// This file references docs/specs/2026-04-26-T5-host-callback-design.md for
// the full concurrency contract, error model, and method surface documentation.
package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/credentials/binding"
	"github.com/agentkms/agentkms/internal/destination"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// pendingRevocationEntry is stored in the in-memory revocation queue.
// Persisted to EncryptedKV for durability on the host side.
type pendingRevocationEntry struct {
	CredentialUUID string    `json:"credential_uuid"`
	ScheduledAt    time.Time `json:"scheduled_at"`
	RetryCount     int32     `json:"retry_count"`
}

// hostServiceServer implements pluginv1.HostServiceServer.
// It is created once per orchestrator plugin startup and registered on the
// GRPCBroker side channel opened by StartOrchestrator.
//
// Concurrency: all methods are safe for concurrent use. SaveBindingMetadata
// for the same binding name is serialized by bindingMu. The pending-revocation
// queue (kvQueue) is serialized by queueMu.
type hostServiceServer struct {
	pluginv1.UnimplementedHostServiceServer

	store    binding.BindingStore
	registry *Registry
	auditor  audit.Auditor
	kv       credentials.KVWriter // for pending-revocation queue

	// bindingMu serializes SaveBindingMetadata per binding name.
	bindingMuMap  map[string]*sync.Mutex
	bindingMuLock sync.RWMutex

	// queueMu serializes EnqueueRevocation / DrainPendingRevocations / AckRevocation.
	queueMu sync.Mutex
}

// newHostServiceServer constructs a HostService server.
func newHostServiceServer(
	store binding.BindingStore,
	registry *Registry,
	auditor audit.Auditor,
	kv credentials.KVWriter,
) *hostServiceServer {
	return &hostServiceServer{
		store:        store,
		registry:     registry,
		auditor:      auditor,
		kv:           kv,
		bindingMuMap: make(map[string]*sync.Mutex),
	}
}

// bindingLock returns the per-binding mutex, creating it if needed.
func (s *hostServiceServer) bindingLock(name string) *sync.Mutex {
	s.bindingMuLock.RLock()
	mu, ok := s.bindingMuMap[name]
	s.bindingMuLock.RUnlock()
	if ok {
		return mu
	}
	s.bindingMuLock.Lock()
	defer s.bindingMuLock.Unlock()
	if mu, ok = s.bindingMuMap[name]; ok {
		return mu
	}
	mu = &sync.Mutex{}
	s.bindingMuMap[name] = mu
	return mu
}

// ── Bindings ─────────────────────────────────────────────────────────────────

// defaultPageSize is used when ListBindingsRequest.filter.page_size is zero.
const defaultPageSize = 50

// maxPageSize is the upper bound for ListBindingsRequest.filter.page_size.
const maxPageSize = 200

// ListBindings returns a paginated list of bindings matching the filter.
func (s *hostServiceServer) ListBindings(ctx context.Context, req *pluginv1.ListBindingsRequest) (*pluginv1.BindingList, error) {
	all, err := s.store.List(ctx)
	if err != nil {
		return &pluginv1.BindingList{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
			ErrorMessage: fmt.Sprintf("binding store list: %v", err),
		}, nil
	}

	filter := req.GetFilter()

	// Apply filters.
	var filtered []binding.CredentialBinding
	for _, b := range all {
		if !matchesFilter(b, filter) {
			continue
		}
		filtered = append(filtered, b)
	}

	total := len(filtered)

	// Pagination.
	pageSize := int(filter.GetPageSize())
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	// Decode page token (a simple index string).
	offset := 0
	if tok := filter.GetPageToken(); tok != "" {
		_, err := fmt.Sscanf(tok, "%d", &offset)
		if err != nil || offset < 0 || offset >= total {
			offset = 0
		}
	}

	end := offset + pageSize
	if end > total {
		end = total
	}
	page := filtered[offset:end]

	var nextToken string
	if end < total {
		nextToken = fmt.Sprintf("%d", end)
	}

	pbBindings := make([]*pluginv1.Binding, len(page))
	for i, b := range page {
		pb, err := bindingToProto(b)
		if err != nil {
			return &pluginv1.BindingList{
				ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
				ErrorMessage: fmt.Sprintf("marshal binding %q: %v", b.Name, err),
			}, nil
		}
		pbBindings[i] = pb
	}

	return &pluginv1.BindingList{
		Bindings:      pbBindings,
		NextPageToken: nextToken,
		TotalCount:    int32(total),
		ErrorCode:     pluginv1.HostCallbackErrorCode_HOST_OK,
	}, nil
}

// matchesFilter returns true if the binding passes all filter criteria.
func matchesFilter(b binding.CredentialBinding, f *pluginv1.BindingFilter) bool {
	if f == nil {
		return true
	}
	if pk := f.GetProviderKind(); pk != "" && b.ProviderKind != pk {
		return false
	}
	if bs := f.GetBindingState(); bs != "" {
		if b.Metadata.BindingState != bs {
			return false
		}
	}
	for _, tag := range f.GetTags() {
		if !containsTag(b.Metadata.Tags, tag) {
			return false
		}
	}
	return true
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// GetBinding fetches a specific binding by name.
func (s *hostServiceServer) GetBinding(ctx context.Context, req *pluginv1.GetBindingRequest) (*pluginv1.GetBindingResponse, error) {
	b, err := s.store.Get(ctx, req.GetName())
	if err != nil {
		if isBindingNotFound(err) {
			return &pluginv1.GetBindingResponse{
				ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND,
				ErrorMessage: fmt.Sprintf("binding %q not found", req.GetName()),
			}, nil
		}
		return &pluginv1.GetBindingResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
			ErrorMessage: fmt.Sprintf("binding store get %q: %v", req.GetName(), err),
		}, nil
	}
	pb, err := bindingToProto(*b)
	if err != nil {
		return &pluginv1.GetBindingResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
			ErrorMessage: fmt.Sprintf("marshal binding %q: %v", b.Name, err),
		}, nil
	}
	return &pluginv1.GetBindingResponse{
		Binding:   pb,
		ErrorCode: pluginv1.HostCallbackErrorCode_HOST_OK,
	}, nil
}

// SaveBindingMetadata persists the four metadata fields the orchestrator owns.
// Read-modify-write under the per-binding mutex.
func (s *hostServiceServer) SaveBindingMetadata(ctx context.Context, req *pluginv1.SaveBindingMetadataRequest) (*pluginv1.SaveBindingMetadataResponse, error) {
	name := req.GetName()
	patch := req.GetPatch()
	if patch == nil {
		return &pluginv1.SaveBindingMetadataResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
			ErrorMessage: "patch is nil",
		}, nil
	}

	mu := s.bindingLock(name)
	mu.Lock()
	defer mu.Unlock()

	// Read current binding.
	b, err := s.store.Get(ctx, name)
	if err != nil {
		if isBindingNotFound(err) {
			return &pluginv1.SaveBindingMetadataResponse{
				ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND,
				ErrorMessage: fmt.Sprintf("binding %q not found", name),
			}, nil
		}
		return &pluginv1.SaveBindingMetadataResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
			ErrorMessage: fmt.Sprintf("binding store get %q: %v", name, err),
		}, nil
	}

	// Reject generation regression: require strictly increasing generation.
	// patch.last_generation must be greater than the stored generation; equal
	// values are also rejected to prevent same-generation replay overwrites from
	// a stale orchestrator instance racing on a single node. (Multi-node
	// linearizability is a known limitation tracked in BLOCKERS.md B4 and
	// requires distributed locking beyond this single-node check.)
	if patch.GetLastGeneration() <= b.Metadata.LastGeneration {
		return &pluginv1.SaveBindingMetadataResponse{
			ErrorCode: pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
			ErrorMessage: fmt.Sprintf(
				"generation regression or replay: patch=%d must be > stored=%d",
				patch.GetLastGeneration(), b.Metadata.LastGeneration,
			),
		}, nil
	}

	// Apply patch fields.
	b.Metadata.LastGeneration = patch.GetLastGeneration()
	if ts := patch.GetLastRotatedAt(); ts != nil {
		b.Metadata.LastRotatedAt = ts.AsTime().UTC().Format(time.RFC3339)
	}
	if bs := patch.GetBindingState(); bs != "" {
		b.Metadata.BindingState = bs
	}
	if uuid := patch.GetLastCredentialUuid(); uuid != "" {
		b.Metadata.LastCredentialUUID = uuid
	}

	if err := s.store.Save(ctx, *b); err != nil {
		return &pluginv1.SaveBindingMetadataResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
			ErrorMessage: fmt.Sprintf("binding store save %q: %v", name, err),
		}, nil
	}

	return &pluginv1.SaveBindingMetadataResponse{
		ErrorCode: pluginv1.HostCallbackErrorCode_HOST_OK,
	}, nil
}

// ── Provider invocation ───────────────────────────────────────────────────────

// VendCredential dispatches to the provider plugin identified by provider_kind.
// Decision HC-4: the host does NOT auto-emit OperationCredentialVend here.
func (s *hostServiceServer) VendCredential(ctx context.Context, req *pluginv1.VendCredentialRequest) (*pluginv1.VendCredentialResponse, error) {
	vender, err := s.registry.LookupVender(req.GetProviderKind())
	if err != nil {
		return &pluginv1.VendCredentialResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND,
			ErrorMessage: fmt.Sprintf("provider kind %q not registered: %v", req.GetProviderKind(), err),
		}, nil
	}

	scope := protoToScope(req.GetScope())
	vc, err := vender.Vend(ctx, scope)
	if err != nil {
		// Classify as permanent (provider rejected) or transient (subprocess unavailable).
		errCode := pluginv1.HostCallbackErrorCode_HOST_PERMANENT
		if isTransientError(err) {
			errCode = pluginv1.HostCallbackErrorCode_HOST_TRANSIENT
		}
		return &pluginv1.VendCredentialResponse{
			ErrorCode:    errCode,
			ErrorMessage: fmt.Sprintf("vend from provider %q: %v", req.GetProviderKind(), err),
		}, nil
	}

	return &pluginv1.VendCredentialResponse{
		Credential: &pluginv1.VendedCredential{
			ApiKey:            vc.APIKey,
			Uuid:              vc.UUID,
			ProviderTokenHash: vc.ProviderTokenHash,
			ExpiresAt:         timestamppb.New(vc.ExpiresAt),
		},
		ErrorCode: pluginv1.HostCallbackErrorCode_HOST_OK,
	}, nil
}

// ── Destination invocation ────────────────────────────────────────────────────

// DeliverToDestination dispatches to the destination plugin identified by destination_kind.
// Maps DestinationDeliverer errors to HostCallbackErrorCode per design §2.3.
func (s *hostServiceServer) DeliverToDestination(ctx context.Context, req *pluginv1.DeliverToDestinationRequest) (*pluginv1.DeliverToDestinationResponse, error) {
	deliverer, err := s.registry.LookupDeliverer(req.GetDestinationKind())
	if err != nil {
		return &pluginv1.DeliverToDestinationResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND,
			ErrorMessage: fmt.Sprintf("destination kind %q not registered: %v", req.GetDestinationKind(), err),
		}, nil
	}

	var params map[string]any
	if p := req.GetParams(); p != nil {
		params = p.AsMap()
	}

	dreq := destination.DeliverRequest{
		TargetID:        req.GetTargetId(),
		CredentialValue: req.GetCredentialValue(),
		Generation:      req.GetGeneration(),
		DeliveryID:      req.GetDeliveryId(),
		TTL:             time.Duration(req.GetTtlSeconds()) * time.Second,
		ExpiresAt:       req.GetExpiresAt().AsTime(),
		RequesterID:     req.GetRequesterId(),
		CredentialUUID:  req.GetCredentialUuid(),
		Params:          params,
	}

	// Deliver first, then emit a single audit event with the actual outcome.
	// The audit event MUST reflect what actually happened, not what was intended.
	// Emitting before the call (as previously coded) would record a false
	// "success" when delivery fails. (Fix 4, forensics accuracy for Part 8.)
	isPerm, err := deliverer.Deliver(ctx, dreq)

	if err != nil {
		// Classify the anomaly tag by permanence so forensics queries can
		// distinguish transient (retry candidates) from permanent failures.
		anomalyTag := "delivery_transient_error"
		if isPerm {
			anomalyTag = "delivery_permanent_error"
		}
		_ = s.emitDestinationDeliverAudit(ctx, req, audit.OutcomeError, err.Error(), anomalyTag)
		if isPerm {
			return &pluginv1.DeliverToDestinationResponse{
				ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
				ErrorMessage: err.Error(),
			}, nil
		}
		return &pluginv1.DeliverToDestinationResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
			ErrorMessage: err.Error(),
		}, nil
	}

	_ = s.emitDestinationDeliverAudit(ctx, req, audit.OutcomeSuccess, "", "")
	return &pluginv1.DeliverToDestinationResponse{
		ErrorCode: pluginv1.HostCallbackErrorCode_HOST_OK,
	}, nil
}

// emitDestinationDeliverAudit logs a single destination_deliver audit event
// after the actual delivery attempt completes. anomalyTag should be
// "delivery_permanent_error", "delivery_transient_error", or "" (success).
func (s *hostServiceServer) emitDestinationDeliverAudit(ctx context.Context, req *pluginv1.DeliverToDestinationRequest, outcome, errDetail, anomalyTag string) error {
	ev, err := audit.New()
	if err != nil {
		return err
	}
	ev.Operation = audit.OperationDestinationDeliver
	ev.CallerID = "orchestrator"
	ev.Outcome = outcome
	ev.CredentialUUID = req.GetCredentialUuid()
	ev.CredentialType = req.GetDestinationKind()
	ev.AgentSession = req.GetDeliveryId()
	if errDetail != "" {
		ev.ErrorDetail = errDetail
	}
	if anomalyTag != "" {
		ev.Anomalies = append(ev.Anomalies, anomalyTag)
	}
	return s.auditor.Log(context.WithoutCancel(ctx), ev)
}

// RevokeAtDestination dispatches a Revoke to the destination plugin.
func (s *hostServiceServer) RevokeAtDestination(ctx context.Context, req *pluginv1.RevokeAtDestinationRequest) (*pluginv1.RevokeAtDestinationResponse, error) {
	deliverer, err := s.registry.LookupDeliverer(req.GetDestinationKind())
	if err != nil {
		return &pluginv1.RevokeAtDestinationResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND,
			ErrorMessage: fmt.Sprintf("destination kind %q not registered: %v", req.GetDestinationKind(), err),
		}, nil
	}

	var params map[string]any
	if p := req.GetParams(); p != nil {
		params = p.AsMap()
	}

	isPerm, err := deliverer.Revoke(ctx, req.GetTargetId(), req.GetGeneration(), params)
	if err != nil {
		if isPerm {
			return &pluginv1.RevokeAtDestinationResponse{
				ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
				ErrorMessage: err.Error(),
			}, nil
		}
		return &pluginv1.RevokeAtDestinationResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
			ErrorMessage: err.Error(),
		}, nil
	}

	return &pluginv1.RevokeAtDestinationResponse{
		ErrorCode: pluginv1.HostCallbackErrorCode_HOST_OK,
	}, nil
}

// ── Provider revocation ───────────────────────────────────────────────────────

// RevokeCredential revokes the credential identified by credential_uuid at its provider.
// The host looks up the vender by credential UUID. Currently uses a scan of the
// registry's venders. A dedicated credential-UUID → provider-kind index would be
// cleaner; see BLOCKERS.md note on RevokeCredential lookup.
func (s *hostServiceServer) RevokeCredential(ctx context.Context, req *pluginv1.RevokeCredentialRequest) (*pluginv1.RevokeCredentialResponse, error) {
	uuid := req.GetCredentialUuid()
	if uuid == "" {
		return &pluginv1.RevokeCredentialResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
			ErrorMessage: "credential_uuid is required",
		}, nil
	}

	// Attempt revocation against all registered venders.
	// This is O(N) venders but N is always tiny (typically 1-3 provider plugins).
	// A dedicated UUID→kind index is a v1.1 optimization (see BLOCKERS.md).
	kinds := s.registry.VenderKinds()
	if len(kinds) == 0 {
		return &pluginv1.RevokeCredentialResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND,
			ErrorMessage: fmt.Sprintf("no provider venders registered; cannot revoke credential %q", uuid),
		}, nil
	}

	// Try each vender. The one that owns the UUID will revoke it; others
	// should return a not-found/already-revoked success (idempotent contract).
	var lastErr error
	for _, kind := range kinds {
		vender, err := s.registry.LookupVender(kind)
		if err != nil {
			continue
		}
		// Check if this vender implements Revoke.
		type Revoker interface {
			Revoke(ctx context.Context, credentialUUID string) error
		}
		revoker, ok := vender.(Revoker)
		if !ok {
			continue // vender doesn't support Revoke — skip
		}
		if err := revoker.Revoke(ctx, uuid); err != nil {
			lastErr = err
			if isTransientError(err) {
				return &pluginv1.RevokeCredentialResponse{
					ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
					ErrorMessage: fmt.Sprintf("revoke via %q: %v", kind, err),
				}, nil
			}
			// Permanent error from this vender — try next (maybe another owns it).
			continue
		}
		return &pluginv1.RevokeCredentialResponse{
			ErrorCode: pluginv1.HostCallbackErrorCode_HOST_OK,
		}, nil
	}

	if lastErr != nil {
		return &pluginv1.RevokeCredentialResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
			ErrorMessage: fmt.Sprintf("revoke credential %q: %v", uuid, lastErr),
		}, nil
	}

	// No vender supports Revoke — treat as not found.
	return &pluginv1.RevokeCredentialResponse{
		ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND,
		ErrorMessage: fmt.Sprintf("no vender can revoke credential %q (none implement Revoke)", uuid),
	}, nil
}

// ── Audit emission ────────────────────────────────────────────────────────────

// EmitAudit writes an audit event through the OSS Auditor.
func (s *hostServiceServer) EmitAudit(ctx context.Context, req *pluginv1.EmitAuditRequest) (*pluginv1.EmitAuditResponse, error) {
	ev := req.GetEvent()
	if ev == nil {
		return &pluginv1.EmitAuditResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
			ErrorMessage: "event is nil",
		}, nil
	}

	auditEv, err := audit.New()
	if err != nil {
		return &pluginv1.EmitAuditResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
			ErrorMessage: fmt.Sprintf("generate event ID: %v", err),
		}, nil
	}

	// Map proto fields onto AuditEvent.
	auditEv.Operation = ev.GetOperation()
	auditEv.CredentialUUID = ev.GetCredentialUuid()
	auditEv.CredentialType = ev.GetCredentialType()
	auditEv.CallerID = ev.GetCallerId()
	auditEv.Outcome = ev.GetOutcome()
	auditEv.ErrorDetail = ev.GetErrorDetail()
	auditEv.Anomalies = ev.GetAnomalies()
	auditEv.AgentSession = ev.GetAgentSession()
	auditEv.InvalidationReason = ev.GetInvalidationReason()
	auditEv.RuleID = ev.GetRuleId()

	// Server-side firewall: validate before writing.
	if err := auditEv.Validate(); err != nil {
		return &pluginv1.EmitAuditResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
			ErrorMessage: fmt.Sprintf("audit event validation failed: %v", err),
		}, nil
	}

	if err := s.auditor.Log(context.WithoutCancel(ctx), auditEv); err != nil {
		return &pluginv1.EmitAuditResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
			ErrorMessage: fmt.Sprintf("audit log: %v", err),
		}, nil
	}

	return &pluginv1.EmitAuditResponse{
		ErrorCode: pluginv1.HostCallbackErrorCode_HOST_OK,
	}, nil
}

// ── Pending revocation queue ──────────────────────────────────────────────────

const pendingRevocationPrefix = "orchestrator/pending-revocations/"

func revocationKVPath(credentialUUID string) string {
	return pendingRevocationPrefix + credentialUUID
}

// EnqueueRevocation persists a delayed-revocation entry to EncryptedKV.
func (s *hostServiceServer) EnqueueRevocation(ctx context.Context, req *pluginv1.EnqueueRevocationRequest) (*pluginv1.EnqueueRevocationResponse, error) {
	uuid := req.GetCredentialUuid()
	if uuid == "" {
		return &pluginv1.EnqueueRevocationResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
			ErrorMessage: "credential_uuid is required",
		}, nil
	}

	s.queueMu.Lock()
	defer s.queueMu.Unlock()

	entry := pendingRevocationEntry{
		CredentialUUID: uuid,
		ScheduledAt:    req.GetScheduledAt().AsTime().UTC(),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return &pluginv1.EnqueueRevocationResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
			ErrorMessage: fmt.Sprintf("marshal revocation entry: %v", err),
		}, nil
	}

	if err := s.kv.SetSecret(ctx, revocationKVPath(uuid), map[string]string{"entry": string(data)}); err != nil {
		return &pluginv1.EnqueueRevocationResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
			ErrorMessage: fmt.Sprintf("kv set %q: %v", uuid, err),
		}, nil
	}

	return &pluginv1.EnqueueRevocationResponse{
		ErrorCode: pluginv1.HostCallbackErrorCode_HOST_OK,
	}, nil
}

// DrainPendingRevocations returns all pending revocations whose scheduled_at <= now.
func (s *hostServiceServer) DrainPendingRevocations(ctx context.Context, req *pluginv1.DrainPendingRevocationsRequest) (*pluginv1.DrainPendingRevocationsResponse, error) {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()

	now := req.GetNow().AsTime().UTC()

	paths, err := s.kv.ListPaths(ctx)
	if err != nil {
		return &pluginv1.DrainPendingRevocationsResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
			ErrorMessage: fmt.Sprintf("kv list paths: %v", err),
		}, nil
	}

	var due []*pluginv1.PendingRevocation
	for _, path := range paths {
		if !strings.HasPrefix(path, pendingRevocationPrefix) {
			continue
		}
		fields, err := s.kv.GetSecret(ctx, path)
		if err != nil {
			continue // skip inaccessible entries
		}
		raw, ok := fields["entry"]
		if !ok {
			continue
		}
		var entry pendingRevocationEntry
		if err := json.Unmarshal([]byte(raw), &entry); err != nil {
			continue
		}
		if !entry.ScheduledAt.After(now) {
			// Increment retry_count in the stored entry.
			entry.RetryCount++
			updated, _ := json.Marshal(entry)
			_ = s.kv.SetSecret(ctx, path, map[string]string{"entry": string(updated)})
			due = append(due, &pluginv1.PendingRevocation{
				CredentialUuid: entry.CredentialUUID,
				ScheduledAt:    timestamppb.New(entry.ScheduledAt),
				RetryCount:     entry.RetryCount,
			})
		}
	}

	return &pluginv1.DrainPendingRevocationsResponse{
		Revocations: due,
		ErrorCode:   pluginv1.HostCallbackErrorCode_HOST_OK,
	}, nil
}

// AckRevocation removes a pending-revocation entry from EncryptedKV.
func (s *hostServiceServer) AckRevocation(ctx context.Context, req *pluginv1.AckRevocationRequest) (*pluginv1.AckRevocationResponse, error) {
	uuid := req.GetCredentialUuid()
	if uuid == "" {
		return &pluginv1.AckRevocationResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_PERMANENT,
			ErrorMessage: "credential_uuid is required",
		}, nil
	}

	s.queueMu.Lock()
	defer s.queueMu.Unlock()

	if err := s.kv.DeleteSecret(ctx, revocationKVPath(uuid)); err != nil {
		// Idempotent: already-removed UUID returns HOST_OK.
		if isNotFoundKV(err) {
			return &pluginv1.AckRevocationResponse{
				ErrorCode: pluginv1.HostCallbackErrorCode_HOST_OK,
			}, nil
		}
		return &pluginv1.AckRevocationResponse{
			ErrorCode:    pluginv1.HostCallbackErrorCode_HOST_TRANSIENT,
			ErrorMessage: fmt.Sprintf("kv delete %q: %v", uuid, err),
		}, nil
	}

	return &pluginv1.AckRevocationResponse{
		ErrorCode: pluginv1.HostCallbackErrorCode_HOST_OK,
	}, nil
}

// ── Type conversion helpers ───────────────────────────────────────────────────

// bindingToProto converts a CredentialBinding to its proto representation.
func bindingToProto(b binding.CredentialBinding) (*pluginv1.Binding, error) {
	ppStruct := mapToStruct(b.ProviderParams)

	dests := make([]*pluginv1.BindingDestinationSpec, len(b.Destinations))
	for i, d := range b.Destinations {
		dests[i] = &pluginv1.BindingDestinationSpec{
			Kind:     d.Kind,
			TargetId: d.TargetID,
			Params:   mapToStruct(d.Params),
		}
	}

	policy := &pluginv1.BindingRotationPolicy{
		TtlHintSeconds: b.RotationPolicy.TTLHintSeconds,
		ManualOnly:     b.RotationPolicy.ManualOnly,
	}

	pb := &pluginv1.Binding{
		Name:               b.Name,
		ProviderKind:       b.ProviderKind,
		ProviderParams:     ppStruct,
		Scope:              scopeToProto(b.Scope),
		Destinations:       dests,
		RotationPolicy:     policy,
		LastGeneration:     b.Metadata.LastGeneration,
		Tags:               b.Metadata.Tags,
		LastCredentialUuid: b.Metadata.LastCredentialUUID, //nolint:staticcheck // proto field name uses UUID not Uuid
	}

	if b.Metadata.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, b.Metadata.CreatedAt); err == nil {
			pb.CreatedAt = timestamppb.New(t)
		}
	}
	if b.Metadata.LastRotatedAt != "" {
		if t, err := time.Parse(time.RFC3339, b.Metadata.LastRotatedAt); err == nil {
			pb.LastRotatedAt = timestamppb.New(t)
		}
	}

	// Read binding_state directly from the struct field.
	pb.BindingState = b.Metadata.BindingState

	return pb, nil
}

// isBindingNotFound returns true for binding.ErrNotFound errors.
func isBindingNotFound(err error) bool {
	if err == nil {
		return false
	}
	return err == binding.ErrNotFound ||
		strings.Contains(err.Error(), "not found")
}

// isNotFoundKV returns true for KV-layer not-found errors.
func isNotFoundKV(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not found")
}

// isTransientError returns true when the error is a transient infrastructure failure.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unavailable") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "temporary")
}
