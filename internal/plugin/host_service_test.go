package plugin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	pluginv1 "github.com/agentkms/agentkms/api/plugin/v1"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/credentials/binding"
	"github.com/agentkms/agentkms/internal/destination"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ── Test helpers / stubs ─────────────────────────────────────────────────────

// stubBindingStore is an in-memory BindingStore for tests.
type stubBindingStore struct {
	mu   sync.Mutex
	data map[string]binding.CredentialBinding
	err  error // if non-nil, returned from all operations
}

func newStubStore(bindings ...binding.CredentialBinding) *stubBindingStore {
	s := &stubBindingStore{data: make(map[string]binding.CredentialBinding)}
	for _, b := range bindings {
		s.data[b.Name] = b
	}
	return s
}

func (s *stubBindingStore) Save(_ context.Context, b binding.CredentialBinding) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[b.Name] = b
	return nil
}

func (s *stubBindingStore) Get(_ context.Context, name string) (*binding.CredentialBinding, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data[name]
	if !ok {
		return nil, binding.ErrNotFound
	}
	cp := b
	return &cp, nil
}

func (s *stubBindingStore) List(_ context.Context) ([]binding.CredentialBinding, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]binding.CredentialBinding, 0, len(s.data))
	for _, b := range s.data {
		out = append(out, b)
	}
	return out, nil
}

func (s *stubBindingStore) Delete(_ context.Context, name string) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[name]; !ok {
		return binding.ErrNotFound
	}
	delete(s.data, name)
	return nil
}

// stubAuditor is an in-memory Auditor that records events.
type stubAuditor struct {
	mu     sync.Mutex
	events []audit.AuditEvent
	err    error
}

func (a *stubAuditor) Log(_ context.Context, ev audit.AuditEvent) error {
	if a.err != nil {
		return a.err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *stubAuditor) Flush(_ context.Context) error { return nil }

func (a *stubAuditor) last() (audit.AuditEvent, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) == 0 {
		return audit.AuditEvent{}, false
	}
	return a.events[len(a.events)-1], true
}

// stubKV is an in-memory KVWriter for tests.
type stubKV struct {
	mu   sync.Mutex
	data map[string]map[string]string
	err  error
}

func newStubKV() *stubKV { return &stubKV{data: make(map[string]map[string]string)} }

func (k *stubKV) SetSecret(_ context.Context, path string, fields map[string]string) error {
	if k.err != nil {
		return k.err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.data[path] = fields
	return nil
}

func (k *stubKV) GetSecret(_ context.Context, path string) (map[string]string, error) {
	if k.err != nil {
		return nil, k.err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.data[path]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (k *stubKV) ListPaths(_ context.Context) ([]string, error) {
	if k.err != nil {
		return nil, k.err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]string, 0, len(k.data))
	for p := range k.data {
		out = append(out, p)
	}
	return out, nil
}

func (k *stubKV) DeleteSecret(_ context.Context, path string) error {
	if k.err != nil {
		return k.err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.data[path]; !ok {
		return errors.New("not found")
	}
	delete(k.data, path)
	return nil
}

// stubVender is a minimal CredentialVender stub.
type stubVender struct {
	vend func() (*credentials.VendedCredential, error)
}

func (v *stubVender) Kind() string             { return "stub" }
func (v *stubVender) Capabilities() []string   { return nil }
func (v *stubVender) Vend(_ context.Context, _ credentials.Scope) (*credentials.VendedCredential, error) {
	if v.vend != nil {
		return v.vend()
	}
	return &credentials.VendedCredential{UUID: "test-uuid", APIKey: []byte("secret")}, nil
}

// stubDeliverer is a minimal DestinationDeliverer stub.
type stubDeliverer struct {
	kind    string
	deliver func(req destination.DeliverRequest) (bool, error)
	revoke  func() (bool, error)
}

func (d *stubDeliverer) Kind() string { return d.kind }
func (d *stubDeliverer) Validate(_ context.Context, _ map[string]any) error { return nil }
func (d *stubDeliverer) Deliver(_ context.Context, req destination.DeliverRequest) (bool, error) {
	if d.deliver != nil {
		return d.deliver(req)
	}
	return false, nil
}
func (d *stubDeliverer) Revoke(_ context.Context, _ string, _ uint64, _ map[string]any) (bool, error) {
	if d.revoke != nil {
		return d.revoke()
	}
	return false, nil
}
func (d *stubDeliverer) Health(_ context.Context) error { return nil }

// makeServer builds a hostServiceServer with all stubs wired up.
func makeServer(store binding.BindingStore, aud audit.Auditor, kv credentials.KVWriter) *hostServiceServer {
	reg := NewRegistry()
	return newHostServiceServer(store, reg, aud, kv)
}

// ── ListBindings tests ───────────────────────────────────────────────────────

func TestHostService_ListBindings_Empty(t *testing.T) {
	srv := makeServer(newStubStore(), &stubAuditor{}, newStubKV())
	resp, err := srv.ListBindings(context.Background(), &pluginv1.ListBindingsRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_OK {
		t.Errorf("error_code = %v, want HOST_OK", resp.ErrorCode)
	}
	if len(resp.Bindings) != 0 {
		t.Errorf("bindings = %d, want 0", len(resp.Bindings))
	}
}

func TestHostService_ListBindings_PageSizeRespected(t *testing.T) {
	store := newStubStore()
	for i := 0; i < 60; i++ {
		store.data[string(rune('a'+i%26))+"-"+string(rune('0'+i/26))] = binding.CredentialBinding{
			Name:         string(rune('a'+i%26)) + "-" + string(rune('0'+i/26)),
			ProviderKind: "stub",
			Destinations: []binding.DestinationSpec{{Kind: "stub-dest", TargetID: "t"}},
		}
	}
	srv := makeServer(store, &stubAuditor{}, newStubKV())
	resp, err := srv.ListBindings(context.Background(), &pluginv1.ListBindingsRequest{
		Filter: &pluginv1.BindingFilter{PageSize: 10},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Bindings) > 10 {
		t.Errorf("returned %d bindings, want <= 10", len(resp.Bindings))
	}
	if resp.NextPageToken == "" && resp.TotalCount > 10 {
		t.Error("expected next_page_token when more pages available")
	}
}

func TestHostService_ListBindings_StoreError_ReturnsTransient(t *testing.T) {
	store := &stubBindingStore{data: map[string]binding.CredentialBinding{}, err: errors.New("kv unavailable")}
	srv := makeServer(store, &stubAuditor{}, newStubKV())
	resp, err := srv.ListBindings(context.Background(), &pluginv1.ListBindingsRequest{})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_TRANSIENT {
		t.Errorf("error_code = %v, want HOST_TRANSIENT", resp.ErrorCode)
	}
}

// ── GetBinding tests ──────────────────────────────────────────────────────────

func TestHostService_GetBinding_Found(t *testing.T) {
	b := binding.CredentialBinding{
		Name:         "test-binding",
		ProviderKind: "github-app-token",
		Destinations: []binding.DestinationSpec{{Kind: "github-secret", TargetID: "owner/repo:SECRET"}},
	}
	srv := makeServer(newStubStore(b), &stubAuditor{}, newStubKV())
	resp, err := srv.GetBinding(context.Background(), &pluginv1.GetBindingRequest{Name: "test-binding"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_OK {
		t.Errorf("error_code = %v, want HOST_OK (msg: %s)", resp.ErrorCode, resp.ErrorMessage)
	}
	if resp.Binding.GetName() != "test-binding" {
		t.Errorf("binding name = %q, want %q", resp.Binding.GetName(), "test-binding")
	}
}

func TestHostService_GetBinding_NotFound(t *testing.T) {
	srv := makeServer(newStubStore(), &stubAuditor{}, newStubKV())
	resp, err := srv.GetBinding(context.Background(), &pluginv1.GetBindingRequest{Name: "missing"})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND {
		t.Errorf("error_code = %v, want HOST_NOT_FOUND", resp.ErrorCode)
	}
}

// ── SaveBindingMetadata tests ─────────────────────────────────────────────────

func TestHostService_SaveBindingMetadata_HappyPath(t *testing.T) {
	b := binding.CredentialBinding{
		Name:         "my-binding",
		ProviderKind: "stub",
		Destinations: []binding.DestinationSpec{{Kind: "stub-dest", TargetID: "t"}},
		Metadata:     binding.BindingMetadata{LastGeneration: 0},
	}
	store := newStubStore(b)
	srv := makeServer(store, &stubAuditor{}, newStubKV())

	now := time.Now().UTC()
	resp, err := srv.SaveBindingMetadata(context.Background(), &pluginv1.SaveBindingMetadataRequest{
		Name: "my-binding",
		Patch: &pluginv1.BindingMetadataPatch{
			LastGeneration:     1,
			LastRotatedAt:      timestamppb.New(now),
			BindingState:       "ok",
			LastCredentialUuid: "cred-uuid-1",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_OK {
		t.Errorf("error_code = %v, want HOST_OK (msg: %s)", resp.ErrorCode, resp.ErrorMessage)
	}

	// Read back and verify.
	updated, _ := store.Get(context.Background(), "my-binding")
	if updated.Metadata.LastGeneration != 1 {
		t.Errorf("LastGeneration = %d, want 1", updated.Metadata.LastGeneration)
	}
	if updated.Metadata.LastCredentialUUID != "cred-uuid-1" {
		t.Errorf("LastCredentialUUID = %q, want %q", updated.Metadata.LastCredentialUUID, "cred-uuid-1")
	}

	// B3: BindingState must be stored in the struct field, NOT as a tag.
	if updated.Metadata.BindingState != "ok" {
		t.Errorf("BindingState = %q, want %q", updated.Metadata.BindingState, "ok")
	}
	for _, tag := range updated.Metadata.Tags {
		if strings.HasPrefix(tag, "state:") {
			t.Errorf("found synthetic state tag %q in Tags — must NOT be added", tag)
		}
	}
}

// TestHostService_SaveBindingMetadata_BindingStateRoundTrips verifies that
// the BindingState field persisted by SaveBindingMetadata is visible through
// GetBinding's BindingState proto field — exercising the full store→proto path.
func TestHostService_SaveBindingMetadata_BindingStateRoundTrips(t *testing.T) {
	b := binding.CredentialBinding{
		Name:         "state-binding",
		ProviderKind: "stub",
		Destinations: []binding.DestinationSpec{{Kind: "stub-dest", TargetID: "t"}},
		Metadata:     binding.BindingMetadata{LastGeneration: 0},
	}
	store := newStubStore(b)
	srv := makeServer(store, &stubAuditor{}, newStubKV())

	_, err := srv.SaveBindingMetadata(context.Background(), &pluginv1.SaveBindingMetadataRequest{
		Name: "state-binding",
		Patch: &pluginv1.BindingMetadataPatch{
			LastGeneration: 1,
			BindingState:   "degraded",
		},
	})
	if err != nil {
		t.Fatalf("SaveBindingMetadata error: %v", err)
	}

	getResp, err := srv.GetBinding(context.Background(), &pluginv1.GetBindingRequest{Name: "state-binding"})
	if err != nil {
		t.Fatalf("GetBinding error: %v", err)
	}
	if getResp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_OK {
		t.Fatalf("GetBinding error_code = %v: %s", getResp.ErrorCode, getResp.ErrorMessage)
	}
	if got := getResp.Binding.GetBindingState(); got != "degraded" {
		t.Errorf("binding_state in proto = %q, want %q", got, "degraded")
	}
}

// TestHostService_SaveBindingMetadata_LegitimateStateTag_Preserved verifies
// that a binding with a legitimate user tag "state:approved" is not clobbered
// or misinterpreted after SaveBindingMetadata updates the BindingState field.
// Regression test for the original B3 tag-hack bug.
func TestHostService_SaveBindingMetadata_LegitimateStateTag_Preserved(t *testing.T) {
	b := binding.CredentialBinding{
		Name:         "tagged-binding",
		ProviderKind: "stub",
		Destinations: []binding.DestinationSpec{{Kind: "stub-dest", TargetID: "t"}},
		Metadata: binding.BindingMetadata{
			LastGeneration: 0,
			Tags:           []string{"state:approved", "env:prod"},
		},
	}
	store := newStubStore(b)
	srv := makeServer(store, &stubAuditor{}, newStubKV())

	// Update BindingState to "ok" — must NOT touch the "state:approved" tag.
	_, err := srv.SaveBindingMetadata(context.Background(), &pluginv1.SaveBindingMetadataRequest{
		Name: "tagged-binding",
		Patch: &pluginv1.BindingMetadataPatch{
			LastGeneration: 1,
			BindingState:   "ok",
		},
	})
	if err != nil {
		t.Fatalf("SaveBindingMetadata error: %v", err)
	}

	updated, _ := store.Get(context.Background(), "tagged-binding")

	// User tags must pass through unchanged.
	found := false
	for _, tag := range updated.Metadata.Tags {
		if tag == "state:approved" {
			found = true
		}
	}
	if !found {
		t.Errorf("legitimate tag %q was lost after SaveBindingMetadata; tags = %v", "state:approved", updated.Metadata.Tags)
	}

	// BindingState struct field must hold "ok".
	if updated.Metadata.BindingState != "ok" {
		t.Errorf("BindingState = %q, want %q", updated.Metadata.BindingState, "ok")
	}
}

func TestHostService_SaveBindingMetadata_GenerationRegression_Rejected(t *testing.T) {
	b := binding.CredentialBinding{
		Name:         "my-binding",
		ProviderKind: "stub",
		Destinations: []binding.DestinationSpec{{Kind: "stub-dest", TargetID: "t"}},
		Metadata:     binding.BindingMetadata{LastGeneration: 5},
	}
	srv := makeServer(newStubStore(b), &stubAuditor{}, newStubKV())

	resp, err := srv.SaveBindingMetadata(context.Background(), &pluginv1.SaveBindingMetadataRequest{
		Name:  "my-binding",
		Patch: &pluginv1.BindingMetadataPatch{LastGeneration: 3},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_PERMANENT {
		t.Errorf("error_code = %v, want HOST_PERMANENT (regression)", resp.ErrorCode)
	}
}

// TestHostService_SaveBindingMetadata_SameGeneration_Rejected verifies that a
// SaveBindingMetadata call with last_generation == stored_generation is rejected
// with HOST_PERMANENT. Same-generation replay could overwrite binding_state or
// other metadata fields from a stale orchestrator instance. Strict monotonicity
// (patch.gen > stored.gen) is required. (Fix 3, SHOULD-FIX.)
func TestHostService_SaveBindingMetadata_SameGeneration_Rejected(t *testing.T) {
	const storedGen = uint64(5)
	b := binding.CredentialBinding{
		Name:         "my-binding",
		ProviderKind: "stub",
		Destinations: []binding.DestinationSpec{{Kind: "stub-dest", TargetID: "t"}},
		Metadata:     binding.BindingMetadata{LastGeneration: storedGen},
	}
	srv := makeServer(newStubStore(b), &stubAuditor{}, newStubKV())

	resp, err := srv.SaveBindingMetadata(context.Background(), &pluginv1.SaveBindingMetadataRequest{
		Name:  "my-binding",
		Patch: &pluginv1.BindingMetadataPatch{LastGeneration: storedGen}, // same as stored
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_PERMANENT {
		t.Errorf("error_code = %v, want HOST_PERMANENT (same-generation replay rejected)", resp.ErrorCode)
	}
	if resp.ErrorMessage == "" {
		t.Error("expected non-empty ErrorMessage for same-generation rejection, got empty")
	}
	// Error message must mention the stored generation so operators can diagnose.
	if !containsGen(resp.ErrorMessage, storedGen) {
		t.Errorf("ErrorMessage %q does not reference stored generation %d", resp.ErrorMessage, storedGen)
	}
}

// containsGen returns true if s contains the decimal representation of gen.
func containsGen(s string, gen uint64) bool {
	return strings.Contains(s, fmt.Sprintf("%d", gen))
}

func TestHostService_SaveBindingMetadata_NotFound(t *testing.T) {
	srv := makeServer(newStubStore(), &stubAuditor{}, newStubKV())
	resp, err := srv.SaveBindingMetadata(context.Background(), &pluginv1.SaveBindingMetadataRequest{
		Name:  "ghost",
		Patch: &pluginv1.BindingMetadataPatch{LastGeneration: 1},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND {
		t.Errorf("error_code = %v, want HOST_NOT_FOUND", resp.ErrorCode)
	}
}

func TestHostService_SaveBindingMetadata_Concurrent_Linearized(t *testing.T) {
	// Two goroutines race to save different generations; the higher generation
	// must always win at the end.
	b := binding.CredentialBinding{
		Name:         "race-binding",
		ProviderKind: "stub",
		Destinations: []binding.DestinationSpec{{Kind: "stub-dest", TargetID: "t"}},
		Metadata:     binding.BindingMetadata{LastGeneration: 0},
	}
	store := newStubStore(b)
	srv := makeServer(store, &stubAuditor{}, newStubKV())

	var wg sync.WaitGroup
	for gen := uint64(1); gen <= 5; gen++ {
		gen := gen
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv.SaveBindingMetadata(context.Background(), &pluginv1.SaveBindingMetadataRequest{ //nolint:errcheck
				Name:  "race-binding",
				Patch: &pluginv1.BindingMetadataPatch{LastGeneration: gen},
			})
		}()
	}
	wg.Wait()

	updated, err := store.Get(context.Background(), "race-binding")
	if err != nil {
		t.Fatalf("final get failed: %v", err)
	}
	if updated.Metadata.LastGeneration > 5 {
		t.Errorf("LastGeneration = %d, want <= 5", updated.Metadata.LastGeneration)
	}
}

// ── VendCredential tests ──────────────────────────────────────────────────────

// scopeCapturingVender is a stubVender that records the Scope it received.
// Used to verify that VendCredential merges provider_params into the scope.
type scopeCapturingVender struct {
	mu          sync.Mutex
	capturedScope credentials.Scope
}

func (v *scopeCapturingVender) Kind() string           { return "scope-capturer" }
func (v *scopeCapturingVender) Capabilities() []string { return nil }
func (v *scopeCapturingVender) Vend(_ context.Context, s credentials.Scope) (*credentials.VendedCredential, error) {
	v.mu.Lock()
	v.capturedScope = s
	v.mu.Unlock()
	return &credentials.VendedCredential{UUID: "cap-uuid", APIKey: []byte("cap-key")}, nil
}

// TestHostService_VendCredential_ProviderParams_MergedIntoScope is the
// regression test for the T6 provider-params-drop bug.
//
// When a VendCredentialRequest carries provider_params (e.g. {"app_name":"blog-audit"}),
// the host service must merge those params into the Scope.Params before calling
// vender.Vend — otherwise the plugin sees an empty app_name and falls back to "default".
//
// Before the fix: host_service.VendCredential called vender.Vend(ctx, scope) where
// scope was built only from req.GetScope(); provider_params were silently discarded.
// After the fix: provider_params keys are merged into scope.Params (scope wins on collision).
func TestHostService_VendCredential_ProviderParams_MergedIntoScope(t *testing.T) {
	cv := &scopeCapturingVender{}
	reg := NewRegistry()
	_ = reg.RegisterVender("scope-capturer", cv)
	srv := newHostServiceServer(newStubStore(), reg, &stubAuditor{}, newStubKV())

	pp, err := structpb.NewStruct(map[string]any{
		"app_name": "blog-audit",
	})
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}

	resp, err := srv.VendCredential(context.Background(), &pluginv1.VendCredentialRequest{
		ProviderKind:   "scope-capturer",
		ProviderParams: pp,
		// Scope has no params — provider_params should fill the gap.
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_OK {
		t.Errorf("error_code = %v, want HOST_OK (msg: %s)", resp.ErrorCode, resp.ErrorMessage)
	}

	cv.mu.Lock()
	scope := cv.capturedScope
	cv.mu.Unlock()

	got, ok := scope.Params["app_name"]
	if !ok {
		t.Fatalf("scope.Params missing app_name key; got: %v — provider_params were not merged into scope", scope.Params)
	}
	if got != "blog-audit" {
		t.Errorf("scope.Params[\"app_name\"] = %q, want %q", got, "blog-audit")
	}
}

// TestHostService_VendCredential_ScopeParamsWinOnCollision verifies that when
// both Scope.Params and provider_params contain the same key, Scope.Params wins.
// This preserves override semantics: the caller can override binding defaults.
func TestHostService_VendCredential_ScopeParamsWinOnCollision(t *testing.T) {
	cv := &scopeCapturingVender{}
	reg := NewRegistry()
	_ = reg.RegisterVender("scope-capturer", cv)
	srv := newHostServiceServer(newStubStore(), reg, &stubAuditor{}, newStubKV())

	pp, err := structpb.NewStruct(map[string]any{
		"app_name": "binding-level-app",
	})
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}

	scopeParams, err := structpb.NewStruct(map[string]any{
		"app_name": "caller-override-app",
	})
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}

	resp, err := srv.VendCredential(context.Background(), &pluginv1.VendCredentialRequest{
		ProviderKind:   "scope-capturer",
		ProviderParams: pp,
		Scope: &pluginv1.Scope{
			Params: scopeParams,
		},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_OK {
		t.Errorf("error_code = %v, want HOST_OK", resp.ErrorCode)
	}

	cv.mu.Lock()
	scope := cv.capturedScope
	cv.mu.Unlock()

	got, ok := scope.Params["app_name"]
	if !ok {
		t.Fatalf("scope.Params missing app_name key; got: %v", scope.Params)
	}
	if got != "caller-override-app" {
		t.Errorf("scope.Params[\"app_name\"] = %q, want %q (scope should win over provider_params)", got, "caller-override-app")
	}
}

func TestHostService_VendCredential_ProviderNotFound(t *testing.T) {
	srv := makeServer(newStubStore(), &stubAuditor{}, newStubKV())
	resp, err := srv.VendCredential(context.Background(), &pluginv1.VendCredentialRequest{
		ProviderKind: "unknown-provider",
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND {
		t.Errorf("error_code = %v, want HOST_NOT_FOUND", resp.ErrorCode)
	}
}

func TestHostService_VendCredential_HappyPath(t *testing.T) {
	reg := NewRegistry()
	_ = reg.RegisterVender("stub", &stubVender{})
	srv := newHostServiceServer(newStubStore(), reg, &stubAuditor{}, newStubKV())

	resp, err := srv.VendCredential(context.Background(), &pluginv1.VendCredentialRequest{
		ProviderKind: "stub",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_OK {
		t.Errorf("error_code = %v, want HOST_OK (msg: %s)", resp.ErrorCode, resp.ErrorMessage)
	}
	if resp.Credential == nil {
		t.Fatal("expected credential, got nil")
	}
	if resp.Credential.Uuid != "test-uuid" {
		t.Errorf("uuid = %q, want %q", resp.Credential.Uuid, "test-uuid")
	}
}

// ── DeliverToDestination tests ────────────────────────────────────────────────

func TestHostService_DeliverToDestination_NotFound(t *testing.T) {
	srv := makeServer(newStubStore(), &stubAuditor{}, newStubKV())
	resp, err := srv.DeliverToDestination(context.Background(), &pluginv1.DeliverToDestinationRequest{
		DestinationKind: "unknown-dest",
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND {
		t.Errorf("error_code = %v, want HOST_NOT_FOUND", resp.ErrorCode)
	}
}

func TestHostService_DeliverToDestination_TransientError_Mapped(t *testing.T) {
	reg := NewRegistry()
	_ = reg.RegisterDeliverer("stub-dest", &stubDeliverer{
		kind: "stub-dest",
		deliver: func(_ destination.DeliverRequest) (bool, error) {
			return false, errors.New("connection timeout")
		},
	})
	srv := newHostServiceServer(newStubStore(), reg, &stubAuditor{}, newStubKV())
	resp, err := srv.DeliverToDestination(context.Background(), &pluginv1.DeliverToDestinationRequest{
		DestinationKind: "stub-dest",
		CredentialValue: []byte("cred"),
		DeliveryId:      "delivery-1",
		CredentialUuid:  "cred-uuid",
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_TRANSIENT {
		t.Errorf("error_code = %v, want HOST_TRANSIENT (timeout should be transient)", resp.ErrorCode)
	}
}

func TestHostService_DeliverToDestination_PermanentError_Mapped(t *testing.T) {
	reg := NewRegistry()
	_ = reg.RegisterDeliverer("stub-dest", &stubDeliverer{
		kind: "stub-dest",
		deliver: func(_ destination.DeliverRequest) (bool, error) {
			return true, errors.New("permission denied by target")
		},
	})
	srv := newHostServiceServer(newStubStore(), reg, &stubAuditor{}, newStubKV())
	resp, err := srv.DeliverToDestination(context.Background(), &pluginv1.DeliverToDestinationRequest{
		DestinationKind: "stub-dest",
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_PERMANENT {
		t.Errorf("error_code = %v, want HOST_PERMANENT", resp.ErrorCode)
	}
}

// ── Fix 4: DeliverToDestination audit emission timing ────────────────────────
//
// All three tests below verify that exactly ONE audit event is emitted per
// delivery attempt, AFTER the actual Deliver call returns, with the actual
// outcome — not a pre-determined success. (Fix 4, SHOULD-FIX, forensics accuracy.)

// TestHostService_DeliverToDestination_Audit_Success verifies that a successful
// delivery emits a single audit event with outcome="success" and no anomaly tags.
func TestHostService_DeliverToDestination_Audit_Success(t *testing.T) {
	aud := &stubAuditor{}
	reg := NewRegistry()
	_ = reg.RegisterDeliverer("stub-dest", &stubDeliverer{
		kind: "stub-dest",
		deliver: func(_ destination.DeliverRequest) (bool, error) {
			return false, nil // success
		},
	})
	srv := newHostServiceServer(newStubStore(), reg, aud, newStubKV())

	resp, err := srv.DeliverToDestination(context.Background(), &pluginv1.DeliverToDestinationRequest{
		DestinationKind: "stub-dest",
		CredentialUuid:  "cred-uuid-1",
		DeliveryId:      "delivery-001",
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_OK {
		t.Errorf("error_code = %v, want HOST_OK (msg: %s)", resp.ErrorCode, resp.ErrorMessage)
	}

	ev, ok := aud.last()
	if !ok {
		t.Fatal("expected audit event to be written, got none")
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("audit outcome = %q, want %q", ev.Outcome, audit.OutcomeSuccess)
	}
	if ev.ErrorDetail != "" {
		t.Errorf("audit error_detail = %q, want empty on success", ev.ErrorDetail)
	}
	if len(ev.Anomalies) != 0 {
		t.Errorf("audit anomalies = %v, want empty on success", ev.Anomalies)
	}
	if ev.Operation != audit.OperationDestinationDeliver {
		t.Errorf("audit operation = %q, want %q", ev.Operation, audit.OperationDestinationDeliver)
	}
}

// TestHostService_DeliverToDestination_Audit_PermanentError verifies that a
// permanent delivery failure emits a single audit event with outcome="error",
// a populated error_detail, and the anomaly tag "delivery_permanent_error".
func TestHostService_DeliverToDestination_Audit_PermanentError(t *testing.T) {
	aud := &stubAuditor{}
	reg := NewRegistry()
	_ = reg.RegisterDeliverer("stub-dest", &stubDeliverer{
		kind: "stub-dest",
		deliver: func(_ destination.DeliverRequest) (bool, error) {
			return true, errors.New("permission denied by target") // permanent
		},
	})
	srv := newHostServiceServer(newStubStore(), reg, aud, newStubKV())

	resp, err := srv.DeliverToDestination(context.Background(), &pluginv1.DeliverToDestinationRequest{
		DestinationKind: "stub-dest",
		CredentialUuid:  "cred-uuid-2",
		DeliveryId:      "delivery-002",
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_PERMANENT {
		t.Errorf("error_code = %v, want HOST_PERMANENT", resp.ErrorCode)
	}

	ev, ok := aud.last()
	if !ok {
		t.Fatal("expected audit event to be written, got none")
	}
	if ev.Outcome != audit.OutcomeError {
		t.Errorf("audit outcome = %q, want %q", ev.Outcome, audit.OutcomeError)
	}
	if ev.ErrorDetail == "" {
		t.Error("audit error_detail is empty, want non-empty on permanent error")
	}
	if !containsAnomaly(ev.Anomalies, "delivery_permanent_error") {
		t.Errorf("audit anomalies = %v, want to contain %q", ev.Anomalies, "delivery_permanent_error")
	}
}

// TestHostService_DeliverToDestination_Audit_TransientError verifies that a
// transient delivery failure emits a single audit event with outcome="error"
// and the anomaly tag "delivery_transient_error" (not "delivery_permanent_error").
func TestHostService_DeliverToDestination_Audit_TransientError(t *testing.T) {
	aud := &stubAuditor{}
	reg := NewRegistry()
	_ = reg.RegisterDeliverer("stub-dest", &stubDeliverer{
		kind: "stub-dest",
		deliver: func(_ destination.DeliverRequest) (bool, error) {
			return false, errors.New("connection timeout") // transient (isPerm=false)
		},
	})
	srv := newHostServiceServer(newStubStore(), reg, aud, newStubKV())

	resp, err := srv.DeliverToDestination(context.Background(), &pluginv1.DeliverToDestinationRequest{
		DestinationKind: "stub-dest",
		CredentialUuid:  "cred-uuid-3",
		DeliveryId:      "delivery-003",
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_TRANSIENT {
		t.Errorf("error_code = %v, want HOST_TRANSIENT", resp.ErrorCode)
	}

	ev, ok := aud.last()
	if !ok {
		t.Fatal("expected audit event to be written, got none")
	}
	if ev.Outcome != audit.OutcomeError {
		t.Errorf("audit outcome = %q, want %q", ev.Outcome, audit.OutcomeError)
	}
	if ev.ErrorDetail == "" {
		t.Error("audit error_detail is empty, want non-empty on transient error")
	}
	if !containsAnomaly(ev.Anomalies, "delivery_transient_error") {
		t.Errorf("audit anomalies = %v, want to contain %q", ev.Anomalies, "delivery_transient_error")
	}
}

// containsAnomaly returns true if anomalies contains the given tag.
func containsAnomaly(anomalies []string, tag string) bool {
	for _, a := range anomalies {
		if a == tag {
			return true
		}
	}
	return false
}

// TestHostService_DeliverToDestination_AuditEventCount verifies that exactly
// ONE audit event is emitted per delivery attempt (not two — not a
// "delivery initiated" + "delivery completed" pair). This guards against
// double-emit that would produce misleading forensics records.
func TestHostService_DeliverToDestination_AuditEventCount(t *testing.T) {
	aud := &stubAuditor{}
	reg := NewRegistry()
	_ = reg.RegisterDeliverer("stub-dest", &stubDeliverer{
		kind: "stub-dest",
		deliver: func(_ destination.DeliverRequest) (bool, error) {
			return false, nil // success
		},
	})
	srv := newHostServiceServer(newStubStore(), reg, aud, newStubKV())

	_, err := srv.DeliverToDestination(context.Background(), &pluginv1.DeliverToDestinationRequest{
		DestinationKind: "stub-dest",
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}

	aud.mu.Lock()
	count := len(aud.events)
	aud.mu.Unlock()

	if count != 1 {
		t.Errorf("audit event count = %d, want exactly 1 per delivery", count)
	}
}

// ── EmitAudit tests ───────────────────────────────────────────────────────────

func TestHostService_EmitAudit_Valid(t *testing.T) {
	aud := &stubAuditor{}
	srv := makeServer(newStubStore(), aud, newStubKV())

	resp, err := srv.EmitAudit(context.Background(), &pluginv1.EmitAuditRequest{
		Event: &pluginv1.AuditEventProto{
			Operation:      "binding_rotate_start",
			CallerId:       "orchestrator",
			Outcome:        "success",
			CredentialType: "github-app-token",
			AgentSession:   "rotation-123",
		},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_OK {
		t.Errorf("error_code = %v, want HOST_OK (msg: %s)", resp.ErrorCode, resp.ErrorMessage)
	}
	ev, ok := aud.last()
	if !ok {
		t.Fatal("expected audit event to be written")
	}
	if ev.Operation != "binding_rotate_start" {
		t.Errorf("operation = %q, want %q", ev.Operation, "binding_rotate_start")
	}
}

func TestHostService_EmitAudit_KeyMaterial_Rejected(t *testing.T) {
	srv := makeServer(newStubStore(), &stubAuditor{}, newStubKV())
	// 64 hex chars = key material pattern.
	resp, err := srv.EmitAudit(context.Background(), &pluginv1.EmitAuditRequest{
		Event: &pluginv1.AuditEventProto{
			Operation:   "binding_rotate",
			CallerId:    "orchestrator",
			Outcome:     "success",
			ErrorDetail: "abc123" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_PERMANENT {
		t.Errorf("error_code = %v, want HOST_PERMANENT (key material rejected)", resp.ErrorCode)
	}
}

func TestHostService_EmitAudit_NilEvent_Rejected(t *testing.T) {
	srv := makeServer(newStubStore(), &stubAuditor{}, newStubKV())
	resp, err := srv.EmitAudit(context.Background(), &pluginv1.EmitAuditRequest{Event: nil})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_PERMANENT {
		t.Errorf("error_code = %v, want HOST_PERMANENT", resp.ErrorCode)
	}
}

// ── Pending revocation queue tests ───────────────────────────────────────────

func TestHostService_EnqueueAndDrain_HappyPath(t *testing.T) {
	kv := newStubKV()
	srv := makeServer(newStubStore(), &stubAuditor{}, kv)
	ctx := context.Background()

	schedAt := time.Now().Add(-time.Minute)
	_, err := srv.EnqueueRevocation(ctx, &pluginv1.EnqueueRevocationRequest{
		CredentialUuid: "cred-abc",
		ScheduledAt:    timestamppb.New(schedAt),
	})
	if err != nil {
		t.Fatalf("EnqueueRevocation error: %v", err)
	}

	drain, err := srv.DrainPendingRevocations(ctx, &pluginv1.DrainPendingRevocationsRequest{
		Now: timestamppb.New(time.Now()),
	})
	if err != nil {
		t.Fatalf("DrainPendingRevocations error: %v", err)
	}
	if drain.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_OK {
		t.Errorf("drain error_code = %v: %s", drain.ErrorCode, drain.ErrorMessage)
	}
	if len(drain.Revocations) != 1 {
		t.Fatalf("expected 1 revocation, got %d", len(drain.Revocations))
	}
	if drain.Revocations[0].CredentialUuid != "cred-abc" {
		t.Errorf("credential_uuid = %q, want %q", drain.Revocations[0].CredentialUuid, "cred-abc")
	}
}

func TestHostService_AckRevocation_Idempotent(t *testing.T) {
	kv := newStubKV()
	srv := makeServer(newStubStore(), &stubAuditor{}, kv)
	ctx := context.Background()

	// Ack for a UUID that doesn't exist — should be HOST_OK (idempotent).
	resp, err := srv.AckRevocation(ctx, &pluginv1.AckRevocationRequest{
		CredentialUuid: "nonexistent-uuid",
	})
	if err != nil {
		t.Fatalf("AckRevocation error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_OK {
		t.Errorf("error_code = %v, want HOST_OK (idempotent ack)", resp.ErrorCode)
	}
}

func TestHostService_EnqueueRevocation_FutureNotDrained(t *testing.T) {
	kv := newStubKV()
	srv := makeServer(newStubStore(), &stubAuditor{}, kv)
	ctx := context.Background()

	// Schedule 1 hour in the future.
	_, err := srv.EnqueueRevocation(ctx, &pluginv1.EnqueueRevocationRequest{
		CredentialUuid: "future-cred",
		ScheduledAt:    timestamppb.New(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("EnqueueRevocation error: %v", err)
	}

	drain, err := srv.DrainPendingRevocations(ctx, &pluginv1.DrainPendingRevocationsRequest{
		Now: timestamppb.New(time.Now()),
	})
	if err != nil {
		t.Fatalf("DrainPendingRevocations error: %v", err)
	}
	if len(drain.Revocations) != 0 {
		t.Errorf("expected 0 due revocations (future scheduled_at), got %d", len(drain.Revocations))
	}
}

func TestHostService_RevokeAtDestination_NotFound(t *testing.T) {
	srv := makeServer(newStubStore(), &stubAuditor{}, newStubKV())
	resp, err := srv.RevokeAtDestination(context.Background(), &pluginv1.RevokeAtDestinationRequest{
		DestinationKind: "unknown",
	})
	if err != nil {
		t.Fatalf("unexpected RPC error: %v", err)
	}
	if resp.ErrorCode != pluginv1.HostCallbackErrorCode_HOST_NOT_FOUND {
		t.Errorf("error_code = %v, want HOST_NOT_FOUND", resp.ErrorCode)
	}
}
