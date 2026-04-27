package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/credentials/binding"
	"github.com/agentkms/agentkms/internal/destination/noop"
	"github.com/agentkms/agentkms/internal/plugin"
	"github.com/agentkms/agentkms/internal/webhooks"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// newBindingServer creates an allow-all Server with an in-memory binding store
// and a destination registry pre-seeded with a no-op deliverer for "github-secret"
// (the kind used by minimalBinding).
func newBindingServer(t *testing.T) (*api.Server, *capturingAuditor, binding.BindingStore) {
	t.Helper()
	b := backend.NewDevBackend()
	srv, aud := newAllowServer(t, b)
	store := binding.NewKVBindingStore(newBindingMemKV())
	srv.SetBindingStore(store)

	// Wire a destination registry so rotate tests exercise the real dispatch path.
	reg := plugin.NewRegistry()
	if err := reg.RegisterDeliverer("github-secret", noop.NewNoopDeliverer()); err != nil {
		t.Fatalf("RegisterDeliverer: %v", err)
	}
	srv.SetDestinationRegistry(reg)

	return srv, aud, store
}

func bindingRequest(t *testing.T, srv http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	return request(t, srv, method, path, bodyReader)
}

// minimalBinding returns a valid CredentialBinding for testing.
func minimalBinding(name string) binding.CredentialBinding {
	return binding.CredentialBinding{
		Name:         name,
		ProviderKind: "github-app-token",
		Scope: credentials.Scope{
			Kind: "llm-session",
		},
		Destinations: []binding.DestinationSpec{
			{Kind: "github-secret", TargetID: "owner/repo:MY_SECRET"},
		},
		RotationPolicy: binding.RotationPolicy{ManualOnly: true},
	}
}

// ── POST /bindings ────────────────────────────────────────────────────────────

func TestHandleRegisterBinding_OK(t *testing.T) {
	srv, aud, _ := newBindingServer(t)

	rr := bindingRequest(t, srv, http.MethodPost, "/bindings", minimalBinding("my-binding"))
	assertStatus(t, rr, http.StatusCreated)
	assertContentTypeJSON(t, rr)

	var got binding.CredentialBinding
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Name != "my-binding" {
		t.Errorf("name: got %q want %q", got.Name, "my-binding")
	}

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.Operation != audit.OperationBindingRegister {
		t.Errorf("audit operation: got %q want %q", ev.Operation, audit.OperationBindingRegister)
	}
	if ev.Outcome != audit.OutcomeSuccess {
		t.Errorf("audit outcome: got %q want success", ev.Outcome)
	}
}

func TestHandleRegisterBinding_InvalidName(t *testing.T) {
	srv, _, _ := newBindingServer(t)
	b := minimalBinding("INVALID_NAME")
	rr := bindingRequest(t, srv, http.MethodPost, "/bindings", b)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestHandleRegisterBinding_NoDestinations(t *testing.T) {
	srv, _, _ := newBindingServer(t)
	b := minimalBinding("no-dests")
	b.Destinations = nil
	rr := bindingRequest(t, srv, http.MethodPost, "/bindings", b)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestHandleRegisterBinding_InvalidDestKind(t *testing.T) {
	srv, _, _ := newBindingServer(t)
	b := minimalBinding("bad-dest")
	b.Destinations = []binding.DestinationSpec{{Kind: "BAD_KIND", TargetID: "x"}}
	rr := bindingRequest(t, srv, http.MethodPost, "/bindings", b)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestHandleRegisterBinding_NoStore(t *testing.T) {
	b := backend.NewDevBackend()
	srv, _ := newAllowServer(t, b)
	// No SetBindingStore — expect 503.
	rr := bindingRequest(t, srv, http.MethodPost, "/bindings", minimalBinding("x"))
	assertStatus(t, rr, http.StatusServiceUnavailable)
}

func TestHandleRegisterBinding_Unauthorized(t *testing.T) {
	b := backend.NewDevBackend()
	srv, _ := newAllowServer(t, b)
	srv.SetBindingStore(binding.NewKVBindingStore(newBindingMemKV()))

	// Do NOT inject identity — raw request bypasses auth helper.
	body, _ := json.Marshal(minimalBinding("unauth"))
	req := httptest.NewRequest(http.MethodPost, "/bindings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// ── GET /bindings ─────────────────────────────────────────────────────────────

func TestHandleListBindings_Empty(t *testing.T) {
	srv, _, _ := newBindingServer(t)
	rr := request(t, srv, http.MethodGet, "/bindings", nil)
	assertStatus(t, rr, http.StatusOK)

	var body struct {
		Bindings []binding.BindingSummary `json:"bindings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Bindings) != 0 {
		t.Errorf("expected 0 bindings, got %d", len(body.Bindings))
	}
}

func TestHandleListBindings_AfterRegister(t *testing.T) {
	srv, _, _ := newBindingServer(t)
	for _, name := range []string{"alpha", "beta"} {
		bindingRequest(t, srv, http.MethodPost, "/bindings", minimalBinding(name))
	}

	rr := request(t, srv, http.MethodGet, "/bindings", nil)
	assertStatus(t, rr, http.StatusOK)

	var body struct {
		Bindings []binding.BindingSummary `json:"bindings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Bindings) != 2 {
		t.Errorf("expected 2 bindings, got %d", len(body.Bindings))
	}
}

func TestHandleListBindings_Unauthorized(t *testing.T) {
	b := backend.NewDevBackend()
	srv, _ := newAllowServer(t, b)
	srv.SetBindingStore(binding.NewKVBindingStore(newBindingMemKV()))

	req := httptest.NewRequest(http.MethodGet, "/bindings", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// ── GET /bindings/{name} ──────────────────────────────────────────────────────

func TestHandleGetBinding_OK(t *testing.T) {
	srv, _, _ := newBindingServer(t)
	bindingRequest(t, srv, http.MethodPost, "/bindings", minimalBinding("inspect-me"))

	rr := request(t, srv, http.MethodGet, "/bindings/inspect-me", nil)
	assertStatus(t, rr, http.StatusOK)

	var got binding.CredentialBinding
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Name != "inspect-me" {
		t.Errorf("name: got %q", got.Name)
	}
}

func TestHandleGetBinding_NotFound(t *testing.T) {
	srv, _, _ := newBindingServer(t)
	rr := request(t, srv, http.MethodGet, "/bindings/does-not-exist", nil)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestHandleGetBinding_Unauthorized(t *testing.T) {
	b := backend.NewDevBackend()
	srv, _ := newAllowServer(t, b)
	srv.SetBindingStore(binding.NewKVBindingStore(newBindingMemKV()))

	req := httptest.NewRequest(http.MethodGet, "/bindings/any-name", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// ── DELETE /bindings/{name} ───────────────────────────────────────────────────

func TestHandleDeleteBinding_OK(t *testing.T) {
	srv, aud, _ := newBindingServer(t)
	bindingRequest(t, srv, http.MethodPost, "/bindings", minimalBinding("to-delete"))

	rr := request(t, srv, http.MethodDelete, "/bindings/to-delete", nil)
	assertStatus(t, rr, http.StatusNoContent)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event")
	}
	if ev.Operation != audit.OperationBindingDelete {
		t.Errorf("audit op: got %q", ev.Operation)
	}

	// Confirm gone.
	rr2 := request(t, srv, http.MethodGet, "/bindings/to-delete", nil)
	assertStatus(t, rr2, http.StatusNotFound)
}

func TestHandleDeleteBinding_NotFound(t *testing.T) {
	srv, _, _ := newBindingServer(t)
	rr := request(t, srv, http.MethodDelete, "/bindings/nonexistent", nil)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestHandleDeleteBinding_Unauthorized(t *testing.T) {
	b := backend.NewDevBackend()
	srv, _ := newAllowServer(t, b)
	srv.SetBindingStore(binding.NewKVBindingStore(newBindingMemKV()))

	req := httptest.NewRequest(http.MethodDelete, "/bindings/any-name", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// ── POST /bindings/{name}/rotate ──────────────────────────────────────────────

func TestHandleRotateBinding_OK(t *testing.T) {
	srv, aud, _ := newBindingServer(t)
	bindingRequest(t, srv, http.MethodPost, "/bindings", minimalBinding("rotate-me"))

	rr := bindingRequest(t, srv, http.MethodPost, "/bindings/rotate-me/rotate", nil)
	assertStatus(t, rr, http.StatusOK)

	var got struct {
		Name       string                      `json:"name"`
		Generation uint64                      `json:"generation"`
		RotatedAt  string                      `json:"rotated_at"`
		Results    []binding.DestinationResult `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Name != "rotate-me" {
		t.Errorf("name: got %q", got.Name)
	}
	if got.Generation != 1 {
		t.Errorf("generation: got %d want 1", got.Generation)
	}
	if len(got.Results) != 1 {
		t.Fatalf("results: got %d want 1", len(got.Results))
	}
	if !got.Results[0].Success {
		t.Errorf("destination result: expected success")
	}

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event")
	}
	if ev.Operation != audit.OperationBindingRotate {
		t.Errorf("audit op: got %q want %q", ev.Operation, audit.OperationBindingRotate)
	}
}

func TestHandleRotateBinding_NotFound(t *testing.T) {
	srv, _, _ := newBindingServer(t)
	rr := bindingRequest(t, srv, http.MethodPost, "/bindings/nonexistent/rotate", nil)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestHandleRotateBinding_GenerationIncrement(t *testing.T) {
	srv, _, _ := newBindingServer(t)
	bindingRequest(t, srv, http.MethodPost, "/bindings", minimalBinding("gen-test"))

	var r1, r2 struct {
		Generation uint64 `json:"generation"`
	}

	rr1 := bindingRequest(t, srv, http.MethodPost, "/bindings/gen-test/rotate", nil)
	if err := json.Unmarshal(rr1.Body.Bytes(), &r1); err != nil {
		t.Fatalf("decode r1: %v", err)
	}
	if r1.Generation != 1 {
		t.Errorf("first rotation: got generation %d want 1", r1.Generation)
	}

	rr2 := bindingRequest(t, srv, http.MethodPost, "/bindings/gen-test/rotate", nil)
	if err := json.Unmarshal(rr2.Body.Bytes(), &r2); err != nil {
		t.Fatalf("decode r2: %v", err)
	}
	if r2.Generation != 2 {
		t.Errorf("second rotation: got generation %d want 2", r2.Generation)
	}
}

func TestHandleRotateBinding_Unauthorized(t *testing.T) {
	b := backend.NewDevBackend()
	srv, _ := newAllowServer(t, b)
	srv.SetBindingStore(binding.NewKVBindingStore(newBindingMemKV()))

	req := httptest.NewRequest(http.MethodPost, "/bindings/any/rotate", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// ── POST /bindings/{name}/rotate — stub path audit marker ─────────────────────

// TestHandleRotateBinding_StubPathAuditMarker verifies that when the rotate
// handler takes the stub credential path (provider not in Vender's supported
// list, no real credential vended), it emits an audit event with operation
// OperationBindingRotateStub so forensics queries can distinguish real
// rotations from stub-path no-op rotations.
//
// Setup: newBindingServer already registers a noop deliverer for "github-secret"
// so the destination side succeeds. The binding's provider_kind is
// "github-app-token", which is not in the default Vender's SupportedProviders
// list, so the stub path is taken.
func TestHandleRotateBinding_StubPathAuditMarker(t *testing.T) {
	srv, aud, _ := newBindingServer(t)

	// Register and then rotate a binding whose provider_kind triggers the stub path.
	b := minimalBinding("stub-audit-test")
	// provider_kind "github-app-token" is not an LLM provider; Vender.Vend will
	// fail → stub path taken. The destination kind "github-secret" IS registered
	// in newBindingServer so the delivery side succeeds.
	bindingRequest(t, srv, http.MethodPost, "/bindings", b)

	rr := bindingRequest(t, srv, http.MethodPost, "/bindings/stub-audit-test/rotate", nil)
	assertStatus(t, rr, http.StatusOK)

	// Scan all recorded events for the stub marker.
	aud.mu.Lock()
	events := make([]audit.AuditEvent, len(aud.events))
	copy(events, aud.events)
	aud.mu.Unlock()

	var foundStub bool
	for _, ev := range events {
		if ev.Operation == audit.OperationBindingRotateStub {
			foundStub = true
			// Verify the stub event carries the binding key.
			if ev.KeyID != "bindings/stub-audit-test" {
				t.Errorf("stub audit event KeyID = %q, want %q", ev.KeyID, "bindings/stub-audit-test")
			}
			if ev.Outcome != audit.OutcomeSuccess {
				t.Errorf("stub audit event Outcome = %q, want %q", ev.Outcome, audit.OutcomeSuccess)
			}
			if ev.ErrorDetail == "" {
				t.Error("stub audit event ErrorDetail is empty, want provider_kind explanation")
			}
			break
		}
	}

	if !foundStub {
		t.Errorf("no %q audit event found after stub-path rotate; operations seen: %v",
			audit.OperationBindingRotateStub, operationNames(events))
	}
}

// ── POST /bindings/{name}/rotate — Pro orchestrator delegation ────────────────

// TestHandleRotateBinding_OrchestratorDelegation verifies that when a Pro
// RotationHook is wired to the Server's AlertOrchestrator, POST
// /bindings/{name}/rotate delegates to hook.RotateBinding rather than taking
// the OSS stub credential path.
//
// Assertions:
//   - HTTP 200 is returned
//   - hook.RotateBinding was called with the correct binding name
//   - No binding_rotate_stub audit event is emitted
//   - A binding_rotate audit event IS emitted with OutcomeSuccess
func TestHandleRotateBinding_OrchestratorDelegation(t *testing.T) {
	srv, aud, _ := newBindingServer(t)

	// Wire up an AlertOrchestrator with a stubRotationHook.
	orch := webhooks.NewAlertOrchestrator(nil, nil, nil, nil)
	hook := &stubRotationHook{}
	orch.SetRotationHook(hook)
	srv.SetAlertOrchestrator(orch)

	// Register and rotate a binding.
	bindingRequest(t, srv, http.MethodPost, "/bindings", minimalBinding("orch-delegate-test"))
	rr := bindingRequest(t, srv, http.MethodPost, "/bindings/orch-delegate-test/rotate", nil)
	assertStatus(t, rr, http.StatusOK)

	// Verify the hook was invoked.
	hook.mu.Lock()
	rotateCalls := make([]string, len(hook.rotateCalls))
	copy(rotateCalls, hook.rotateCalls)
	hook.mu.Unlock()

	if len(rotateCalls) != 1 {
		t.Fatalf("hook.RotateBinding call count: got %d, want 1", len(rotateCalls))
	}
	if rotateCalls[0] != "orch-delegate-test" {
		t.Errorf("hook.RotateBinding called with %q, want %q", rotateCalls[0], "orch-delegate-test")
	}

	// Verify audit events: must have binding_rotate, must NOT have binding_rotate_stub.
	aud.mu.Lock()
	events := make([]audit.AuditEvent, len(aud.events))
	copy(events, aud.events)
	aud.mu.Unlock()

	var foundRotate, foundStub bool
	for _, ev := range events {
		switch ev.Operation {
		case audit.OperationBindingRotate:
			foundRotate = true
			if ev.Outcome != audit.OutcomeSuccess {
				t.Errorf("binding_rotate audit Outcome = %q, want %q", ev.Outcome, audit.OutcomeSuccess)
			}
		case audit.OperationBindingRotateStub:
			foundStub = true
		}
	}
	if !foundRotate {
		t.Errorf("no %q audit event found; operations seen: %v", audit.OperationBindingRotate, operationNames(events))
	}
	if foundStub {
		t.Errorf("unexpected %q audit event: stub path must NOT be taken when orchestrator hook is wired", audit.OperationBindingRotateStub)
	}
}

// TestHandleRotateBinding_OrchestratorDelegation_HookError verifies that when
// the hook returns an error, the handler returns HTTP 500 and emits a
// binding_rotate audit event with OutcomeError (not OutcomeSuccess).
func TestHandleRotateBinding_OrchestratorDelegation_HookError(t *testing.T) {
	srv, aud, _ := newBindingServer(t)

	orch := webhooks.NewAlertOrchestrator(nil, nil, nil, nil)
	hook := &stubRotationHook{rotateErr: context.DeadlineExceeded}
	orch.SetRotationHook(hook)
	srv.SetAlertOrchestrator(orch)

	bindingRequest(t, srv, http.MethodPost, "/bindings", minimalBinding("orch-err-test"))
	rr := bindingRequest(t, srv, http.MethodPost, "/bindings/orch-err-test/rotate", nil)
	assertStatus(t, rr, http.StatusInternalServerError)

	aud.mu.Lock()
	events := make([]audit.AuditEvent, len(aud.events))
	copy(events, aud.events)
	aud.mu.Unlock()

	var foundError bool
	for _, ev := range events {
		if ev.Operation == audit.OperationBindingRotate && ev.Outcome == audit.OutcomeError {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Errorf("expected binding_rotate audit event with OutcomeError; operations seen: %v", operationNames(events))
	}
}

// ── Audit constants compile-check ─────────────────────────────────────────────

var (
	_ = audit.OperationBindingRegister
	_ = audit.OperationBindingRotate
	_ = audit.OperationBindingDelete
	_ = audit.OperationBindingRotateStub
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// operationNames extracts the Operation field from a slice of AuditEvents for
// use in test failure messages.
func operationNames(events []audit.AuditEvent) []string {
	names := make([]string, len(events))
	for i, ev := range events {
		names[i] = ev.Operation
	}
	return names
}

// ── In-memory KV for binding handler tests ────────────────────────────────────

type bindingMemKV struct {
	data map[string]map[string]string
}

func newBindingMemKV() credentials.KVWriter {
	return &bindingMemKV{data: make(map[string]map[string]string)}
}

func (m *bindingMemKV) GetSecret(_ context.Context, path string) (map[string]string, error) {
	v, ok := m.data[path]
	if !ok {
		return nil, credentials.ErrCredentialNotFound
	}
	out := make(map[string]string, len(v))
	for k, val := range v {
		out[k] = val
	}
	return out, nil
}

func (m *bindingMemKV) SetSecret(_ context.Context, path string, fields map[string]string) error {
	cp := make(map[string]string, len(fields))
	for k, v := range fields {
		cp[k] = v
	}
	m.data[path] = cp
	return nil
}

func (m *bindingMemKV) DeleteSecret(_ context.Context, path string) error {
	delete(m.data, path)
	return nil
}

func (m *bindingMemKV) ListPaths(_ context.Context) ([]string, error) {
	paths := make([]string, 0, len(m.data))
	for p := range m.data {
		paths = append(paths, p)
	}
	return paths, nil
}
