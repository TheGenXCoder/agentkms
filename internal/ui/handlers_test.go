package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
)

func TestHandleListKeys(t *testing.T) {
	bknd := backend.NewDevBackend()
	// Create a key so there's something to list.
	_ = bknd.CreateKey("test-key", backend.AlgorithmAES256GCM, "test-team")

	h := &Handlers{
		Backend: bknd,
	}

	req := httptest.NewRequest("GET", "/ui/api/keys", nil)
	w := httptest.NewRecorder()
	h.HandleListKeys(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Code)
	}

	var metas []backend.KeyMeta
	if err := json.NewDecoder(w.Body).Decode(&metas); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if len(metas) != 1 || metas[0].KeyID != "test-key" {
		t.Errorf("unexpected key list: %+v", metas)
	}
}

func TestHandleGetPolicy(t *testing.T) {
	p := policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{ID: "test-rule", Effect: policy.EffectAllow},
		},
	}
	eng := policy.New(p)
	h := &Handlers{
		Policy: policy.AsEngineI(eng),
	}

	req := httptest.NewRequest("GET", "/ui/api/policy", nil)
	w := httptest.NewRecorder()
	h.HandleGetPolicy(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Code)
	}

	if w.Header().Get("Content-Type") != "application/x-yaml" {
		t.Errorf("expected YAML content type, got %s", w.Header().Get("Content-Type"))
	}
}

func TestHandleUpdatePolicy(t *testing.T) {
	eng := policy.New(policy.Policy{Version: "1"})
	h := &Handlers{
		Policy: policy.AsEngineI(eng),
	}

	yamlData := `
version: "1"
rules:
  - id: new-rule
    effect: allow
`
	req := httptest.NewRequest("PUT", "/ui/api/policy", bytes.NewBufferString(yamlData))
	w := httptest.NewRecorder()
	h.HandleUpdatePolicy(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 No Content, got %d: %s", w.Code, w.Body.String())
	}

	updated := h.Policy.GetPolicy()
	if len(updated.Rules) != 1 || updated.Rules[0].ID != "new-rule" {
		t.Errorf("policy was not updated: %+v", updated)
	}
}

func TestHandleListAudit(t *testing.T) {
	// Need an auditor that supports Export.
	sink, _ := audit.NewFileAuditSink(t.TempDir() + "/audit.log")
	// Log something to the file sink.
	ev, _ := audit.New()
	ev.Operation = "test-op"
	ev.Outcome = "success"
	ev.Timestamp = time.Now().UTC()
	_ = sink.Log(context.Background(), ev)

	h := &Handlers{
		Auditor: sink,
	}

	req := httptest.NewRequest("GET", "/ui/api/audit", nil)
	w := httptest.NewRecorder()
	h.HandleListAudit(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Code)
	}

	var events []audit.AuditEvent
	if err := json.NewDecoder(w.Body).Decode(&events); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if len(events) < 1 {
		t.Errorf("expected at least 1 audit event, got %d", len(events))
	}
}

type mockBackend struct {
	backend.Backend
	listKeysErr error
}

func (m *mockBackend) ListKeys(ctx context.Context, scope backend.KeyScope) ([]*backend.KeyMeta, error) {
	if m.listKeysErr != nil {
		return nil, m.listKeysErr
	}
	return m.Backend.ListKeys(ctx, scope)
}

func TestHandleListKeys_Error(t *testing.T) {
	errBackend := &mockBackend{
		Backend:     backend.NewDevBackend(),
		listKeysErr: context.DeadlineExceeded,
	}

	h := &Handlers{Backend: errBackend}

	req := httptest.NewRequest("GET", "/ui/api/keys", nil)
	w := httptest.NewRecorder()
	h.HandleListKeys(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error, got %d", w.Code)
	}
}

type nullAud struct{}
func (n nullAud) Log(ctx context.Context, ev audit.AuditEvent) error { return nil }
func (n nullAud) Flush(ctx context.Context) error { return nil }

func TestHandleListAudit_NotSupported(t *testing.T) {
	h := &Handlers{
		Auditor: nullAud{},
	}

	req := httptest.NewRequest("GET", "/ui/api/audit", nil)
	w := httptest.NewRecorder()
	h.HandleListAudit(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected 501 Not Implemented, got %d", w.Code)
	}
}

func TestHandleUpdatePolicy_InvalidYAML(t *testing.T) {
	h := &Handlers{}

	req := httptest.NewRequest("PUT", "/ui/api/policy", bytes.NewBufferString("\tinvalid\t::::"))
	w := httptest.NewRecorder()
	h.HandleUpdatePolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", w.Code)
	}
}

func TestRegisterHandlers(t *testing.T) {
	mux := http.NewServeMux()
	h := &Handlers{
		Backend: backend.NewDevBackend(),
	}
	RegisterHandlers(mux, h)

	// test GET /ui/api/keys
	req := httptest.NewRequest("GET", "/ui/api/keys", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Code)
	}

	// test GET /ui redirect
	req2 := httptest.NewRequest("GET", "/ui", nil)
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusMovedPermanently {
		t.Errorf("expected 301 Moved Permanently, got %d", w2.Code)
	}
}
