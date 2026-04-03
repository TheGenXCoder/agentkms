package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/policy"
)

// ── stub KVReader ─────────────────────────────────────────────────────────────

type stubCredKV struct {
	data map[string]map[string]string
	err  error
}

func (s *stubCredKV) GetSecret(_ context.Context, path string) (map[string]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	v, ok := s.data[path]
	if !ok {
		return nil, credentials.ErrCredentialNotFound
	}
	return v, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newCredServer(t *testing.T, apiKey string) (*api.Server, *capturingAuditor) {
	t.Helper()
	b := backend.NewDevBackend()
	aud := &capturingAuditor{}
	srv := api.NewServer(b, aud, policy.AllowAllEngine{}, "dev")
	if apiKey != "" {
		kv := &stubCredKV{
			data: map[string]map[string]string{
				"kv/data/llm/anthropic": {"api_key": apiKey},
				"kv/data/llm/openai":    {"api_key": apiKey + "-openai"},
			},
		}
		srv.SetVender(credentials.NewVender(kv, "kv"))
	}
	return srv, aud
}

func credRequest(t *testing.T, srv *api.Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	srv.ServeHTTP(rr, req)
	return rr
}

// ── GET /credentials/llm ─────────────────────────────────────────────────────

func TestHandleListLLMProviders(t *testing.T) {
	srv, _ := newCredServer(t, "sk-test")
	rr := credRequest(t, srv, http.MethodGet, "/credentials/llm")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp map[string][]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp["providers"]) == 0 {
		t.Error("expected non-empty providers list")
	}
}

// ── GET /credentials/llm/{provider} ──────────────────────────────────────────

func TestHandleGetLLMCredential_Success(t *testing.T) {
	const apiKey = "sk-ant-realkey-abc123"
	srv, sink := newCredServer(t, apiKey)

	rr := credRequest(t, srv, http.MethodGet, "/credentials/llm/anthropic")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["provider"] != "anthropic" {
		t.Errorf("provider = %v, want anthropic", resp["provider"])
	}
	if resp["api_key"] != apiKey {
		t.Errorf("api_key mismatch")
	}
	if _, ok := resp["expires_at"]; !ok {
		t.Error("missing expires_at field")
	}
	if _, ok := resp["ttl_seconds"]; !ok {
		t.Error("missing ttl_seconds field")
	}

	// Audit event must be written with operation=credential_vend.
	if sink.eventCount() != 1 {
		t.Fatalf("expected 1 audit event, got %d", sink.eventCount())
	}
	ev := sink.events[0]
	if ev.Operation != "credential_vend" {
		t.Errorf("audit operation = %q, want credential_vend", ev.Operation)
	}
	if ev.Outcome != "success" {
		t.Errorf("audit outcome = %q, want success", ev.Outcome)
	}
}

func TestHandleGetLLMCredential_UnsupportedProvider(t *testing.T) {
	srv, sink := newCredServer(t, "sk-test")
	rr := credRequest(t, srv, http.MethodGet, "/credentials/llm/unsupported-llm")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	// Denial must be audited.
	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("no audit event for unsupported provider")
	}
	if ev.Outcome != "denied" {
		t.Errorf("audit outcome = %q, want denied", ev.Outcome)
	}
}

func TestHandleGetLLMCredential_NoVender(t *testing.T) {
	srv, _ := newCredServer(t, "") // no vender set
	rr := credRequest(t, srv, http.MethodGet, "/credentials/llm/anthropic")
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

func TestHandleGetLLMCredential_NotFound(t *testing.T) {
	// Vender configured, but this provider has no key in KV
	b := backend.NewDevBackend()
	aud := &capturingAuditor{}
	srv := api.NewServer(b, aud, policy.AllowAllEngine{}, "dev")
	kv := &stubCredKV{data: map[string]map[string]string{}} // empty KV
	srv.SetVender(credentials.NewVender(kv, "kv"))

	rr := credRequest(t, srv, http.MethodGet, "/credentials/llm/anthropic")
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestHandleGetLLMCredential_PolicyDeny(t *testing.T) {
	b := backend.NewDevBackend()
	aud := &capturingAuditor{}
	srv := api.NewServer(b, aud, policy.DenyAllEngine{}, "dev")
	kv := &stubCredKV{
		data: map[string]map[string]string{
			"kv/data/llm/anthropic": {"api_key": "sk-test"},
		},
	}
	srv.SetVender(credentials.NewVender(kv, "kv"))

	rr := credRequest(t, srv, http.MethodGet, "/credentials/llm/anthropic")
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

// ── ADVERSARIAL: API key must not appear in audit events ─────────────────────

func TestAdversarial_CredentialVend_APIKeyNotInAuditEvent(t *testing.T) {
	const secretKey = "sk-ant-super-secret-key-NEVER-LOG-THIS"
	srv, sink := newCredServer(t, secretKey)

	rr := credRequest(t, srv, http.MethodGet, "/credentials/llm/anthropic")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	// The audit event must not contain the API key in any field.
	if sink.eventCount() == 0 {
		t.Fatal("no audit event written")
	}
	ev := sink.events[0]

	// Serialize the full audit event and scan for the key.
	evJSON, _ := json.Marshal(ev)
	if contains(string(evJSON), secretKey) {
		t.Fatal("ADVERSARIAL: API key appears in audit event JSON")
	}
}

// ── POST /credentials/llm/{provider}/refresh ─────────────────────────────────

func TestHandleRefreshLLMCredential_Success(t *testing.T) {
	srv, _ := newCredServer(t, "sk-refresh-test")
	rr := credRequest(t, srv, http.MethodPost, "/credentials/llm/anthropic/refresh")
	if rr.Code != http.StatusOK {
		t.Errorf("refresh: status = %d, want 200", rr.Code)
	}
}

func TestHandleGetLLMCredential_KVError(t *testing.T) {
	kvErr := errors.New("connection refused")
	b := backend.NewDevBackend()
	aud := &capturingAuditor{}
	srv := api.NewServer(b, aud, policy.AllowAllEngine{}, "dev")
	kv := &stubCredKV{err: kvErr}
	srv.SetVender(credentials.NewVender(kv, "kv"))

	rr := credRequest(t, srv, http.MethodGet, "/credentials/llm/anthropic")
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

func TestNewServer_NilPanics(t *testing.T) {
	b := backend.NewDevBackend()
	aud := &capturingAuditor{}

	for _, tc := range []struct {
		name string
		fn   func()
	}{
		{"nil backend", func() { api.NewServer(nil, aud, policy.AllowAllEngine{}, "dev") }},
		{"nil auditor", func() { api.NewServer(b, nil, policy.AllowAllEngine{}, "dev") }},
		{"nil policy", func() { api.NewServer(b, aud, nil, "dev") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("expected panic for nil argument")
				}
			}()
			tc.fn()
		})
	}
}

// contains is a substring helper for test assertions.
func contains(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
