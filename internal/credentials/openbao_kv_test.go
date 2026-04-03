package credentials_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentkms/agentkms/internal/credentials"
)

// fakeVaultKV serves a minimal KV v2 API using httptest.Server.
type fakeVaultKV struct {
	data   map[string]map[string]string // path → fields
	status int                          // forced HTTP status (0 = normal)
}

func (f *fakeVaultKV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	// Strip leading /v1/
	path := r.URL.Path[len("/v1/"):]
	fields, ok := f.data[path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"data": fields,
		},
	}
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

func TestOpenBaoKV_GetSecret_Success(t *testing.T) {
	srv := httptest.NewServer(&fakeVaultKV{
		data: map[string]map[string]string{
			"kv/data/llm/anthropic": {"api_key": "sk-ant-test", "provider": "anthropic"},
		},
	})
	defer srv.Close()

	kv := credentials.NewOpenBaoKV(srv.URL, "test-token", nil)
	fields, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if fields["api_key"] != "sk-ant-test" {
		t.Errorf("api_key = %q, want sk-ant-test", fields["api_key"])
	}
}

func TestOpenBaoKV_GetSecret_NotFound(t *testing.T) {
	srv := httptest.NewServer(&fakeVaultKV{data: map[string]map[string]string{}})
	defer srv.Close()

	kv := credentials.NewOpenBaoKV(srv.URL, "test-token", nil)
	_, err := kv.GetSecret(context.Background(), "kv/data/llm/missing")
	if err == nil {
		t.Fatal("expected error for missing path")
	}
	if !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("expected ErrCredentialNotFound, got: %v", err)
	}
}

func TestOpenBaoKV_GetSecret_ServerError(t *testing.T) {
	srv := httptest.NewServer(&fakeVaultKV{status: http.StatusInternalServerError})
	defer srv.Close()

	kv := credentials.NewOpenBaoKV(srv.URL, "test-token", nil)
	_, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected error for server 500")
	}
}

func TestOpenBaoKV_GetSecret_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(&fakeVaultKV{data: map[string]map[string]string{}})
	defer srv.Close()

	kv := credentials.NewOpenBaoKV(srv.URL, "test-token", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := kv.GetSecret(ctx, "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestOpenBaoKV_GetSecret_EmptyData(t *testing.T) {
	// Server returns 200 but with nil data envelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"data": nil}}) //nolint:errcheck
	}))
	defer srv.Close()

	kv := credentials.NewOpenBaoKV(srv.URL, "test-token", nil)
	_, err := kv.GetSecret(context.Background(), "kv/data/llm/anthropic")
	if err == nil {
		t.Fatal("expected error for empty data envelope")
	}
	if !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("expected ErrCredentialNotFound, got: %v", err)
	}
}
