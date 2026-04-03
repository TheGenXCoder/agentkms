package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPKIClient_RevokeCert_FetchCRL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/revoke", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/pki/cert/crl", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mock crl data"))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := NewPKIClient(PKIConfig{
		Address:        ts.URL,
		BootstrapToken: "test-token",
		PKIMount:       "pki",
	})

	ctx := context.Background()

	err := client.RevokeCert(ctx, "serial123")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	crl, err := client.FetchCRL(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(crl) != "mock crl data" {
		t.Errorf("Unexpected CRL data: %s", crl)
	}
}
