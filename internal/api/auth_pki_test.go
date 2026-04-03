package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/policy"
)

func TestAuthHandler_CRL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/cert/crl", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mock crl data"))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	pkiClient := auth.NewPKIClient(auth.PKIConfig{
		Address:        ts.URL,
		BootstrapToken: "test",
		PKIMount:       "pki",
	})

	auditor, _ := audit.NewFileAuditSink("/dev/null")
	tokens, _ := auth.NewTokenService(auth.NewRevocationList())
	handler := NewAuthHandler(tokens, auditor, policy.DenyAllEngine{}, "dev")
	handler.SetPKI(pkiClient, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/crl", nil)
	rr := httptest.NewRecorder()

	handler.CRL(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/pkix-crl" {
		t.Errorf("Unexpected Content-Type: %s", rr.Header().Get("Content-Type"))
	}
}

func TestAuthHandler_RevokeCertificate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/revoke", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	pkiClient := auth.NewPKIClient(auth.PKIConfig{
		Address:        ts.URL,
		BootstrapToken: "test",
		PKIMount:       "pki",
	})

	auditor, _ := audit.NewFileAuditSink("/dev/null")
	tokens, _ := auth.NewTokenService(auth.NewRevocationList())
	handler := NewAuthHandler(tokens, auditor, policy.DenyAllEngine{}, "dev")
	handler.SetPKI(pkiClient, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/revoke-cert", bytes.NewBufferString(`{"serial_number":"123"}`))
	rr := httptest.NewRecorder()

	handler.RevokeCertificate(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected 204 No Content, got %d", rr.Code)
	}
}
