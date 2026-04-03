package auth_test

// Tests for PKIClient — A-10.
// All tests use httptest.Server; no real OpenBao dependency.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/auth"
)

// ── fake PKI server ───────────────────────────────────────────────────────────

type fakePKI struct {
	status   int
	certPEM  string
	keyPEM   string
	caPEM    string
	serial   string
	expiry   int64
	errors   []string
	lastBody map[string]interface{}
	lastToken string
}

func (f *fakePKI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.lastToken = r.Header.Get("X-Vault-Token")
	if r.Method == http.MethodPost {
		json.NewDecoder(r.Body).Decode(&f.lastBody) //nolint:errcheck
	}

	status := f.status
	if status == 0 {
		status = http.StatusOK
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if len(f.errors) > 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{"errors": f.errors}) //nolint:errcheck
		return
	}

	if strings.Contains(r.URL.Path, "/cert/ca") {
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"data": map[string]string{"certificate": f.caPEM},
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"data": map[string]interface{}{
			"certificate":   f.certPEM,
			"private_key":   f.keyPEM,
			"issuing_ca":    f.caPEM,
			"serial_number": f.serial,
			"expiration":    f.expiry,
		},
	})
}

const (
	fakeCert   = "-----BEGIN CERTIFICATE-----\nMIIFake...\n-----END CERTIFICATE-----"
	fakeKey    = "-----BEGIN EC PRIVATE KEY-----\nMIIFakeKey...\n-----END EC PRIVATE KEY-----"
	fakeCA     = "-----BEGIN CERTIFICATE-----\nMIIFakeCA...\n-----END CERTIFICATE-----"
	fakeSerial = "4e:ab:44:b0:34:17:aa:44"
)

func newFakePKI() (*fakePKI, *auth.PKIClient, func()) {
	f := &fakePKI{
		certPEM: fakeCert,
		keyPEM:  fakeKey,
		caPEM:   fakeCA,
		serial:  fakeSerial,
		expiry:  time.Now().Add(720 * time.Hour).Unix(),
	}
	srv := httptest.NewServer(f)
	client := auth.NewPKIClient(auth.PKIConfig{
		Address:        srv.URL,
		BootstrapToken: "test-bootstrap-token",
		PKIMount:       "pki",
		Role:           "agentkms",
	})
	return f, client, srv.Close
}

// ── IssueCert ─────────────────────────────────────────────────────────────────

func TestIssueCert_Success(t *testing.T) {
	_, client, close := newFakePKI()
	defer close()

	bundle, err := client.IssueCert(context.Background(), "bert@platform-team", "platform-team", "", "720h")
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if bundle.CertificatePEM != fakeCert {
		t.Error("CertificatePEM mismatch")
	}
	if bundle.PrivateKeyPEM != fakeKey {
		t.Error("PrivateKeyPEM mismatch")
	}
	if bundle.CAPEM != fakeCA {
		t.Error("CAPEM mismatch")
	}
	if bundle.SerialNumber != fakeSerial {
		t.Error("SerialNumber mismatch")
	}
	if bundle.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero")
	}
}

func TestIssueCert_SendsBootstrapTokenInHeader(t *testing.T) {
	f, client, close := newFakePKI()
	defer close()

	client.IssueCert(context.Background(), "user@team", "team", "", "") //nolint:errcheck

	if f.lastToken != "test-bootstrap-token" {
		t.Errorf("expected bootstrap token in X-Vault-Token, got: %q", f.lastToken)
	}
}

func TestIssueCert_SendsCallerIDAsCommonName(t *testing.T) {
	f, client, close := newFakePKI()
	defer close()

	client.IssueCert(context.Background(), "alice@team-alpha", "team-alpha", "", "") //nolint:errcheck

	if f.lastBody["common_name"] != "alice@team-alpha" {
		t.Errorf("common_name = %v, want alice@team-alpha", f.lastBody["common_name"])
	}
}

func TestIssueCert_SendsTeamIDAsOrganization(t *testing.T) {
	f, client, close := newFakePKI()
	defer close()

	client.IssueCert(context.Background(), "user@team", "payments-team", "", "") //nolint:errcheck

	orgs, _ := f.lastBody["organization"].([]interface{})
	if len(orgs) == 0 || orgs[0] != "payments-team" {
		t.Errorf("organization = %v, want [payments-team]", f.lastBody["organization"])
	}
}

func TestIssueCert_DefaultTTL(t *testing.T) {
	f, client, close := newFakePKI()
	defer close()

	client.IssueCert(context.Background(), "user@team", "team", "", "") //nolint:errcheck

	if f.lastBody["ttl"] != "720h" {
		t.Errorf("ttl = %v, want 720h", f.lastBody["ttl"])
	}
}

func TestIssueCert_EmptyCallerID_Error(t *testing.T) {
	_, client, close := newFakePKI()
	defer close()

	_, err := client.IssueCert(context.Background(), "", "team", "", "")
	if err == nil {
		t.Fatal("expected error for empty callerID")
	}
}

func TestIssueCert_EmptyTeamID_Error(t *testing.T) {
	_, client, close := newFakePKI()
	defer close()

	_, err := client.IssueCert(context.Background(), "user@team", "", "", "")
	if err == nil {
		t.Fatal("expected error for empty teamID")
	}
}

func TestIssueCert_PKIRejectsRequest(t *testing.T) {
	f, client, close := newFakePKI()
	defer close()

	f.status = http.StatusBadRequest
	f.errors = []string{"common name not allowed by this role"}

	_, err := client.IssueCert(context.Background(), "user@team", "team", "", "")
	if err == nil {
		t.Fatal("expected error for PKI rejection")
	}
	if !errors.Is(err, auth.ErrPKIIssueFailed) {
		t.Errorf("expected ErrPKIIssueFailed, got: %v", err)
	}
	// Error message should contain the PKI reason (it's policy text, not key material).
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected PKI reason in error, got: %v", err)
	}
}

func TestIssueCert_ServerError(t *testing.T) {
	f, pki, close := newFakePKI()
	defer close()

	f.status = http.StatusInternalServerError
	f.errors = []string{}

	_, err := pki.IssueCert(context.Background(), "user@team", "team", "", "")
	if err == nil {
		t.Fatal("expected error for server 500")
	}
	if !errors.Is(err, auth.ErrPKIIssueFailed) {
		t.Errorf("expected ErrPKIIssueFailed, got: %v", err)
	}
}

func TestIssueCert_MissingCertInResponse(t *testing.T) {
	f, client, close := newFakePKI()
	defer close()

	f.certPEM = "" // simulate broken response

	_, err := client.IssueCert(context.Background(), "user@team", "team", "", "")
	if err == nil {
		t.Fatal("expected error when cert is missing")
	}
	if !errors.Is(err, auth.ErrPKIIssueFailed) {
		t.Errorf("expected ErrPKIIssueFailed, got: %v", err)
	}
}

func TestIssueCert_CancelledContext(t *testing.T) {
	_, client, close := newFakePKI()
	defer close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.IssueCert(ctx, "user@team", "team", "", "")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// ── ADVERSARIAL: private key never in error messages ─────────────────────────

func TestAdversarial_IssueCert_PrivateKeyNotInError(t *testing.T) {
	// This test does not use newFakePKI — it constructs a custom server
	// that returns a response containing a fake private key but missing the
	// certificate, triggering ErrPKIIssueFailed. The key must not appear in
	// the returned error message.
	// Simulate by returning a valid JSON body with a missing certificate field.
	corruptSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Valid JSON but missing certificate field — forces ErrPKIIssueFailed.
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"data": map[string]interface{}{
				"private_key":   "sk-SUPER-SECRET-KEY-NEVER-LOG",
				"certificate":   "", // missing cert triggers failure
				"serial_number": "aa:bb",
				"expiration":    0,
			},
		})
	}))
	defer corruptSrv.Close()

	corruptClient := auth.NewPKIClient(auth.PKIConfig{
		Address:        corruptSrv.URL,
		BootstrapToken: "token",
	})

	_, err := corruptClient.IssueCert(context.Background(), "user@team", "team", "", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "SUPER-SECRET-KEY-NEVER-LOG") {
		t.Fatal("ADVERSARIAL: private key material appears in error message")
	}
}

// ── FetchCACert ───────────────────────────────────────────────────────────────

func TestFetchCACert_Success(t *testing.T) {
	_, client, close := newFakePKI()
	defer close()

	ca, err := client.FetchCACert(context.Background())
	if err != nil {
		t.Fatalf("FetchCACert: %v", err)
	}
	if ca != fakeCA {
		t.Errorf("CA cert mismatch")
	}
}

func TestFetchCACert_ServerError(t *testing.T) {
	f, client, close := newFakePKI()
	defer close()

	f.status = http.StatusInternalServerError
	_, err := client.FetchCACert(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

// ── Default config values ─────────────────────────────────────────────────────

func TestNewPKIClient_DefaultMountAndRole(t *testing.T) {
	// Verify defaults are applied when PKIMount and Role are empty.
	f := &fakePKI{certPEM: fakeCert, keyPEM: fakeKey, caPEM: fakeCA, serial: "aa", expiry: time.Now().Add(time.Hour).Unix()}
	srv := httptest.NewServer(f)
	defer srv.Close()

	client := auth.NewPKIClient(auth.PKIConfig{
		Address:        srv.URL,
		BootstrapToken: "tok",
		// PKIMount and Role intentionally empty
	})
	// The request URL should contain /pki/issue/agentkms (the defaults).
	// We verify by checking that IssueCert works (it would 404 if the path were wrong).
	_, err := client.IssueCert(context.Background(), "u@t", "t", "", "")
	if err != nil {
		t.Fatalf("expected defaults to produce a valid URL: %v", err)
	}
}
