package api_test

// cert_enroll_test.go — Unit tests for POST /auth/cert/issue and GET /auth/cert/list.
//
// All tests mock the PKI engine — no real Vault is contacted.
// The mock is a local httptest.Server whose handlers are configured per-test
// to simulate different Vault responses.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
)

// ── Test infrastructure ───────────────────────────────────────────────────────

// mockBootstrapStore is an in-memory BootstrapStore for tests.
type mockBootstrapStore struct {
	records map[string]*auth.BootstrapRecord // token → record
	used    map[string]bool
}

func newMockBootstrapStore() *mockBootstrapStore {
	return &mockBootstrapStore{
		records: make(map[string]*auth.BootstrapRecord),
		used:    make(map[string]bool),
	}
}

func (m *mockBootstrapStore) Add(rawToken string, rec auth.BootstrapRecord) {
	m.records[rawToken] = &rec
}

func (m *mockBootstrapStore) Fetch(_ context.Context, rawToken string) (*auth.BootstrapRecord, error) {
	rec, ok := m.records[rawToken]
	if !ok {
		return nil, nil
	}
	// Return a copy with the used flag reflecting the in-memory state.
	copy := *rec
	copy.Used = m.used[rawToken]
	return &copy, nil
}

func (m *mockBootstrapStore) MarkUsed(_ context.Context, rawToken string) error {
	m.used[rawToken] = true
	return nil
}

// mockPKIServer is a minimal httptest.Server that simulates the Vault PKI API.
type mockPKIServer struct {
	ts *httptest.Server

	// signResponse controls what POST /v1/pki/sign/agentkms-device returns.
	signStatus   int
	signCertPEM  string
	signSerial   string
	signExpiry   int64

	// listResponse controls what LIST /v1/pki/certs returns.
	listSerials []string

	// fetchCerts maps serial → certPEM for GET /v1/pki/cert/<serial>.
	fetchCerts map[string]string
}

func newMockPKIServer(t *testing.T) *mockPKIServer {
	t.Helper()
	m := &mockPKIServer{
		fetchCerts: make(map[string]string),
	}

	mux := http.NewServeMux()

	// POST /v1/pki/sign/agentkms-device
	mux.HandleFunc("/v1/pki/sign/agentkms-device", func(w http.ResponseWriter, r *http.Request) {
		status := m.signStatus
		if status == 0 {
			status = http.StatusOK
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errors": []string{"mock PKI sign error"},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate":   m.signCertPEM,
				"issuing_ca":    "mock-ca-pem",
				"serial_number": m.signSerial,
				"expiration":    m.signExpiry,
			},
		})
	})

	// POST /v1/pki/revoke
	mux.HandleFunc("/v1/pki/revoke", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// GET /v1/pki/cert/crl
	mux.HandleFunc("/v1/pki/cert/crl", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mock-crl"))
	})

	// LIST or GET /v1/pki/certs
	mux.HandleFunc("/v1/pki/certs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": m.listSerials,
			},
		})
	})

	// GET /v1/pki/cert/<serial>
	mux.HandleFunc("/v1/pki/cert/", func(w http.ResponseWriter, r *http.Request) {
		serial := strings.TrimPrefix(r.URL.Path, "/v1/pki/cert/")
		certPEM, ok := m.fetchCerts[serial]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate": certPEM,
			},
		})
	})

	m.ts = httptest.NewServer(mux)
	t.Cleanup(m.ts.Close)
	return m
}

// newCertEnrollStack builds an AuthHandler wired to a mock PKI server.
func newCertEnrollStack(t *testing.T, mockPKI *mockPKIServer) (*auth.TokenService, *api.AuthHandler, *mockBootstrapStore) {
	t.Helper()
	rl := auth.NewRevocationList()
	svc, err := auth.NewTokenService(rl)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}
	auditor, _ := audit.NewFileAuditSink("/dev/null")
	handler := api.NewAuthHandler(svc, auditor, policy.DenyAllEngine{}, "test")

	pkiClient := auth.NewPKIClient(auth.PKIConfig{
		Address:        mockPKI.ts.URL,
		BootstrapToken: "test-vault-token",
		PKIMount:       "pki",
	})
	handler.SetPKI(pkiClient, nil)

	bs := newMockBootstrapStore()
	handler.SetBootstrapStore(bs)

	return svc, handler, bs
}

// ── CSR helpers ───────────────────────────────────────────────────────────────

// makeCSR generates a self-signed ECDSA P-256 CSR with the given SPIFFE URI.
func makeCSR(t *testing.T, spiffeURI string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	spiffeURL, err := url.Parse(spiffeURI)
	if err != nil {
		t.Fatalf("parse SPIFFE URI: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject:    pkix.Name{CommonName: "test-device"},
		URIs:       []*url.URL{spiffeURL},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

// makeRSACSR generates a CSR with an RSA key of the given bit size.
func makeRSACSR(t *testing.T, spiffeURI string, bits int) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key (%d bits): %v", bits, err)
	}

	spiffeURL, err := url.Parse(spiffeURI)
	if err != nil {
		t.Fatalf("parse SPIFFE URI: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-device"},
		URIs:    []*url.URL{spiffeURL},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("create RSA CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

// makeSelfSignedCert creates a self-signed certificate with a SPIFFE URI SAN.
// Used to populate the mock PKI server's fetchCerts map so /auth/cert/list works.
func makeSelfSignedCert(t *testing.T, spiffeURI string) (certPEM string, serial string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	spiffeURL, err := url.Parse(spiffeURI)
	if err != nil {
		t.Fatalf("parse SPIFFE URI: %v", err)
	}

	serialNum, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		URIs:         []*url.URL{spiffeURL},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	serial = serialNum.Text(16)
	return certPEM, serial
}

// makeIssueReq builds a POST /auth/cert/issue HTTP request.
func makeIssueReq(t *testing.T, body any, tokenStr string) *http.Request {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/cert/issue", bytes.NewReader(bodyBytes))
	r.Header.Set("Content-Type", "application/json")
	if tokenStr != "" {
		r.Header.Set("Authorization", "Bearer "+tokenStr)
	}
	return r
}

// issueCertHumanToken mints a cert+human strength token for a given user+device identity.
// The identity has no real mTLS cert, so we use a zeroed-out fingerprint.
func issueCertHumanToken(t *testing.T, svc *auth.TokenService, userID, deviceID, tenant string) string {
	t.Helper()
	spiffe := "spiffe://test-domain/tenant/" + tenant + "/user/" + userID + "/device/" + deviceID
	id := authTestIdentity(userID, deviceID, tenant, spiffe)
	tokenStr, _, err := svc.IssueWithStrength(id, auth.AuthStrengthCertHuman)
	if err != nil {
		t.Fatalf("IssueWithStrength: %v", err)
	}
	return tokenStr
}

// issueCertOnlyToken mints a cert-only strength token.
func issueCertOnlyToken(t *testing.T, svc *auth.TokenService, userID, deviceID, tenant string) string {
	t.Helper()
	spiffe := "spiffe://test-domain/tenant/" + tenant + "/user/" + userID + "/device/" + deviceID
	id := authTestIdentity(userID, deviceID, tenant, spiffe)
	tokenStr, _, err := svc.IssueWithStrength(id, auth.AuthStrengthCertOnly)
	if err != nil {
		t.Fatalf("IssueWithStrength: %v", err)
	}
	return tokenStr
}

func authTestIdentity(userID, deviceID, tenant, spiffe string) *identity.Identity {
	return &identity.Identity{
		CallerID:        userID,
		UserID:          userID,
		DeviceID:        deviceID,
		Tenant:          tenant,
		TeamID:          "test-team",
		SPIFFEID:        spiffe,
		CertFingerprint: strings.Repeat("a", 64), // fake but non-empty fingerprint
	}
}

// ── POST /auth/cert/issue tests ───────────────────────────────────────────────

// TestCertIssue_Bootstrap_HappyPath verifies Mode 1: valid bootstrap token
// with matching device name signs the CSR and returns a cert.
func TestCertIssue_Bootstrap_HappyPath(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	// Pre-configure what the mock PKI will return when sign is called.
	fakeCert := "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
	mockPKI.signCertPEM = fakeCert
	mockPKI.signSerial = "01:02:03"
	mockPKI.signExpiry = time.Now().Add(365 * 24 * time.Hour).Unix()

	_, handler, bs := newCertEnrollStack(t, mockPKI)

	bs.Add("tok-1", auth.BootstrapRecord{
		UserID:            "alice",
		DeviceNamePattern: "alice-laptop",
		ExpiresAt:         time.Now().Add(time.Hour),
	})

	spiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/alice/device/alice-laptop"
	csr := makeCSR(t, spiffe)

	w := httptest.NewRecorder()
	r := makeIssueReq(t, map[string]any{
		"csr":             csr,
		"device_name":     "alice-laptop",
		"bootstrap_token": "tok-1",
	}, "")
	handler.HandleCertIssue(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["cert"] == "" || resp["cert"] == nil {
		t.Error("response missing cert field")
	}
	if resp["serial"] != "01:02:03" {
		t.Errorf("serial = %v, want 01:02:03", resp["serial"])
	}
	// Verify the token is now marked used.
	if !bs.used["tok-1"] {
		t.Error("bootstrap token not marked used after redemption")
	}
}

// TestCertIssue_Bootstrap_TokenReuse verifies that re-using a bootstrap token
// is rejected after the first redemption.
func TestCertIssue_Bootstrap_TokenReuse(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	mockPKI.signCertPEM = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
	mockPKI.signSerial = "de:ad:be:ef"
	mockPKI.signExpiry = time.Now().Add(365 * 24 * time.Hour).Unix()

	_, handler, bs := newCertEnrollStack(t, mockPKI)
	bs.Add("tok-reuse", auth.BootstrapRecord{
		UserID:            "bob",
		DeviceNamePattern: "bob-wks",
		ExpiresAt:         time.Now().Add(time.Hour),
	})

	spiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/bob/device/bob-wks"
	csr := makeCSR(t, spiffe)

	doIssue := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := makeIssueReq(t, map[string]any{
			"csr":             csr,
			"device_name":     "bob-wks",
			"bootstrap_token": "tok-reuse",
		}, "")
		handler.HandleCertIssue(w, r)
		return w
	}

	// First use should succeed.
	if w := doIssue(); w.Code != http.StatusOK {
		t.Fatalf("first use: status = %d, body = %s", w.Code, w.Body.String())
	}

	// Second use must fail.
	w2 := doIssue()
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("second use: status = %d, want 401; body = %s", w2.Code, w2.Body.String())
	}
}

// TestCertIssue_LoggedIn_HappyPath verifies Mode 2: valid cert+human session
// token + CSR with matching user segment returns a cert.
func TestCertIssue_LoggedIn_HappyPath(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	mockPKI.signCertPEM = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
	mockPKI.signSerial = "11:22:33"
	mockPKI.signExpiry = time.Now().Add(365 * 24 * time.Hour).Unix()

	svc, handler, _ := newCertEnrollStack(t, mockPKI)

	tokenStr := issueCertHumanToken(t, svc, "bert", "bert-old-device", "catalyst9")
	// CSR claims a new device name.
	spiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/bert/device/bert-new-device"
	csr := makeCSR(t, spiffe)

	w := httptest.NewRecorder()
	r := makeIssueReq(t, map[string]any{
		"csr":         csr,
		"device_name": "bert-new-device",
	}, tokenStr)
	handler.HandleCertIssue(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["serial"] != "11:22:33" {
		t.Errorf("serial = %v, want 11:22:33", resp["serial"])
	}
}

// TestCertIssue_LoggedIn_CertOnlySessionRejected verifies that a cert-only
// session (no WebAuthn) cannot issue device certs (Mode 2 requires cert+human).
func TestCertIssue_LoggedIn_CertOnlySessionRejected(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	svc, handler, _ := newCertEnrollStack(t, mockPKI)

	tokenStr := issueCertOnlyToken(t, svc, "bert", "bert-device", "catalyst9")
	spiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/bert/device/bert-new-device"
	csr := makeCSR(t, spiffe)

	w := httptest.NewRecorder()
	r := makeIssueReq(t, map[string]any{
		"csr":         csr,
		"device_name": "bert-new-device",
	}, tokenStr)
	handler.HandleCertIssue(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for cert-only session; body = %s", w.Code, w.Body.String())
	}
}

// TestCertIssue_CrossUser verifies that a session for user=alice cannot issue
// a cert with SPIFFE user=bob.
func TestCertIssue_CrossUser(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	svc, handler, _ := newCertEnrollStack(t, mockPKI)

	// Session belongs to alice.
	tokenStr := issueCertHumanToken(t, svc, "alice", "alice-laptop", "catalyst9")
	// CSR claims bob's identity.
	spiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/bob/device/bob-wks"
	csr := makeCSR(t, spiffe)

	w := httptest.NewRecorder()
	r := makeIssueReq(t, map[string]any{
		"csr":         csr,
		"device_name": "bob-wks",
	}, tokenStr)
	handler.HandleCertIssue(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for cross-user attempt; body = %s", w.Code, w.Body.String())
	}
}

// TestCertIssue_WeakKey_Rejected verifies that a CSR with an RSA-1024 key
// is rejected with 400.
func TestCertIssue_WeakKey_Rejected(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	_, handler, _ := newCertEnrollStack(t, mockPKI)

	// RSA-1024 is below the 2048-bit minimum.
	spiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/alice/device/alice-old"
	csr := makeRSACSR(t, spiffe, 1024)

	w := httptest.NewRecorder()
	r := makeIssueReq(t, map[string]any{
		"csr":             csr,
		"device_name":     "alice-old",
		"bootstrap_token": "unused-token",
	}, "")
	handler.HandleCertIssue(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for weak RSA-1024 key; body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "RSA key too small") {
		t.Errorf("body = %s, want mention of RSA key size", w.Body.String())
	}
}

// TestCertIssue_NoAuth_Returns401 verifies that a request with no bearer
// token and no bootstrap_token is rejected with 401.
func TestCertIssue_NoAuth_Returns401(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	_, handler, _ := newCertEnrollStack(t, mockPKI)

	spiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/alice/device/alice-laptop"
	csr := makeCSR(t, spiffe)

	w := httptest.NewRecorder()
	r := makeIssueReq(t, map[string]any{
		"csr":         csr,
		"device_name": "alice-laptop",
	}, "") // no token, no bootstrap_token
	handler.HandleCertIssue(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body = %s", w.Code, w.Body.String())
	}
}

// TestCertIssue_DeviceNameMismatch verifies that device_name != SPIFFE
// /device/<d> segment is rejected 400.
func TestCertIssue_DeviceNameMismatch(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	svc, handler, _ := newCertEnrollStack(t, mockPKI)

	tokenStr := issueCertHumanToken(t, svc, "alice", "alice-laptop", "catalyst9")
	spiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/alice/device/alice-laptop"
	csr := makeCSR(t, spiffe)

	w := httptest.NewRecorder()
	r := makeIssueReq(t, map[string]any{
		"csr":         csr,
		"device_name": "alice-DIFFERENT", // mismatch with SPIFFE
	}, tokenStr)
	handler.HandleCertIssue(w, r)

	// Either 400 (invalid device_name format) or 400 (device_name mismatch).
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
}

// TestCertIssue_PKINotConfigured verifies 501 when PKI client is not wired.
func TestCertIssue_PKINotConfigured(t *testing.T) {
	rl := auth.NewRevocationList()
	svc, _ := auth.NewTokenService(rl)
	auditor, _ := audit.NewFileAuditSink("/dev/null")
	handler := api.NewAuthHandler(svc, auditor, policy.DenyAllEngine{}, "test")
	// No SetPKI call.

	spiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/alice/device/alice-laptop"
	csr := makeCSR(t, spiffe)

	w := httptest.NewRecorder()
	r := makeIssueReq(t, map[string]any{
		"csr":         csr,
		"device_name": "alice-laptop",
	}, "")
	handler.HandleCertIssue(w, r)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501; body = %s", w.Code, w.Body.String())
	}
}

// ── GET /auth/cert/list tests ─────────────────────────────────────────────────

// TestCertList_FiltersByUserID verifies that only certs for the session's
// user_id are returned, and certs for other users are excluded.
func TestCertList_FiltersByUserID(t *testing.T) {
	mockPKI := newMockPKIServer(t)

	// Create two certs: one for alice, one for bob.
	aliceSpiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/alice/device/alice-laptop"
	bobSpiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/bob/device/bob-wks"

	aliceCertPEM, aliceSerial := makeSelfSignedCert(t, aliceSpiffe)
	bobCertPEM, bobSerial := makeSelfSignedCert(t, bobSpiffe)

	mockPKI.listSerials = []string{aliceSerial, bobSerial}
	mockPKI.fetchCerts[aliceSerial] = aliceCertPEM
	mockPKI.fetchCerts[bobSerial] = bobCertPEM

	svc, handler, _ := newCertEnrollStack(t, mockPKI)

	// Alice's session.
	tokenStr := issueCertHumanToken(t, svc, "alice", "alice-laptop", "catalyst9")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/cert/list", nil)
	r.Header.Set("Authorization", "Bearer "+tokenStr)
	handler.HandleCertList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp struct {
		Certs []map[string]any `json:"certs"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Should see exactly alice's cert, not bob's.
	if len(resp.Certs) != 1 {
		t.Fatalf("cert count = %d, want 1", len(resp.Certs))
	}
	if spiffe, _ := resp.Certs[0]["spiffe"].(string); spiffe != aliceSpiffe {
		t.Errorf("cert[0].spiffe = %q, want alice's spiffe", spiffe)
	}
	if dn, _ := resp.Certs[0]["device_name"].(string); dn != "alice-laptop" {
		t.Errorf("cert[0].device_name = %q, want alice-laptop", dn)
	}
	if revoked, _ := resp.Certs[0]["revoked"].(bool); revoked {
		t.Errorf("cert[0].revoked = true, want false for active cert")
	}
}

// TestCertList_NoAuth_Returns401 verifies that missing session token → 401.
func TestCertList_NoAuth_Returns401(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	_, handler, _ := newCertEnrollStack(t, mockPKI)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/cert/list", nil)
	// No Authorization header.
	handler.HandleCertList(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body = %s", w.Code, w.Body.String())
	}
}

// TestCertList_EmptyForNewUser verifies that a user with no certs in PKI
// gets an empty list (not an error).
func TestCertList_EmptyForNewUser(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	mockPKI.listSerials = []string{} // No certs at all.

	svc, handler, _ := newCertEnrollStack(t, mockPKI)
	tokenStr := issueCertHumanToken(t, svc, "newuser", "newuser-device", "catalyst9")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/cert/list", nil)
	r.Header.Set("Authorization", "Bearer "+tokenStr)
	handler.HandleCertList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Certs []map[string]any `json:"certs"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Certs) != 0 {
		t.Errorf("cert count = %d, want 0 for new user", len(resp.Certs))
	}
}

// ── POST /auth/cert/issue — no SPIFFE SAN test ───────────────────────────────

// TestCertIssue_NoSpiffeSAN verifies that a CSR without a SPIFFE URI SAN is
// rejected with 400.
func TestCertIssue_NoSpiffeSAN(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	_, handler, _ := newCertEnrollStack(t, mockPKI)

	// Build a CSR with no URIs at all.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-device"},
		// URIs intentionally empty.
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	svc, _, _ := newCertEnrollStack(t, mockPKI)
	tokenStr := issueCertHumanToken(t, svc, "alice", "alice-laptop", "catalyst9")

	w := httptest.NewRecorder()
	r := makeIssueReq(t, map[string]any{
		"csr":         csrPEM,
		"device_name": "alice-laptop",
	}, tokenStr)
	handler.HandleCertIssue(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for CSR with no SPIFFE SAN; body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "SPIFFE") {
		t.Errorf("body = %s, want mention of SPIFFE SAN", w.Body.String())
	}
}

// ── POST /auth/certificate/revoke tests ──────────────────────────────────────

// revokeReq builds a POST /auth/certificate/revoke request.
func revokeReq(t *testing.T, body any, tokenStr string) *http.Request {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/certificate/revoke", bytes.NewReader(bodyBytes))
	r.Header.Set("Content-Type", "application/json")
	if tokenStr != "" {
		r.Header.Set("Authorization", "Bearer "+tokenStr)
	}
	return r
}

// TestRevokeCert_DeviceNameResolution verifies that supplying device_name
// instead of serial_number resolves the cert and performs the revocation.
func TestRevokeCert_DeviceNameResolution(t *testing.T) {
	mockPKI := newMockPKIServer(t)

	aliceSpiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/alice/device/alice-laptop"
	aliceCertPEM, aliceSerial := makeSelfSignedCert(t, aliceSpiffe)
	mockPKI.listSerials = []string{aliceSerial}
	mockPKI.fetchCerts[aliceSerial] = aliceCertPEM

	svc, handler, _ := newCertEnrollStack(t, mockPKI)
	tokenStr := issueCertHumanToken(t, svc, "alice", "alice-laptop", "catalyst9")

	w := httptest.NewRecorder()
	r := revokeReq(t, map[string]any{"device_name": "alice-laptop"}, tokenStr)
	handler.RevokeCertificateWithOwnerCheck(w, r)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204; body = %s", w.Code, w.Body.String())
	}
}

// TestRevokeCert_NonOwnerRejected verifies that a session for bob cannot
// revoke alice's certificate.
func TestRevokeCert_NonOwnerRejected(t *testing.T) {
	mockPKI := newMockPKIServer(t)

	// Alice's cert is in PKI.
	aliceSpiffe := "spiffe://catalyst9.local/tenant/catalyst9/user/alice/device/alice-laptop"
	aliceCertPEM, aliceSerial := makeSelfSignedCert(t, aliceSpiffe)
	mockPKI.listSerials = []string{aliceSerial}
	mockPKI.fetchCerts[aliceSerial] = aliceCertPEM

	svc, handler, _ := newCertEnrollStack(t, mockPKI)
	// Bob's session token.
	bobToken := issueCertHumanToken(t, svc, "bob", "bob-wks", "catalyst9")

	w := httptest.NewRecorder()
	r := revokeReq(t, map[string]any{"serial_number": aliceSerial}, bobToken)
	handler.RevokeCertificateWithOwnerCheck(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// TestRevokeCert_DeviceNameNotFound verifies that a device_name with no
// matching cert returns 404.
func TestRevokeCert_DeviceNameNotFound(t *testing.T) {
	mockPKI := newMockPKIServer(t)
	mockPKI.listSerials = []string{} // nothing in PKI

	svc, handler, _ := newCertEnrollStack(t, mockPKI)
	tokenStr := issueCertHumanToken(t, svc, "alice", "alice-laptop", "catalyst9")

	w := httptest.NewRecorder()
	r := revokeReq(t, map[string]any{"device_name": "ghost-device"}, tokenStr)
	handler.RevokeCertificateWithOwnerCheck(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body = %s", w.Code, w.Body.String())
	}
}
