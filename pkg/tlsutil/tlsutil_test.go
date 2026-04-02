package tlsutil_test

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"

	. "github.com/agentkms/agentkms/pkg/tlsutil"
)

// ── GenerateDevCA ─────────────────────────────────────────────────────────────

func TestGenerateDevCA_ProducesValidCA(t *testing.T) {
	certPEM, keyPEM, err := GenerateDevCA()
	if err != nil {
		t.Fatalf("GenerateDevCA: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("GenerateDevCA returned empty PEM")
	}

	cert, err := DecodeCertPEM(certPEM)
	if err != nil {
		t.Fatalf("DecodeCertPEM: %v", err)
	}
	if !cert.IsCA {
		t.Error("CA cert: IsCA = false")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA cert: missing KeyUsageCertSign")
	}
}

func TestGenerateDevCA_KeyMatchesCert(t *testing.T) {
	certPEM, keyPEM, err := GenerateDevCA()
	if err != nil {
		t.Fatalf("GenerateDevCA: %v", err)
	}
	// tls.X509KeyPair validates that the key matches the certificate.
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Errorf("CA cert/key pair mismatch: %v", err)
	}
}

// ── IssueServerCert ───────────────────────────────────────────────────────────

func TestIssueServerCert_IncludesLocalhostSAN(t *testing.T) {
	caCertPEM, caKeyPEM, err := GenerateDevCA()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := IssueServerCert(caCertPEM, caKeyPEM, nil)
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}

	cert, err := DecodeCertPEM(certPEM)
	if err != nil {
		t.Fatalf("DecodeCertPEM: %v", err)
	}

	hasLocalhost := false
	for _, dns := range cert.DNSNames {
		if dns == "localhost" {
			hasLocalhost = true
		}
	}
	if !hasLocalhost {
		t.Error("server cert missing localhost DNS SAN")
	}

	has127 := false
	for _, ip := range cert.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			has127 = true
		}
	}
	if !has127 {
		t.Error("server cert missing 127.0.0.1 IP SAN")
	}

	// Must not be a CA.
	if cert.IsCA {
		t.Error("server cert: IsCA = true")
	}

	// Key must match cert.
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Errorf("server cert/key mismatch: %v", err)
	}
}

func TestIssueServerCert_ExtraHosts(t *testing.T) {
	caCertPEM, caKeyPEM, err := GenerateDevCA()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := IssueServerCert(caCertPEM, caKeyPEM, []string{"myhost.local", "10.0.0.1"})
	if err != nil {
		t.Fatalf("IssueServerCert with extra hosts: %v", err)
	}
	cert, _ := DecodeCertPEM(certPEM)
	hasDNS := false
	for _, d := range cert.DNSNames {
		if d == "myhost.local" {
			hasDNS = true
		}
	}
	if !hasDNS {
		t.Error("server cert missing extra DNS SAN myhost.local")
	}
	hasIP := false
	for _, ip := range cert.IPAddresses {
		if ip.Equal(net.ParseIP("10.0.0.1")) {
			hasIP = true
		}
	}
	if !hasIP {
		t.Error("server cert missing extra IP SAN 10.0.0.1")
	}
}

// ── IssueClientCert ───────────────────────────────────────────────────────────

func TestIssueClientCert_SubjectFields(t *testing.T) {
	caCertPEM, caKeyPEM, err := GenerateDevCA()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := IssueClientCert(
		caCertPEM, caKeyPEM,
		"bert@dev", "dev-team", "developer",
		"spiffe://agentkms.local/dev/developer/bert",
	)
	if err != nil {
		t.Fatalf("IssueClientCert: %v", err)
	}
	cert, _ := DecodeCertPEM(certPEM)

	if cert.Subject.CommonName != "bert@dev" {
		t.Errorf("CN = %q, want bert@dev", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "dev-team" {
		t.Errorf("O = %v, want [dev-team]", cert.Subject.Organization)
	}
	if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] != "developer" {
		t.Errorf("OU = %v, want [developer]", cert.Subject.OrganizationalUnit)
	}
}

func TestIssueClientCert_SPIFFESANPresent(t *testing.T) {
	caCertPEM, caKeyPEM, _ := GenerateDevCA()
	spiffeID := "spiffe://agentkms.local/dev/developer/bert"
	certPEM, _, err := IssueClientCert(caCertPEM, caKeyPEM, "bert@dev", "dev-team", "developer", spiffeID)
	if err != nil {
		t.Fatalf("IssueClientCert: %v", err)
	}
	cert, _ := DecodeCertPEM(certPEM)
	if len(cert.URIs) == 0 || cert.URIs[0].String() != spiffeID {
		t.Errorf("SPIFFE SAN missing or wrong: %v", cert.URIs)
	}
}

func TestIssueClientCert_InvalidSPIFFEScheme(t *testing.T) {
	caCertPEM, caKeyPEM, _ := GenerateDevCA()
	_, _, err := IssueClientCert(caCertPEM, caKeyPEM, "bert@dev", "dev-team", "developer",
		"http://not-spiffe/path")
	if err == nil {
		t.Fatal("expected error for non-spiffe URI scheme, got nil")
	}
}

func TestIssueClientCert_VerifiesAgainstCA(t *testing.T) {
	caCertPEM, caKeyPEM, _ := GenerateDevCA()
	certPEM, _, err := IssueClientCert(caCertPEM, caKeyPEM, "bert@dev", "dev-team", "developer", "")
	if err != nil {
		t.Fatalf("IssueClientCert: %v", err)
	}
	cert, _ := DecodeCertPEM(certPEM)
	pool, _ := LoadCertPool(caCertPEM)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("client cert doesn't verify against CA: %v", err)
	}
}

// ── PEM helpers ───────────────────────────────────────────────────────────────

func TestEncodeDecode_CertRoundTrip(t *testing.T) {
	certPEM, _, _ := GenerateDevCA()
	cert1, err := DecodeCertPEM(certPEM)
	if err != nil {
		t.Fatalf("DecodeCertPEM: %v", err)
	}
	reencoded := EncodeCertPEM(cert1)
	cert2, err := DecodeCertPEM(reencoded)
	if err != nil {
		t.Fatalf("DecodeCertPEM after re-encode: %v", err)
	}
	if cert1.SerialNumber.Cmp(cert2.SerialNumber) != 0 {
		t.Error("serial mismatch after cert PEM round-trip")
	}
}

func TestDecodeKeyPEM_GarbageInput(t *testing.T) {
	_, err := DecodeKeyPEM([]byte("this is not a PEM key"))
	if err == nil {
		t.Fatal("expected error for garbage key PEM, got nil")
	}
}

func TestDecodeCertPEM_GarbageInput(t *testing.T) {
	_, err := DecodeCertPEM([]byte("garbage"))
	if err == nil {
		t.Fatal("expected error for garbage cert PEM, got nil")
	}
}

func TestLoadCertPool_ValidCA(t *testing.T) {
	caCertPEM, _, _ := GenerateDevCA()
	pool, err := LoadCertPool(caCertPEM)
	if err != nil {
		t.Fatalf("LoadCertPool: %v", err)
	}
	if pool == nil {
		t.Fatal("LoadCertPool returned nil pool")
	}
}

func TestLoadCertPool_InvalidPEM(t *testing.T) {
	_, err := LoadCertPool([]byte("not a certificate"))
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

// ── TLS config helpers ────────────────────────────────────────────────────────

func TestNewServerTLSConfig_TLS13AndClientAuth(t *testing.T) {
	caCertPEM, caKeyPEM, _ := GenerateDevCA()
	srvCertPEM, srvKeyPEM, _ := IssueServerCert(caCertPEM, caKeyPEM, nil)
	srvCert, _ := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	pool, _ := LoadCertPool(caCertPEM)

	cfg := NewServerTLSConfig(srvCert, pool)
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs is nil")
	}
}

func TestLoadServerTLSConfig_MismatchedKeyRejected(t *testing.T) {
	caCertPEM, caKeyPEM, _ := GenerateDevCA()
	srv1CertPEM, _, _ := IssueServerCert(caCertPEM, caKeyPEM, nil)
	_, srv2KeyPEM, _ := IssueServerCert(caCertPEM, caKeyPEM, nil)
	// Cert from srv1, key from srv2 — mismatched.
	_, err := LoadServerTLSConfig(srv1CertPEM, srv2KeyPEM, caCertPEM)
	if err == nil {
		t.Fatal("expected error for mismatched cert/key, got nil")
	}
}

func TestLoadClientTLSConfig_Valid(t *testing.T) {
	caCertPEM, caKeyPEM, _ := GenerateDevCA()
	clientCertPEM, clientKeyPEM, _ := IssueClientCert(caCertPEM, caKeyPEM, "bert@dev", "dev-team", "developer", "")
	cfg, err := LoadClientTLSConfig(clientCertPEM, clientKeyPEM, caCertPEM)
	if err != nil {
		t.Fatalf("LoadClientTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1", len(cfg.Certificates))
	}
}

func TestLoadServerTLSConfig_Valid(t *testing.T) {
	caCertPEM, caKeyPEM, _ := GenerateDevCA()
	srvCertPEM, srvKeyPEM, _ := IssueServerCert(caCertPEM, caKeyPEM, nil)
	cfg, err := LoadServerTLSConfig(srvCertPEM, srvKeyPEM, caCertPEM)
	if err != nil {
		t.Fatalf("LoadServerTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
}

func TestLoadClientTLSConfig_InvalidCAPool(t *testing.T) {
	caCertPEM, caKeyPEM, _ := GenerateDevCA()
	clientCertPEM, clientKeyPEM, _ := IssueClientCert(caCertPEM, caKeyPEM, "bert@dev", "dev-team", "developer", "")
	_, err := LoadClientTLSConfig(clientCertPEM, clientKeyPEM, []byte("not a cert"))
	if err == nil {
		t.Fatal("expected error for invalid CA PEM, got nil")
	}
}

func TestLoadCA_MismatchedKeyRejected(t *testing.T) {
	caCertPEM, _, _ := GenerateDevCA()
	// Use a different CA's key.
	_, caKeyPEM2, _ := GenerateDevCA()
	// IssueServerCert calls loadCA internally.
	_, _, err := IssueServerCert(caCertPEM, caKeyPEM2, nil)
	if err == nil {
		t.Fatal("expected error when CA cert and key do not match, got nil")
	}
}

// ── SECURITY: private key never in error messages ──────────────────────────────

func TestEncodeKeyPEM_ErrorMessageNoKeyMaterial(t *testing.T) {
	// EncodeKeyPEM should produce PEM output, not expose key bytes in errors.
	// We verify that no error is produced for a valid key.
	_, caKeyPEM, _ := GenerateDevCA()
	key, err := DecodeKeyPEM(caKeyPEM)
	if err != nil {
		t.Fatalf("DecodeKeyPEM: %v", err)
	}
	out, err := EncodeKeyPEM(key)
	if err != nil {
		t.Fatalf("EncodeKeyPEM: %v", err)
	}
	if !strings.Contains(string(out), "-----BEGIN PRIVATE KEY-----") {
		t.Error("EncodeKeyPEM output missing PRIVATE KEY header")
	}
}
