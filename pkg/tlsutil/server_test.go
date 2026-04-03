package tlsutil_test

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/agentkms/agentkms/pkg/tlsutil"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// mustCA generates a dev CA for use in tests.
func mustCA(t *testing.T) *tlsutil.CertBundle {
	t.Helper()
	ca, err := tlsutil.GenerateSelfSignedCA(tlsutil.CAOptions{
		CN:       "Test CA",
		Org:      "test",
		Validity: time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	return ca
}

// mustServerCert generates a TLS server cert signed by ca.
func mustServerCert(t *testing.T, ca *tlsutil.CertBundle) *tlsutil.CertBundle {
	t.Helper()
	cert, err := tlsutil.GenerateLeafCert(ca, tlsutil.LeafOptions{
		CN:           "localhost",
		Org:          "test",
		OrgUnit:      "service",
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Validity:     time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateLeafCert (server): %v", err)
	}
	return cert
}

// mustClientCert generates a TLS client cert signed by ca.
func mustClientCert(t *testing.T, ca *tlsutil.CertBundle, cn string) *tlsutil.CertBundle {
	t.Helper()
	cert, err := tlsutil.GenerateLeafCert(ca, tlsutil.LeafOptions{
		CN:           cn,
		Org:          "platform-team",
		OrgUnit:      "developer",
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Validity:     time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateLeafCert (client): %v", err)
	}
	return cert
}

// ── ServerTLSConfig tests ─────────────────────────────────────────────────────

func TestClientTLSConfig_ValidConfig(t *testing.T) {
	ca := mustCA(t)
	client := mustClientCert(t, ca, "agentkms-client")

	cfg, err := tlsutil.ClientTLSConfig(ca.CertPEM, client.CertPEM, client.KeyPEM)
	if err != nil {
		t.Fatalf("ClientTLSConfig failed: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion TLS 1.3, got %x", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestClientTLSConfig_InvalidCA(t *testing.T) {
	ca := mustCA(t)
	client := mustClientCert(t, ca, "agentkms-client")

	_, err := tlsutil.ClientTLSConfig([]byte("invalid ca"), client.CertPEM, client.KeyPEM)
	if err == nil {
		t.Fatal("expected error with invalid CA")
	}
}

func TestClientTLSConfig_InvalidClientCert(t *testing.T) {
	ca := mustCA(t)

	_, err := tlsutil.ClientTLSConfig(ca.CertPEM, []byte("invalid"), []byte("invalid"))
	if err == nil {
		t.Fatal("expected error with invalid client cert")
	}
}

func TestServerTLSConfig_ValidConfig2(t *testing.T) {
	ca := mustCA(t)
	srv := mustServerCert(t, ca)

	tlsCert, err := tls.X509KeyPair(srv.CertPEM, srv.KeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	cfg, err := tlsutil.ServerTLSConfig(ca.CertPEM, tlsCert)
	if err != nil {
		t.Fatalf("ServerTLSConfig returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("ServerTLSConfig returned nil config")
	}
}

func TestServerTLSConfig_TLS13Minimum(t *testing.T) {
	ca := mustCA(t)
	srv := mustServerCert(t, ca)

	tlsCert, err := tls.X509KeyPair(srv.CertPEM, srv.KeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	cfg, err := tlsutil.ServerTLSConfig(ca.CertPEM, tlsCert)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want tls.VersionTLS13 (%v)", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestServerTLSConfig_ClientAuthRequired(t *testing.T) {
	ca := mustCA(t)
	srv := mustServerCert(t, ca)

	tlsCert, err := tls.X509KeyPair(srv.CertPEM, srv.KeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	cfg, err := tlsutil.ServerTLSConfig(ca.CertPEM, tlsCert)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
}

func TestServerTLSConfig_ClientCAPoolSet(t *testing.T) {
	ca := mustCA(t)
	srv := mustServerCert(t, ca)

	tlsCert, err := tls.X509KeyPair(srv.CertPEM, srv.KeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	cfg, err := tlsutil.ServerTLSConfig(ca.CertPEM, tlsCert)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs is nil; expected a populated cert pool")
	}
}

func TestServerTLSConfig_ServerCertPresent(t *testing.T) {
	ca := mustCA(t)
	srv := mustServerCert(t, ca)

	tlsCert, err := tls.X509KeyPair(srv.CertPEM, srv.KeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	cfg, err := tlsutil.ServerTLSConfig(ca.CertPEM, tlsCert)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	if len(cfg.Certificates) != 1 {
		t.Errorf("len(Certificates) = %d, want 1", len(cfg.Certificates))
	}
}

func TestServerTLSConfig_EmptyCA(t *testing.T) {
	ca := mustCA(t)
	srv := mustServerCert(t, ca)

	tlsCert, err := tls.X509KeyPair(srv.CertPEM, srv.KeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	_, err = tlsutil.ServerTLSConfig(nil, tlsCert)
	if err == nil {
		t.Fatal("expected error for nil caCertPEM, got nil")
	}
}

func TestServerTLSConfig_GarbageCA(t *testing.T) {
	ca := mustCA(t)
	srv := mustServerCert(t, ca)

	tlsCert, err := tls.X509KeyPair(srv.CertPEM, srv.KeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	_, err = tlsutil.ServerTLSConfig([]byte("this is not a PEM certificate"), tlsCert)
	if err == nil {
		t.Fatal("expected error for garbage caCertPEM, got nil")
	}
}

// TestServerTLSConfig_EndToEndMTLS verifies that a client presenting a valid
// cert can complete the mTLS handshake, and a client with no cert is rejected.
func TestServerTLSConfig_EndToEndMTLS(t *testing.T) {
	ca := mustCA(t)
	srv := mustServerCert(t, ca)
	client := mustClientCert(t, ca, "bert@platform-team")

	// Build server TLS config.
	serverTLSCert, err := tls.X509KeyPair(srv.CertPEM, srv.KeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair (server): %v", err)
	}
	serverCfg, err := tlsutil.ServerTLSConfig(ca.CertPEM, serverTLSCert)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	// Start a local TLS listener.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Build CA pool for client-side server cert verification.
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CertPEM)

	// ── Valid client: should connect successfully ─────────────────────────

	clientTLSCert, err := tls.X509KeyPair(client.CertPEM, client.KeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair (client): %v", err)
	}

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		// Drive the handshake.
		_ = conn.(*tls.Conn).Handshake()
		conn.Close()
		done <- nil
	}()

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientTLSCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("valid client: tls.Dial failed: %v", err)
	}
	conn.Close()
	<-done

	// ── Client with no cert: handshake must fail ──────────────────────────
	//
	// TLS 1.3 note: the client-side Handshake (inside tls.Dial) can return nil
	// before the server has processed the empty Certificate message and sent
	// the certificate_required alert.  In that case the rejection is readable
	// on the first Read.  We handle both: immediate rejection (dialErr != nil)
	// and deferred rejection (dialErr == nil, Read fails).

	serverDone := make(chan struct{}, 1)
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return // listener already closed
		}
		// Drive the server-side handshake.  RequireAndVerifyClientCert means
		// this returns an error and sends an alert for the no-cert client.
		_ = conn.(*tls.Conn).Handshake()
		conn.Close()
	}()

	conn2, dialErr := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
		// No Certificates — client presents nothing.
	})

	var rejectErr error
	if dialErr != nil {
		// Server rejected during the handshake itself.
		rejectErr = dialErr
	} else {
		// tls.Dial returned nil: the client-side handshake completed before the
		// server sent its rejection alert.  Consume the alert via a Read.
		buf := make([]byte, 1)
		_, rejectErr = conn2.Read(buf)
		conn2.Close()
	}

	// Ensure the server goroutine has finished before the test exits.
	<-serverDone

	if rejectErr == nil {
		t.Fatal("no-cert client: expected handshake error, got nil")
	}
}

// ── LoadServerTLSConfig tests ─────────────────────────────────────────────────

func TestLoadServerTLSConfig_Valid(t *testing.T) {
	ca := mustCA(t)
	srv := mustServerCert(t, ca)

	cfg, err := tlsutil.LoadServerTLSConfig(ca.CertPEM, srv.CertPEM, srv.KeyPEM)
	if err != nil {
		t.Fatalf("LoadServerTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadServerTLSConfig returned nil")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", cfg.MinVersion)
	}
}

func TestLoadServerTLSConfig_WrongKey(t *testing.T) {
	ca := mustCA(t)
	srv1 := mustServerCert(t, ca)
	srv2 := mustServerCert(t, ca)

	// Cert from srv1, key from srv2 — mismatched pair.
	_, err := tlsutil.LoadServerTLSConfig(ca.CertPEM, srv1.CertPEM, srv2.KeyPEM)
	if err == nil {
		t.Fatal("expected error for mismatched cert/key pair, got nil")
	}
}

// ── CertGen tests ─────────────────────────────────────────────────────────────

func TestGenerateSelfSignedCA_IsCA(t *testing.T) {
	ca := mustCA(t)
	if !ca.Cert.IsCA {
		t.Error("generated CA cert: IsCA = false, want true")
	}
}

func TestGenerateSelfSignedCA_KeyUsage(t *testing.T) {
	ca := mustCA(t)
	want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if ca.Cert.KeyUsage&want != want {
		t.Errorf("KeyUsage = %v, want CertSign|CRLSign set", ca.Cert.KeyUsage)
	}
}

func TestGenerateSelfSignedCA_EmptyCN(t *testing.T) {
	_, err := tlsutil.GenerateSelfSignedCA(tlsutil.CAOptions{
		CN:       "",
		Validity: time.Hour,
	})
	if err == nil {
		t.Fatal("expected error for empty CN, got nil")
	}
}

func TestGenerateSelfSignedCA_ZeroValidity(t *testing.T) {
	_, err := tlsutil.GenerateSelfSignedCA(tlsutil.CAOptions{
		CN:       "Test CA",
		Validity: 0,
	})
	if err == nil {
		t.Fatal("expected error for zero validity, got nil")
	}
}

func TestGenerateLeafCert_SubjectFields(t *testing.T) {
	ca := mustCA(t)
	leaf, err := tlsutil.GenerateLeafCert(ca, tlsutil.LeafOptions{
		CN:           "bert@platform-team",
		Org:          "platform-team",
		OrgUnit:      "developer",
		SPIFFEID:     "spiffe://agentkms.org/team/platform-team/identity/bert",
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Validity:     time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	if leaf.Cert.Subject.CommonName != "bert@platform-team" {
		t.Errorf("CN = %q, want %q", leaf.Cert.Subject.CommonName, "bert@platform-team")
	}
	if len(leaf.Cert.Subject.Organization) == 0 || leaf.Cert.Subject.Organization[0] != "platform-team" {
		t.Errorf("O = %v, want [platform-team]", leaf.Cert.Subject.Organization)
	}
	if len(leaf.Cert.Subject.OrganizationalUnit) == 0 || leaf.Cert.Subject.OrganizationalUnit[0] != "developer" {
		t.Errorf("OU = %v, want [developer]", leaf.Cert.Subject.OrganizationalUnit)
	}
}

func TestGenerateLeafCert_SPIFFESANPresent(t *testing.T) {
	ca := mustCA(t)
	spiffeID := "spiffe://agentkms.org/team/platform-team/identity/bert"
	leaf, err := tlsutil.GenerateLeafCert(ca, tlsutil.LeafOptions{
		CN:           "bert@platform-team",
		SPIFFEID:     spiffeID,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Validity:     time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	if len(leaf.Cert.URIs) == 0 {
		t.Fatal("no URI SANs in generated cert, expected SPIFFE ID")
	}
	if leaf.Cert.URIs[0].String() != spiffeID {
		t.Errorf("URI SAN = %q, want %q", leaf.Cert.URIs[0].String(), spiffeID)
	}
}

func TestGenerateLeafCert_NotCA(t *testing.T) {
	ca := mustCA(t)
	leaf := mustClientCert(t, ca, "bert@platform-team")
	if leaf.Cert.IsCA {
		t.Error("leaf cert: IsCA = true, want false")
	}
}

func TestGenerateLeafCert_SignedByCA(t *testing.T) {
	ca := mustCA(t)
	leaf := mustClientCert(t, ca, "bert@platform-team")

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leaf.Cert.Verify(opts); err != nil {
		t.Errorf("leaf cert does not verify against CA: %v", err)
	}
}

func TestGenerateLeafCert_EmptyCN(t *testing.T) {
	ca := mustCA(t)
	_, err := tlsutil.GenerateLeafCert(ca, tlsutil.LeafOptions{
		CN:       "",
		Validity: time.Hour,
	})
	if err == nil {
		t.Fatal("expected error for empty CN, got nil")
	}
}
