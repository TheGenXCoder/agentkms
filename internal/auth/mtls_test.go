package auth

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/agentkms/agentkms/pkg/identity"
	"github.com/agentkms/agentkms/pkg/tlsutil"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// testCA is a shared dev CA for all mtls tests in this package.
var testCA = func() *struct{ certPEM, keyPEM []byte } {
	certPEM, keyPEM, err := tlsutil.GenerateDevCA()
	if err != nil {
		panic("mtls_test: GenerateDevCA: " + err.Error())
	}
	return &struct{ certPEM, keyPEM []byte }{certPEM, keyPEM}
}()

// makeClientBundle issues a client certificate from the test CA.
func makeClientBundle(t *testing.T, callerID, teamID, role, spiffeURI string) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	cPEM, kPEM, err := tlsutil.IssueClientCert(testCA.certPEM, testCA.keyPEM, callerID, teamID, role, spiffeURI)
	if err != nil {
		t.Fatalf("IssueClientCert: %v", err)
	}
	parsed, err := tlsutil.DecodeCertPEM(cPEM)
	if err != nil {
		t.Fatalf("DecodeCertPEM: %v", err)
	}
	return cPEM, kPEM, parsed
}

// requestWithVerifiedChain creates an *http.Request whose TLS state has the
// given cert in VerifiedChains (simulating a successfully completed mTLS
// handshake as presented by Go's TLS stack).
func requestWithVerifiedChain(cert *x509.Certificate) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "/auth/session", nil)
	r.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{cert}},
	}
	return r
}

// ── IdentityFromTLS ───────────────────────────────────────────────────────────

func TestIdentityFromTLS_ValidCert(t *testing.T) {
	_, _, cert := makeClientBundle(t,
		"bert@dev", "dev-team", "developer",
		"spiffe://agentkms.local/dev/developer/bert@dev",
	)
	r := requestWithVerifiedChain(cert)

	id, err := IdentityFromTLS(r.TLS)
	if err != nil {
		t.Fatalf("IdentityFromTLS: %v", err)
	}
	if id.CallerID != "bert@dev" {
		t.Errorf("CallerID = %q, want bert@dev", id.CallerID)
	}
	if id.TeamID != "dev-team" {
		t.Errorf("TeamID = %q, want dev-team", id.TeamID)
	}
	if id.Role != identity.RoleDeveloper {
		t.Errorf("Role = %q, want developer", id.Role)
	}
	if id.SPIFFEID != "spiffe://agentkms.local/dev/developer/bert@dev" {
		t.Errorf("SPIFFEID = %q, unexpected", id.SPIFFEID)
	}
	if id.CertFingerprint == "" {
		t.Error("CertFingerprint is empty")
	}
	if id.Certificate == nil {
		t.Error("Certificate is nil")
	}
}

func TestIdentityFromTLS_NilTLSState(t *testing.T) {
	_, err := IdentityFromTLS(nil)
	if err == nil {
		t.Fatal("expected error for nil TLS state, got nil")
	}
}

func TestIdentityFromTLS_NoVerifiedChains(t *testing.T) {
	// VerifiedChains empty — as if client presented no cert.
	cs := &tls.ConnectionState{VerifiedChains: nil}
	_, err := IdentityFromTLS(cs)
	if err == nil {
		t.Fatal("expected error for empty VerifiedChains, got nil")
	}
}

func TestIdentityFromTLS_EmptyInnerChain(t *testing.T) {
	// Outer slice present but inner slice empty.
	cs := &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{}},
	}
	_, err := IdentityFromTLS(cs)
	if err == nil {
		t.Fatal("expected error for empty inner chain, got nil")
	}
}

func TestIdentityFromTLS_UsesVerifiedChains_NotPeerCertificates(t *testing.T) {
	// SECURITY: IdentityFromTLS must read from VerifiedChains, not PeerCertificates.
	// Construct a state where PeerCertificates has a cert but VerifiedChains is empty.
	// IdentityFromTLS must return an error (not extract identity from the unverified cert).
	_, _, cert := makeClientBundle(t, "attacker@evil", "evil-team", "developer", "")
	cs := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert}, // unverified
		VerifiedChains:   nil,                        // no verified chain
	}
	_, err := IdentityFromTLS(cs)
	if err == nil {
		t.Fatal("SECURITY: IdentityFromTLS accepted an unverified PeerCertificate — must require VerifiedChains")
	}
}

// ── MTLSCallerID ──────────────────────────────────────────────────────────────

func TestMTLSCallerID_Valid(t *testing.T) {
	_, _, cert := makeClientBundle(t, "bert@dev", "dev-team", "developer", "")
	cs := &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{cert}},
	}
	got := MTLSCallerID(cs)
	if got != "bert@dev" {
		t.Errorf("MTLSCallerID = %q, want bert@dev", got)
	}
}

func TestMTLSCallerID_NilState(t *testing.T) {
	if got := MTLSCallerID(nil); got != "" {
		t.Errorf("MTLSCallerID(nil) = %q, want empty", got)
	}
}

func TestMTLSCallerID_EmptyVerifiedChains(t *testing.T) {
	cs := &tls.ConnectionState{VerifiedChains: nil}
	if got := MTLSCallerID(cs); got != "" {
		t.Errorf("MTLSCallerID (no chains) = %q, want empty", got)
	}
}

func TestMTLSCallerID_UsesVerifiedChains_NotPeerCertificates(t *testing.T) {
	// SECURITY: must not return caller ID from an unverified PeerCertificate.
	_, _, cert := makeClientBundle(t, "attacker@evil", "evil-team", "developer", "")
	cs := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   nil,
	}
	if got := MTLSCallerID(cs); got != "" {
		t.Errorf("SECURITY: MTLSCallerID returned %q from unverified cert — must use VerifiedChains", got)
	}
}

// ── GetConnectionCertFingerprint ──────────────────────────────────────────────

func TestGetConnectionCertFingerprint_Valid(t *testing.T) {
	_, _, cert := makeClientBundle(t, "bert@dev", "dev-team", "developer", "")
	cs := &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{cert}},
	}
	fp := GetConnectionCertFingerprint(cs)
	if fp == "" {
		t.Fatal("fingerprint is empty for valid cert")
	}
	if len(fp) != 64 {
		t.Errorf("fingerprint length = %d, want 64 (SHA-256 hex)", len(fp))
	}
}

func TestGetConnectionCertFingerprint_Deterministic(t *testing.T) {
	// Same cert must always produce the same fingerprint.
	_, _, cert := makeClientBundle(t, "bert@dev", "dev-team", "developer", "")
	cs := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
	fp1 := GetConnectionCertFingerprint(cs)
	fp2 := GetConnectionCertFingerprint(cs)
	if fp1 != fp2 {
		t.Errorf("fingerprint is not deterministic: %q vs %q", fp1, fp2)
	}
}

func TestGetConnectionCertFingerprint_DifferentCertsDifferentFingerprints(t *testing.T) {
	_, _, cert1 := makeClientBundle(t, "alice@dev", "dev-team", "developer", "")
	_, _, cert2 := makeClientBundle(t, "bob@dev", "dev-team", "developer", "")
	fp1 := GetConnectionCertFingerprint(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert1}}})
	fp2 := GetConnectionCertFingerprint(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert2}}})
	if fp1 == fp2 {
		t.Error("different certs produced the same fingerprint")
	}
}

func TestGetConnectionCertFingerprint_NilState(t *testing.T) {
	if fp := GetConnectionCertFingerprint(nil); fp != "" {
		t.Errorf("fingerprint for nil state = %q, want empty", fp)
	}
}

func TestGetConnectionCertFingerprint_UsesVerifiedChains(t *testing.T) {
	// SECURITY: must not return fingerprint from unverified PeerCertificate.
	_, _, cert := makeClientBundle(t, "attacker@evil", "evil-team", "developer", "")
	cs := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   nil,
	}
	if fp := GetConnectionCertFingerprint(cs); fp != "" {
		t.Errorf("SECURITY: GetConnectionCertFingerprint returned %q from unverified cert", fp)
	}
}

// ── IssueClientCert certificate validity ─────────────────────────────────────

func TestIssueClientCert_NotExpired(t *testing.T) {
	_, _, cert := makeClientBundle(t, "bert@dev", "dev-team", "developer", "")
	now := time.Now().UTC()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		t.Errorf("cert validity window does not include now: [%v, %v]", cert.NotBefore, cert.NotAfter)
	}
}

func TestIssueClientCert_VerifiesAgainstCA(t *testing.T) {
	_, _, cert := makeClientBundle(t, "bert@dev", "dev-team", "developer", "")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(testCA.certPEM)
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("cert does not verify against test CA: %v", err)
	}
}
