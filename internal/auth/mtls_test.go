package auth_test

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/pkg/identity"
	"github.com/agentkms/agentkms/pkg/tlsutil"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// testCA is a shared CA for all auth package tests.
var testCA = func() *tlsutil.CertBundle {
	ca, err := tlsutil.GenerateSelfSignedCA(tlsutil.CAOptions{
		CN:       "AgentKMS Test CA",
		Org:      "test",
		Validity: 24 * time.Hour,
	})
	if err != nil {
		panic("testCA: " + err.Error())
	}
	return ca
}()

// makeClientCert generates a client certificate signed by testCA and returns
// a request with the certificate in its TLS state.
func makeClientCert(t *testing.T, cn, org, ou, spiffeID string) (*tlsutil.CertBundle, *http.Request) {
	t.Helper()
	opts := tlsutil.LeafOptions{
		CN:           cn,
		Org:          org,
		OrgUnit:      ou,
		SPIFFEID:     spiffeID,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Validity:     time.Hour,
	}
	bundle, err := tlsutil.GenerateLeafCert(testCA, opts)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	r := requestWithCert(t, bundle.Cert)
	return bundle, r
}

// requestWithCert creates an *http.Request whose TLS state carries cert as
// the verified client certificate.
func requestWithCert(t *testing.T, cert *x509.Certificate) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "/auth/session", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	r.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{cert}},
	}
	return r
}

// ── ExtractIdentity tests ─────────────────────────────────────────────────────

func TestExtractIdentity_ValidCert(t *testing.T) {
	bundle, r := makeClientCert(t,
		"bert@platform-team",
		"platform-team",
		"developer",
		"spiffe://agentkms.org/team/platform-team/identity/bert",
	)

	id, err := auth.ExtractIdentity(r)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}

	if id.CallerID != "bert@platform-team" {
		t.Errorf("CallerID = %q, want %q", id.CallerID, "bert@platform-team")
	}
	if id.TeamID != "platform-team" {
		t.Errorf("TeamID = %q, want %q", id.TeamID, "platform-team")
	}
	if id.Role != identity.RoleDeveloper {
		t.Errorf("Role = %q, want %q", id.Role, identity.RoleDeveloper)
	}
	if id.SPIFFEID != "spiffe://agentkms.org/team/platform-team/identity/bert" {
		t.Errorf("SPIFFEID = %q, want SPIFFE URI", id.SPIFFEID)
	}

	// Fingerprint should be the SHA-256 of the cert's raw DER bytes.
	wantFP := hex.EncodeToString(func() []byte {
		h := sha256.Sum256(bundle.Cert.Raw)
		return h[:]
	}())
	if id.CertFingerprint != wantFP {
		t.Errorf("CertFingerprint = %q, want %q", id.CertFingerprint, wantFP)
	}
}

func TestExtractIdentity_NoTLSState(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "/auth/session", nil)
	// r.TLS is nil — no TLS at all.

	_, err := auth.ExtractIdentity(r)
	if err == nil {
		t.Fatal("expected error for request with no TLS state, got nil")
	}
}

func TestExtractIdentity_NoVerifiedChains(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "/auth/session", nil)
	r.TLS = &tls.ConnectionState{
		VerifiedChains: nil, // no client cert presented
	}

	_, err := auth.ExtractIdentity(r)
	if err == nil {
		t.Fatal("expected error for no verified chains, got nil")
	}
}

func TestExtractIdentity_EmptyVerifiedChain(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "/auth/session", nil)
	r.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{}}, // chain exists but is empty
	}

	_, err := auth.ExtractIdentity(r)
	if err == nil {
		t.Fatal("expected error for empty verified chain, got nil")
	}
}

func TestExtractIdentity_MissingCN(t *testing.T) {
	// Build a cert with empty CN.  We can't easily do this with
	// GenerateLeafCert (it requires CN), so we test with a manually built cert.
	bundle, err := tlsutil.GenerateLeafCert(testCA, tlsutil.LeafOptions{
		CN: " ", // whitespace-only — trimmed to empty
		// This should succeed at cert generation but fail at identity extraction.
		Org:          "platform-team",
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Validity:     time.Hour,
	})
	// GenerateLeafCert might reject empty CN — either outcome is acceptable;
	// what matters is that we never produce an identity without a CallerID.
	if err != nil {
		// Generation rejected it — that's fine, security constraint enforced early.
		return
	}

	r := requestWithCert(t, bundle.Cert)
	_, err = auth.ExtractIdentity(r)
	if err == nil {
		t.Fatal("expected error for cert with whitespace-only CN, got nil")
	}
}

func TestExtractIdentity_SPIFFEWorkloadMapping(t *testing.T) {
	tests := []struct {
		name     string
		spiffeID string
		wantTeam string
		wantRole identity.Role
	}{
		{
			name:     "AgentKMS Team SPIFFE",
			spiffeID: "spiffe://agentkms.org/team/platform-team/identity/bert",
			wantTeam: "platform-team",
			wantRole: identity.RoleService, // No OU field, defaults to RoleService for SPIFFE
		},
		{
			name:     "K8s Namespace SPIFFE",
			spiffeID: "spiffe://cluster.local/ns/payments/sa/processor",
			wantTeam: "k8s-payments",
			wantRole: identity.RoleService,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No Org field in LeafOptions to test SPIFFE mapping
			bundle, err := tlsutil.GenerateLeafCert(testCA, tlsutil.LeafOptions{
				CN:           "workload",
				Org:          "", // Deliberately empty
				SPIFFEID:     tt.spiffeID,
				ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				Validity:     time.Hour,
			})
			if err != nil {
				t.Fatalf("GenerateLeafCert: %v", err)
			}

			r := requestWithCert(t, bundle.Cert)
			id, err := auth.ExtractIdentity(r)
			if err != nil {
				t.Fatalf("ExtractIdentity: %v", err)
			}

			if id.TeamID != tt.wantTeam {
				t.Errorf("TeamID = %q, want %q", id.TeamID, tt.wantTeam)
			}
			if id.Role != tt.wantRole {
				t.Errorf("Role = %q, want %q", id.Role, tt.wantRole)
			}
			if id.SPIFFEID != tt.spiffeID {
				t.Errorf("SPIFFEID = %q, want %q", id.SPIFFEID, tt.spiffeID)
			}
		})
	}
}

func TestExtractIdentity_MissingOrgAndSPIFFE(t *testing.T) {
	// Build a cert with no Org and no SPIFFE SAN.
	bundle, err := tlsutil.GenerateLeafCert(testCA, tlsutil.LeafOptions{
		CN:           "bert@platform-team",
		Org:          "", // deliberately omitted
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Validity:     time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	r := requestWithCert(t, bundle.Cert)
	_, err = auth.ExtractIdentity(r)
	if err == nil {
		t.Fatal("expected error for cert with no Organisation field AND no SPIFFE ID, got nil")
	}
}

func TestExtractIdentity_RoleService(t *testing.T) {
	_, r := makeClientCert(t, "runner@payments-team", "payments-team", "service", "")
	id, err := auth.ExtractIdentity(r)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	if id.Role != identity.RoleService {
		t.Errorf("Role = %q, want %q", id.Role, identity.RoleService)
	}
}

func TestExtractIdentity_RoleAgent(t *testing.T) {
	_, r := makeClientCert(t, "session@platform-team", "platform-team", "agent", "")
	id, err := auth.ExtractIdentity(r)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	if id.Role != identity.RoleAgent {
		t.Errorf("Role = %q, want %q", id.Role, identity.RoleAgent)
	}
}

func TestExtractIdentity_UnknownOUDefaultsDeveloper(t *testing.T) {
	_, r := makeClientCert(t, "bert@platform-team", "platform-team", "wizard", "")
	id, err := auth.ExtractIdentity(r)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	if id.Role != identity.RoleDeveloper {
		t.Errorf("Role = %q, want RoleDeveloper for unknown OU", id.Role)
	}
}

func TestExtractIdentity_NoSPIFFE(t *testing.T) {
	_, r := makeClientCert(t, "bert@platform-team", "platform-team", "developer", "")
	id, err := auth.ExtractIdentity(r)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	if id.SPIFFEID != "" {
		t.Errorf("SPIFFEID = %q, want empty for cert with no SPIFFE SAN", id.SPIFFEID)
	}
}

func TestExtractIdentity_FingerprintStable(t *testing.T) {
	// Calling ExtractIdentity twice on the same cert must return the same
	// fingerprint — it must be deterministic (SHA-256 of raw DER bytes).
	bundle, r1 := makeClientCert(t, "bert@platform-team", "platform-team", "developer", "")
	r2 := requestWithCert(t, bundle.Cert)

	id1, err := auth.ExtractIdentity(r1)
	if err != nil {
		t.Fatalf("call 1: %v", err)
	}
	id2, err := auth.ExtractIdentity(r2)
	if err != nil {
		t.Fatalf("call 2: %v", err)
	}

	if id1.CertFingerprint != id2.CertFingerprint {
		t.Errorf("fingerprint is not stable: %q vs %q", id1.CertFingerprint, id2.CertFingerprint)
	}
}

func TestExtractIdentity_DifferentCertsHaveDifferentFingerprints(t *testing.T) {
	_, r1 := makeClientCert(t, "bert@platform-team", "platform-team", "developer", "")
	_, r2 := makeClientCert(t, "alice@platform-team", "platform-team", "developer", "")

	id1, err := auth.ExtractIdentity(r1)
	if err != nil {
		t.Fatalf("call 1: %v", err)
	}
	id2, err := auth.ExtractIdentity(r2)
	if err != nil {
		t.Fatalf("call 2: %v", err)
	}

	if id1.CertFingerprint == id2.CertFingerprint {
		t.Error("different certs produced the same fingerprint")
	}
}
