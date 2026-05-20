package auth_test

// mtls_principal_test.go — Phase 1 zero-trust identity rollout: verify that
// the SPIFFE URI parser in identityFromCert correctly extracts the multi-
// principal segments and that the legacy device-only shape still resolves
// to a working identity.

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/pkg/tlsutil"
)

// TestExtractIdentity_NewStyleSPIFFE_UserAndDevice proves the new convention:
// a cert SAN of shape spiffe://<td>/tenant/<t>/user/<u>/device/<d> populates
// UserID, DeviceID, Tenant — and CallerID resolves to the user (so policy
// rules that match on user_id work across multiple device certs for the same
// human).
func TestExtractIdentity_NewStyleSPIFFE_UserAndDevice(t *testing.T) {
	bundle, err := tlsutil.GenerateLeafCert(testCA, tlsutil.LeafOptions{
		CN:           "bert-tp-dev",
		Org:          "platform-team",
		OrgUnit:      "developer",
		SPIFFEID:     "spiffe://catalyst9.local/tenant/catalyst9/user/bert/device/bert-tp-dev",
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

	if id.UserID != "bert" {
		t.Errorf("UserID = %q, want %q", id.UserID, "bert")
	}
	if id.DeviceID != "bert-tp-dev" {
		t.Errorf("DeviceID = %q, want %q", id.DeviceID, "bert-tp-dev")
	}
	if id.Tenant != "catalyst9" {
		t.Errorf("Tenant = %q, want %q", id.Tenant, "catalyst9")
	}
	// CallerID prefers UserID for new-style certs so the legacy "sub" claim
	// resolves to the same value across all of bert's device certs.
	if id.CallerID != "bert" {
		t.Errorf("CallerID = %q, want %q (should equal UserID for new-style certs)", id.CallerID, "bert")
	}
}

// TestExtractIdentity_LegacySPIFFE_DeviceOnly proves the backward-compat path:
// a cert with the legacy shape spiffe://<td>/tenant/<t>/device/<d> still
// produces a working Identity, with UserID == DeviceID == cert CN.  This is
// the load-bearing guarantee for users who haven't re-issued their cert yet.
func TestExtractIdentity_LegacySPIFFE_DeviceOnly(t *testing.T) {
	bundle, err := tlsutil.GenerateLeafCert(testCA, tlsutil.LeafOptions{
		CN:           "bert-tp-dev",
		Org:          "platform-team",
		OrgUnit:      "developer",
		SPIFFEID:     "spiffe://catalyst9.local/tenant/catalyst9/device/bert-tp-dev",
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

	if id.DeviceID != "bert-tp-dev" {
		t.Errorf("DeviceID = %q, want %q", id.DeviceID, "bert-tp-dev")
	}
	if id.Tenant != "catalyst9" {
		t.Errorf("Tenant = %q, want %q", id.Tenant, "catalyst9")
	}
	// For legacy certs, UserID is populated to the device value so audit
	// and policy still have a stable principal handle — but it equals the
	// device, which is how downstream code can detect the legacy case.
	if id.UserID != "bert-tp-dev" {
		t.Errorf("UserID = %q, want %q (legacy: equal to DeviceID)", id.UserID, "bert-tp-dev")
	}
	// CallerID stays equal to the CN for legacy certs — this preserves the
	// existing "sub claim equals CN" contract that pre-Phase-1 consumers rely on.
	if id.CallerID != "bert-tp-dev" {
		t.Errorf("CallerID = %q, want %q (legacy: equal to CN)", id.CallerID, "bert-tp-dev")
	}
}

// TestExtractIdentity_UnknownSPIFFE_FallsBackToCN proves the third leg of the
// parse tripod: a SPIFFE URI that doesn't match either the new or legacy
// convention is ignored, and the CN-based CallerID path takes over.  Without
// this fallback, every non-SPIFFE cert (and every workload URI from the
// existing K8s mapper) would suddenly start producing empty UserID/DeviceID.
func TestExtractIdentity_UnknownSPIFFE_FallsBackToCN(t *testing.T) {
	bundle, err := tlsutil.GenerateLeafCert(testCA, tlsutil.LeafOptions{
		CN:           "ci-runner",
		Org:          "payments-team",
		OrgUnit:      "service",
		SPIFFEID:     "spiffe://cluster.local/ns/payments/sa/processor",
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

	// New fields are empty when the URI shape isn't recognised.
	if id.UserID != "" {
		t.Errorf("UserID = %q, want empty (URI not in new/legacy shape)", id.UserID)
	}
	if id.DeviceID != "" {
		t.Errorf("DeviceID = %q, want empty (URI not in new/legacy shape)", id.DeviceID)
	}
	if id.Tenant != "" {
		t.Errorf("Tenant = %q, want empty (URI not in new/legacy shape)", id.Tenant)
	}
	// CallerID falls back to CN exactly like before this change.
	if id.CallerID != "ci-runner" {
		t.Errorf("CallerID = %q, want %q", id.CallerID, "ci-runner")
	}
}
