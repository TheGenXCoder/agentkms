package auth_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/agentkms/agentkms/pkg/tlsutil"
)

// mustClientCert generates a client TLS certificate signed by ca with the
// given common name, using standard developer role/org defaults.
//
// It is a convenience wrapper around tlsutil.GenerateLeafCert for test code
// that only needs to vary the CN.  The returned bundle's .Cert field is the
// *x509.Certificate.
//
// Fatal on any generation error.
func mustClientCert(t *testing.T, ca *tlsutil.CertBundle, cn string) *tlsutil.CertBundle {
	t.Helper()
	bundle, err := tlsutil.GenerateLeafCert(ca, tlsutil.LeafOptions{
		CN:           cn,
		Org:          "platform-team",
		OrgUnit:      "developer",
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Validity:     time.Hour,
	})
	if err != nil {
		t.Fatalf("mustClientCert(%q): %v", cn, err)
	}
	return bundle
}
