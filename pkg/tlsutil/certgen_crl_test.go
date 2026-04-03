package tlsutil

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestGenerateCRL(t *testing.T) {
	ca, err := GenerateSelfSignedCA(CAOptions{CN: "test-ca", Validity: 24 * time.Hour})
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	revoked := []x509.RevocationListEntry{
		{
			SerialNumber:   big.NewInt(12345),
			RevocationTime: time.Now(),
		},
	}

	crlDER, err := GenerateCRL(ca, revoked)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v", err)
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("Expected 1 revoked cert, got %d", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(12345)) != 0 {
		t.Errorf("Expected serial 12345, got %v", crl.RevokedCertificateEntries[0].SerialNumber)
	}
}
