package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestCertRevocationChecker(t *testing.T) {
	checker := NewCertRevocationChecker()

	serial := big.NewInt(12345)

	if checker.IsRevoked(nil) {
		t.Error("Expected nil serial not to be revoked")
	}

	if checker.IsRevoked(serial) {
		t.Error("Expected serial not to be revoked initially")
	}

	// Generate a dummy CRL for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}

	revokedCerts := []x509.RevocationListEntry{
		{
			SerialNumber:   serial,
			RevocationTime: time.Now(),
		},
	}

	crlTemplate := &x509.RevocationList{
		SignatureAlgorithm: x509.SHA256WithRSA,
		RevokedCertificateEntries: revokedCerts,
		Number: big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(1 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}

	if err := checker.UpdateFromCRL(crlDER); err != nil {
		t.Fatalf("Failed to update from CRL: %v", err)
	}

	if !checker.IsRevoked(serial) {
		t.Error("Expected serial to be revoked after CRL update")
	}

	unrevokedSerial := big.NewInt(54321)
	if checker.IsRevoked(unrevokedSerial) {
		t.Error("Expected other serial not to be revoked")
	}
}

func TestCertRevocationChecker_InvalidCRL(t *testing.T) {
	checker := NewCertRevocationChecker()
	if err := checker.UpdateFromCRL([]byte("invalid")); err == nil {
		t.Error("Expected error for invalid CRL, got nil")
	}
}
