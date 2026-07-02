package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentkms/agentkms/internal/auth"
)

// LocalSigner signs CSRs using a local CA (dev / bare-metal prod).
type LocalSigner struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
}

// LoadLocalSigner reads ca.crt and ca.key from dir.
func LoadLocalSigner(dir string) (*LocalSigner, error) {
	dir = strings.TrimRight(dir, "/")
	caCertPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("local signer: read ca.crt: %w", err)
	}
	caKeyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, fmt.Errorf("local signer: read ca.key: %w (run agentkms init)", err)
	}
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, fmt.Errorf("local signer: invalid ca.crt")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("local signer: invalid ca.key")
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &LocalSigner{caCert: caCert, caKey: caKey, caPEM: caCertPEM}, nil
}

// SignCert implements CSR signing for POST /auth/cert/issue.
func (s *LocalSigner) SignCert(_ context.Context, _role, csrPEM string) (*auth.CertBundle, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("local signer: invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("local signer: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("local signer: CSR signature invalid: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().Add(-time.Minute)
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	if notAfter.After(s.caCert.NotAfter) {
		notAfter = s.caCert.NotAfter
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("local signer: sign: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &auth.CertBundle{
		CertificatePEM: string(certPEM),
		CAPEM:          string(s.caPEM),
		SerialNumber:   fmt.Sprintf("%x", serial),
		ExpiresAt:      notAfter,
	}, nil
}

// ReadCAPEM returns the CA certificate PEM for /.well-known/agentkms-ca.
func ReadCAPEM(dir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, "ca.crt"))
}

// ListCerts returns an empty list in local dev mode.
func (s *LocalSigner) ListCerts(_ context.Context) ([]string, error) {
	return nil, nil
}

// FetchCert is not tracked in local dev mode.
func (s *LocalSigner) FetchCert(_ context.Context, _serial string) (string, error) {
	return "", fmt.Errorf("local signer: cert lookup not available")
}

// RevokeCert is a no-op in local dev mode.
func (s *LocalSigner) RevokeCert(_ context.Context, _serialNumber string) error {
	return nil
}

// FetchCRL returns an empty CRL signed by the local CA.
func (s *LocalSigner) FetchCRL(_ context.Context) ([]byte, error) {
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}, s.caCert, s.caKey)
}
