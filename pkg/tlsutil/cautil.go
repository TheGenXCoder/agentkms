// Package tlsutil provides mTLS server configuration helpers and client
// certificate parsing utilities.
//
// TLS 1.3 minimum.  Client certificates are required and verified against
// the team Intermediate CA.  SPIFFE SVIDs are parsed from SAN URIs.
//
// Backlog: A-01 (server setup), A-02 (identity extraction).
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

// ── PEM helpers ───────────────────────────────────────────────────────────────

// EncodeCertPEM DER-encodes cert and wraps it in a PEM CERTIFICATE block.
func EncodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// EncodeKeyPEM serialises key as PKCS#8 and wraps it in a PEM PRIVATE KEY block.
//
// SECURITY: The returned PEM bytes contain private key material.  They must
// be written to a file with mode 0600 and never logged or transmitted.
func EncodeKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// DecodeCertPEM parses the first CERTIFICATE PEM block from pemBytes.
func DecodeCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("tlsutil: no CERTIFICATE PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: parse certificate: %w", err)
	}
	return cert, nil
}

// DecodeKeyPEM parses the first PRIVATE KEY PEM block from pemBytes (PKCS#8 ECDSA).
func DecodeKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("tlsutil: no PRIVATE KEY PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: parse private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("tlsutil: expected ECDSA key, got %T", key)
	}
	return ecKey, nil
}

// LoadCertPool builds an *x509.CertPool containing the CA certificate from
// caCertPEM.  Returns an error if the PEM is malformed or cannot be parsed.
func LoadCertPool(caCertPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("tlsutil: failed to append CA certificate to pool")
	}
	return pool, nil
}

// ── Certificate generation ────────────────────────────────────────────────────

// GenerateDevCA creates a new ECDSA P-256 self-signed CA certificate for local
// development.  Returns PEM-encoded certificate and PEM-encoded PKCS#8 key.
//
// The CA is valid for 10 years from now.  This is acceptable for a local dev
// CA that is only trusted by the local agentkms-dev server and has no
// authority in staging or production.
//
// SECURITY: The returned keyPEM contains private key material.  Write it to
// ~/.agentkms/dev/ca.key with mode 0600 and never transmit it.
func GenerateDevCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "AgentKMS Dev CA",
			Organization: []string{"AgentKMS Dev"},
		},
		SubjectKeyId:          pubKeyID(&key.PublicKey),
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: parse generated CA certificate: %w", err)
	}

	certPEM = EncodeCertPEM(cert)
	keyPEM, err = EncodeKeyPEM(key)
	return certPEM, keyPEM, err
}

// IssueServerCert issues a TLS server certificate signed by the given CA.
// The certificate is valid for 1 year and always includes SANs for
// "localhost", 127.0.0.1, and ::1.
//
// extraHosts adds additional DNS names or IP addresses to the SANs.  Pass nil
// for a plain localhost-only certificate.
func IssueServerCert(caCertPEM, caKeyPEM []byte, extraHosts []string) (certPEM, keyPEM []byte, err error) {
	caCert, caKey, err := loadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: generate server key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	dnsNames := []string{"localhost"}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	for _, h := range extraHosts {
		if ip := net.ParseIP(h); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"AgentKMS Dev"},
		},
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
		NotBefore:   now,
		NotAfter:    now.Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: create server certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: parse generated server certificate: %w", err)
	}

	certPEM = EncodeCertPEM(cert)
	keyPEM, err = EncodeKeyPEM(key)
	return certPEM, keyPEM, err
}

// IssueClientCert issues an mTLS client certificate signed by the given CA.
// The certificate encodes the AgentKMS identity in Subject fields:
//   - CN = callerID (e.g. "bert@dev")
//   - O  = teamID   (e.g. "dev-team")
//   - OU = role     (e.g. "developer")
//
// spiffeURI, if non-empty, is added as a URI Subject Alternative Name.
// Expected format: "spiffe://agentkms.local/dev/developer/{username}"
//
// The certificate is valid for 1 year from now.
func IssueClientCert(caCertPEM, caKeyPEM []byte, callerID, teamID, role, spiffeURI string) (certPEM, keyPEM []byte, err error) {
	caCert, caKey, err := loadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: generate client key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         callerID,
			Organization:       []string{teamID},
			OrganizationalUnit: []string{role},
		},
		NotBefore:   now,
		NotAfter:    now.Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if spiffeURI != "" {
		u, err := url.Parse(spiffeURI)
		if err != nil {
			return nil, nil, fmt.Errorf("tlsutil: invalid SPIFFE URI %q: %w", spiffeURI, err)
		}
		if u.Scheme != "spiffe" {
			return nil, nil, fmt.Errorf("tlsutil: SPIFFE URI must use 'spiffe' scheme, got %q", u.Scheme)
		}
		tmpl.URIs = []*url.URL{u}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: create client certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: parse generated client certificate: %w", err)
	}

	certPEM = EncodeCertPEM(cert)
	keyPEM, err = EncodeKeyPEM(key)
	return certPEM, keyPEM, err
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// loadCA decodes a CA certificate and key from PEM, then verifies the key
// matches the certificate's public key.
func loadCA(caCertPEM, caKeyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caCert, err := DecodeCertPEM(caCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: decode CA cert: %w", err)
	}
	caKey, err := DecodeKeyPEM(caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: decode CA key: %w", err)
	}
	// Verify the key matches the certificate's public key.
	caPub, ok := caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("tlsutil: CA certificate does not use ECDSA key")
	}
	if caPub.X.Cmp(caKey.PublicKey.X) != 0 || caPub.Y.Cmp(caKey.PublicKey.Y) != 0 {
		return nil, nil, fmt.Errorf("tlsutil: CA private key does not match CA certificate public key")
	}
	return caCert, caKey, nil
}

// randomSerial returns a cryptographically random 128-bit certificate serial
// number, satisfying RFC 5280 §4.1.2.2.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: generate serial number: %w", err)
	}
	return serial, nil
}

// pubKeyID computes a Subject Key Identifier for an ECDSA public key.
// Uses the first 20 bytes of SHA-256(PKIX-encoded public key), which is a
// non-security-critical identifier per RFC 5280 §4.2.1.2.
// (SHA-1 would be equally acceptable here per the RFC; SHA-256 is used to
// avoid importing crypto/sha1 in a security-sensitive package.)
func pubKeyID(pub *ecdsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil // unreachable for valid P-256 keys
	}
	h := sha256.Sum256(der)
	return h[:20] // 20 bytes matches the conventional SubjectKeyIdentifier length
}
