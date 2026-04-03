package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

// CertBundle holds a certificate and its ECDSA P-256 private key in both
// parsed form and PEM-encoded form.
//
// SECURITY NOTE: KeyPEM contains the private key material.  Write it to disk
// with mode 0600 and never log, print, or include it in error messages.
type CertBundle struct {
	// CertPEM is the PEM-encoded DER certificate.  Safe to log and distribute.
	CertPEM []byte

	// KeyPEM is the PEM-encoded EC private key.  MUST NOT be logged or
	// included in any API response, error message, or audit event.
	KeyPEM []byte

	// Cert is the parsed X.509 certificate.  Same data as CertPEM.
	Cert *x509.Certificate

	// PrivKey is the parsed ECDSA private key.  Same data as KeyPEM.
	// Access to this field is intentionally narrow: only this package and
	// cmd/enroll use it for certificate signing.
	PrivKey *ecdsa.PrivateKey
}

// CAOptions controls the properties of a generated CA certificate.
type CAOptions struct {
	// CN is the Common Name of the CA (e.g. "AgentKMS Dev CA").
	CN string

	// Org is the Organisation field (e.g. "agentkms-dev").
	Org string

	// Validity is how long the CA certificate is valid.
	Validity time.Duration
}

// LeafOptions controls the properties of a generated leaf certificate.
type LeafOptions struct {
	// CN is the Common Name (e.g. "bert@platform-team").
	CN string

	// Org is the Organisation field, used as TeamID (e.g. "platform-team").
	Org string

	// OrgUnit is the Organisational Unit, used as Role (e.g. "developer").
	OrgUnit string

	// SPIFFEID is an optional SPIFFE ID to include as a SAN URI.
	// Example: "spiffe://agentkms.org/team/dev/identity/bert"
	SPIFFEID string

	// DNSNames are additional DNS SANs (e.g. "localhost").
	DNSNames []string

	// IPAddresses are IP address SANs (e.g. 127.0.0.1).
	IPAddresses []net.IP

	// ExtKeyUsages determines the extended key usage of the leaf certificate.
	// Use x509.ExtKeyUsageClientAuth for developer/service certs.
	// Use x509.ExtKeyUsageServerAuth for server certs.
	// Use both for certs that serve as either.
	ExtKeyUsages []x509.ExtKeyUsage

	// Validity is how long the leaf certificate is valid.
	Validity time.Duration
}

// GenerateSelfSignedCA generates a new ECDSA P-256 self-signed CA certificate
// and private key.
//
// The CA has KeyUsage = CertSign | CRLSign and IsCA = true.  Use the returned
// CertBundle to sign leaf certificates with GenerateLeafCert.
func GenerateSelfSignedCA(opts CAOptions) (*CertBundle, error) {
	if opts.CN == "" {
		return nil, fmt.Errorf("tlsutil: CA Common Name must not be empty")
	}
	if opts.Validity <= 0 {
		return nil, fmt.Errorf("tlsutil: CA validity must be positive")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: generating CA key: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.CN,
			Organization: nonEmpty(opts.Org),
		},
		NotBefore:             now.Add(-30 * time.Second), // clock-skew tolerance
		NotAfter:              now.Add(opts.Validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-signed: parent == template, signer == leaf key.
	return encodeBundle(tmpl, tmpl, priv, priv)
}

// GenerateLeafCert generates an ECDSA P-256 leaf certificate signed by the
// provided CA bundle.
//
// This is used to generate developer certs, service certs, and server certs
// for local dev mode.
func GenerateLeafCert(ca *CertBundle, opts LeafOptions) (*CertBundle, error) {
	if opts.CN == "" {
		return nil, fmt.Errorf("tlsutil: leaf Common Name must not be empty")
	}
	if opts.Validity <= 0 {
		return nil, fmt.Errorf("tlsutil: leaf validity must be positive")
	}

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: generating leaf key: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         opts.CN,
			Organization:       nonEmpty(opts.Org),
			OrganizationalUnit: nonEmpty(opts.OrgUnit),
		},
		NotBefore:             now.Add(-30 * time.Second),
		NotAfter:              now.Add(opts.Validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           opts.ExtKeyUsages,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              opts.DNSNames,
		IPAddresses:           opts.IPAddresses,
	}

	if opts.SPIFFEID != "" {
		u, err := url.Parse(opts.SPIFFEID)
		if err != nil {
			return nil, fmt.Errorf("tlsutil: parsing SPIFFE ID %q: %w", opts.SPIFFEID, err)
		}
		tmpl.URIs = []*url.URL{u}
	}

	// CA-signed: parent == CA cert, leaf key signs nothing (CA key signs).
	return encodeBundle(tmpl, ca.Cert, leafPriv, ca.PrivKey)
}

// GenerateCRL creates a DER-encoded CRL signed by the provided CA.
func GenerateCRL(ca *CertBundle, revoked []x509.RevocationListEntry) ([]byte, error) {
	now := time.Now().UTC()
	tmpl := &x509.RevocationList{
		Number:                     big.NewInt(1),
		ThisUpdate:                 now,
		NextUpdate:                 now.Add(24 * time.Hour),
		RevokedCertificateEntries: revoked,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.Cert, ca.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: creating CRL: %w", err)
	}

	return crlDER, nil
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// encodeBundle signs tmpl (using signerKey against parent) and encodes
// leafPriv as the private key.  For self-signed CAs, leafPriv == signerKey.
// For CA-issued leaf certs, leafPriv is the new leaf key; signerKey is the CA.
func encodeBundle(
	tmpl *x509.Certificate,
	parent *x509.Certificate,
	leafPriv *ecdsa.PrivateKey,
	signerKey *ecdsa.PrivateKey,
) (*CertBundle, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &leafPriv.PublicKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: creating certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: parsing certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(leafPriv)
	if err != nil {
		// SECURITY: never include key material bytes in error messages.
		return nil, fmt.Errorf("tlsutil: marshalling private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return &CertBundle{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Cert:    cert,
		PrivKey: leafPriv,
	}, nil
}

// newSerial generates a cryptographically random 128-bit certificate serial
// number.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: generating serial number: %w", err)
	}
	return serial, nil
}

// nonEmpty wraps s in a []string slice if non-empty, else returns nil.
// Used to set optional certificate subject fields cleanly.
func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
