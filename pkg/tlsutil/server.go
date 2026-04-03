// Package tlsutil provides mTLS server configuration helpers and client
// certificate parsing utilities.
//
// TLS 1.3 minimum.  Client certificates are required and verified against
// the provided CA pool.  SPIFFE SVIDs are parsed from SAN URIs by
// internal/auth/mtls.go.
//
// Backlog: A-01 (server setup), A-02 (identity extraction).
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// ServerTLSConfig returns a *tls.Config suitable for an mTLS server.
//
// Security requirements enforced:
//   - TLS 1.3 is the minimum version; TLS 1.2 and below are rejected.
//   - Client certificate is required at the TLS handshake level.
//   - Client certificate must verify against the CAs in caCertPEM.
//   - The server presents serverCert to clients.
//
// caCertPEM must contain one or more PEM-encoded X.509 CA certificates that
// form the trust anchor for client certs.  In dev mode this is the locally
// generated dev CA.  In production this is the team Intermediate CA pool.
//
// Returns an error if caCertPEM contains no valid certificates.
//
// A-01.
func ServerTLSConfig(caCertPEM []byte, serverCert tls.Certificate) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("tlsutil: no valid CA certificates found in PEM")
	}

	return &tls.Config{
		// TLS 1.3 only.  TLS 1.2 has known weaknesses (BEAST, LUCKY13,
		// POODLE, DROWN) and its cipher suite negotiation is complex.
		// TLS 1.3 eliminates all of these and is universally supported by
		// any client we would accept (Go 1.18+, Node 18+, OpenSSL 1.1.1+).
		MinVersion: tls.VersionTLS13,

		// RequireAndVerifyClientCert: the handshake fails immediately if the
		// client does not present a certificate, or if the presented certificate
		// does not chain to a CA in ClientCAs.  This is the mTLS enforcement
		// point — no request reaches the HTTP layer without a verified cert.
		ClientAuth: tls.RequireAndVerifyClientCert,

		// ClientCAs is the pool of trusted CAs for client certificate
		// verification.  Only certificates chaining to these CAs are accepted.
		ClientCAs: pool,

		// Certificates is the list of server certificates presented to clients.
		Certificates: []tls.Certificate{serverCert},
	}, nil
}

// ClientTLSConfig builds a strict tls.Config for client connections (e.g. to Vault).
//
// Like ServerTLSConfig, it enforces TLS 1.3 as the minimum version.
// It configures the provided client cert/key for mutual TLS authentication
// and verifies the server's certificate against the provided CA bundle.
//
// Parameters:
//   - caCertPEM: PEM-encoded CA certificate(s) to verify the server against.
//   - clientCertPEM, clientKeyPEM: PEM-encoded leaf certificate and private key.
func ClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM []byte) (*tls.Config, error) {
	// 1. Build the CA pool for verifying the server.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, errors.New("tlsutil: failed to parse root CA certificates")
	}

	// 2. Parse the client's mTLS certificate.
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: parse client key pair: %w", err)
	}

	// 3. Construct the config with strict defaults.
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}
	return cfg, nil
}

// LoadServerTLSConfig is a convenience wrapper that loads the server
// certificate and key from PEM bytes and calls ServerTLSConfig.
//
// certPEM and keyPEM are the PEM-encoded server certificate and private key
// respectively.  caCertPEM is the CA pool for client verification.
func LoadServerTLSConfig(caCertPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// SECURITY: do not include key material in the error.
		return nil, fmt.Errorf("tlsutil: loading server certificate: %w", err)
	}
	return ServerTLSConfig(caCertPEM, serverCert)
}
