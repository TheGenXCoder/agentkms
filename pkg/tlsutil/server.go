package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// NewServerTLSConfig builds an *tls.Config for an mTLS server.
//
// Properties enforced:
//   - TLS 1.3 minimum (no TLS 1.2 fallback)
//   - Client certificate required and verified against clientCAs
//   - Server presents serverCert on every connection
//
// The serverCert is typically loaded with tls.X509KeyPair from PEM files
// written by IssueServerCert.  clientCAs is typically built with LoadCertPool
// from the dev CA certificate.
func NewServerTLSConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS13,
	}
}

// NewClientTLSConfig builds an *tls.Config for an mTLS client.
//
// Properties:
//   - TLS 1.3 minimum
//   - Client presents clientCert for mutual authentication
//   - Server certificate verified against rootCAs (the dev CA pool)
func NewClientTLSConfig(clientCert tls.Certificate, rootCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS13,
	}
}

// LoadServerTLSConfig is a convenience function that loads the server
// certificate + key from PEM byte slices, the client CA pool from caCertPEM,
// and returns a fully configured *tls.Config for the mTLS server.
//
// certPEM and keyPEM are the server certificate and key (from IssueServerCert).
// caCertPEM is the CA certificate used to verify incoming client certificates.
func LoadServerTLSConfig(certPEM, keyPEM, caCertPEM []byte) (*tls.Config, error) {
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: load server key pair: %w", err)
	}
	clientCAs, err := LoadCertPool(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: load client CA pool: %w", err)
	}
	return NewServerTLSConfig(serverCert, clientCAs), nil
}

// LoadClientTLSConfig is a convenience function that loads the client
// certificate + key from PEM byte slices and the server CA pool from
// caCertPEM, returning a fully configured *tls.Config for an mTLS client.
//
// certPEM and keyPEM are the client certificate and key (from IssueClientCert).
// caCertPEM is the CA certificate used to verify the server's certificate.
func LoadClientTLSConfig(certPEM, keyPEM, caCertPEM []byte) (*tls.Config, error) {
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: load client key pair: %w", err)
	}
	rootCAs, err := LoadCertPool(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: load root CA pool: %w", err)
	}
	return NewClientTLSConfig(clientCert, rootCAs), nil
}
