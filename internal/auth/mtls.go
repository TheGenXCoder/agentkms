// Package auth implements mTLS client certificate validation, workload
// identity extraction, short-lived session token issuance and revocation.
//
// Token TTL: 15 minutes.  Tokens are bound to the mTLS connection identity
// and cannot be replayed on a different connection.
//
// Backlog: A-01 to A-13.
package auth

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/agentkms/agentkms/pkg/identity"
)

// GetConnectionCertFingerprint calculates a SHA-256 fingerprint of the
// verified leaf client certificate in cs.  Returns an empty string if cs is
// nil or has no verified certificate chain.
//
// SECURITY: Uses VerifiedChains (not PeerCertificates) so that the fingerprint
// is only computed for certificates that passed full mTLS chain verification.
// Pass cs directly from the HTTP request (r.TLS) — never from a package-level
// variable shared across goroutines.
func GetConnectionCertFingerprint(cs *tls.ConnectionState) string {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return ""
	}
	certHash := sha256.Sum256(cs.VerifiedChains[0][0].Raw)
	return hex.EncodeToString(certHash[:])
}

// MTLSCallerID extracts the caller ID from the verified TLS connection state.
//
// Returns the Common Name from the first leaf certificate in the verified chain,
// or an empty string if:
//   - cs is nil (plaintext connection)
//   - VerifiedChains is empty (chain verification failed)
//   - The certificate has no Common Name
//
// SECURITY: Uses VerifiedChains (not PeerCertificates) — same rationale as
// GetConnectionCertFingerprint.
func MTLSCallerID(cs *tls.ConnectionState) string {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return ""
	}
	return cs.VerifiedChains[0][0].Subject.CommonName
}

// IdentityFromTLS extracts an AgentKMS Identity from the mTLS connection
// state of an HTTP request.
//
// The identity is derived from the first (leaf) client certificate in the
// verified chain:
//   - CallerID  ← certificate Common Name (CN)
//   - TeamID    ← first value of certificate Organisation (O)
//   - Role      ← first value of certificate Organisational Unit (OU)
//   - SPIFFEID  ← first URI SAN whose scheme is "spiffe"
//   - CertSerial← hex-encoded certificate serial number
//
// Returns an error if:
//   - cs is nil (no TLS connection state — connection was not encrypted)
//   - The verified certificate chain is empty (mTLS verification failed)
//   - The certificate has no Common Name
//
// SECURITY: This function reads from cs.VerifiedChains, NOT cs.PeerCertificates.
// PeerCertificates is the raw peer-presented chain with no verification guarantee.
// VerifiedChains is populated only after Go’s TLS stack successfully verified
// the chain against the configured ClientCAs pool; using it here ensures we
// only trust certificates that passed full mTLS chain verification.
//
// This function MUST only be called on connections where the server TLS config
// has tls.RequireAndVerifyClientCert set.
func IdentityFromTLS(cs *tls.ConnectionState) (*identity.Identity, error) {
	if cs == nil {
		return nil, fmt.Errorf("auth: no TLS connection state — plaintext connection rejected")
	}
	// Use VerifiedChains (not PeerCertificates) to ensure chain verification
	// has succeeded before we extract any identity from the certificate.
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return nil, fmt.Errorf("auth: no verified client certificate in TLS connection state")
	}

	cert := cs.VerifiedChains[0][0]

	// Calculate certificate fingerprint for strong binding
	certDER := cert.Raw
	certHash := sha256.Sum256(certDER)
	certFingerprint := hex.EncodeToString(certHash[:])

	id := &identity.Identity{
		CallerID:       cert.Subject.CommonName,
		Certificate:    cert,
		CertFingerprint: certFingerprint,
		CertSerial: hex.EncodeToString(cert.SerialNumber.Bytes()),
	}

	if len(cert.Subject.Organization) > 0 {
		id.TeamID = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		id.Role = identity.Role(cert.Subject.OrganizationalUnit[0])
	}

	// Extract the SPIFFE ID from URI Subject Alternative Names.
	// RFC 4122 / SPIFFE spec: URI SAN with scheme "spiffe".
	for _, uri := range cert.URIs {
		if strings.EqualFold(uri.Scheme, "spiffe") {
			id.SPIFFEID = uri.String()
			break
		}
	}

	if id.CallerID == "" {
		return nil, fmt.Errorf("auth: mTLS certificate has no Common Name (CN); identity cannot be established")
	}

	return id, nil
}
