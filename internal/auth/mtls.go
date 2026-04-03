package auth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/agentkms/agentkms/pkg/identity"
)

// ExtractIdentity derives an Identity from the verified client certificate
// presented during the mTLS handshake.
//
// This function must only be called on requests that have completed a
// successful mTLS handshake (i.e. tls.RequireAndVerifyClientCert is set on
// the server).  It does not re-verify the certificate chain — that is the TLS
// stack's responsibility.
//
// Field mapping from the certificate:
//
//	CN  → Identity.CallerID
//	O   → Identity.TeamID    (first value; empty = error)
//	OU  → Identity.Role      (first value; unrecognised = RoleDeveloper)
//	SAN → Identity.SPIFFEID  (first URI SAN with scheme "spiffe://")
//
// Identity.CertFingerprint is set to the hex-encoded SHA-256 of the
// certificate's raw DER bytes.  It is used to bind session tokens to the
// specific certificate that was presented.
//
// Returns an error if:
//   - The request has no TLS state (mTLS bypass — must never happen)
//   - No verified client certificate is present
//   - The certificate has an empty Common Name
//   - The certificate has no Organisation field
//
// A-02.
func ExtractIdentity(r *http.Request) (*identity.Identity, error) {
	if r.TLS == nil {
		return nil, fmt.Errorf("auth: request has no TLS state — mTLS is required for all connections")
	}
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil, fmt.Errorf("auth: no verified client certificate in TLS handshake")
	}

	// VerifiedChains[0][0] is the client's end-entity certificate, the leaf of
	// the first valid chain.  The Go TLS stack only populates VerifiedChains
	// after successful verification, so no further verification is needed here.
	cert := r.TLS.VerifiedChains[0][0]
	return identityFromCert(cert)
}

// identityFromCert extracts and validates an Identity from an X.509
// certificate.  Called by ExtractIdentity after TLS-level verification.
func identityFromCert(cert *x509.Certificate) (*identity.Identity, error) {
	// Common Name is the primary caller identifier.
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn == "" {
		return nil, fmt.Errorf("auth: client certificate has no Common Name (CN) — cannot identify caller")
	}

	// First SPIFFE URI SAN.
	var spiffeID string
	for _, u := range cert.URIs {
		// Exact scheme match only — "spiffe", not "spiffefoo" or similar.
		// url.Parse lowercases the scheme, so no case folding needed.
		if u != nil && u.Scheme == "spiffe" {
			spiffeID = u.String()
			break
		}
	}

	// Organisation is the team identifier.
	var teamID string
	if len(cert.Subject.Organization) > 0 && strings.TrimSpace(cert.Subject.Organization[0]) != "" {
		teamID = strings.TrimSpace(cert.Subject.Organization[0])
	} else if spiffeID != "" {
		// For SPIFFE-only certificates (common in K8s/Spire), derive team from
		// the SPIFFE ID.
		// Pattern 1: spiffe://agentkms.org/team/{teamID}/...
		// Pattern 2: spiffe://cluster.local/ns/{namespace}/sa/{serviceaccount}
		if strings.HasPrefix(spiffeID, "spiffe://agentkms.org/team/") {
			parts := strings.Split(strings.TrimPrefix(spiffeID, "spiffe://agentkms.org/team/"), "/")
			if len(parts) > 0 && parts[0] != "" {
				teamID = parts[0]
			}
		} else if strings.Contains(spiffeID, "/ns/") {
			// Map K8s namespace to TeamID for workload identities.
			idx := strings.Index(spiffeID, "/ns/")
			parts := strings.Split(spiffeID[idx+4:], "/")
			if len(parts) > 0 && parts[0] != "" {
				teamID = "k8s-" + parts[0]
			}
		}
	}

	if teamID == "" {
		return nil, fmt.Errorf("auth: client certificate has no Organisation (O) and no recognisable SPIFFE team mapping — cannot identify team")
	}

	// Organisational Unit maps to role.  Unrecognised values default to
	// RoleDeveloper rather than failing, to allow certificate extensions without
	// a service disruption.  The audit log always records the actual OU value.
	role := identity.RoleDeveloper
	if len(cert.Subject.OrganizationalUnit) > 0 {
		switch strings.ToLower(strings.TrimSpace(cert.Subject.OrganizationalUnit[0])) {
		case "developer":
			role = identity.RoleDeveloper
		case "service":
			role = identity.RoleService
		case "agent":
			role = identity.RoleAgent
		}
	} else if spiffeID != "" {
		// Workloads with SPIFFE IDs but no OU are treated as RoleService.
		role = identity.RoleService
	}

	// SHA-256 fingerprint of the raw DER certificate bytes.
	// This value is stored in the session token to bind the token to the
	// specific certificate that authenticated this session.
	// SECURITY: we hash the cert, not any key material.
	fp := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(fp[:])

	return &identity.Identity{
		CallerID:        cn,
		TeamID:          teamID,
		Role:            role,
		SPIFFEID:        spiffeID,
		CertFingerprint: fingerprint,
	}, nil
}
