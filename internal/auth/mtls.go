package auth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/agentkms/agentkms/pkg/identity"
)

// legacySpiffeWarnOnce de-duplicates the "legacy device-only SPIFFE URI"
// warning so a chatty CI never floods the log with the same advice.  Keyed
// on (UserID,DeviceID) — one warning per resolved principal pair, ever.
var legacySpiffeWarnOnce sync.Map

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

	// Parse the canonical multi-principal SPIFFE convention.
	//
	//   tenant/<t>/user/<u>/device/<d>  → user-and-device-bearing cert
	//   tenant/<t>/device/<d>           → legacy device-only cert
	//
	// Anything else is left for the CN-based fallback so non-SPIFFE certs
	// keep working.  The returned IDs are empty when the URI doesn't match
	// either shape.
	userID, deviceID, tenant := parseTenantPrincipal(spiffeID)
	if userID == "" && deviceID != "" {
		// Legacy device-only URI — warn once per (UserID,DeviceID) so the
		// operator gets one nudge to re-issue with the new convention but
		// log volume doesn't explode under a chatty client.
		key := deviceID + "\x00" + deviceID
		if _, already := legacySpiffeWarnOnce.LoadOrStore(key, struct{}{}); !already {
			slog.Warn(
				"legacy device-only SPIFFE URI — re-issue cert with /user/<name>/device/<name> for multi-device portability",
				"device_id", deviceID,
				"tenant", tenant,
				"spiffe_id", spiffeID,
			)
		}
		// Surface device as the (legacy) user too so downstream code that
		// looks at UserID still has a stable principal value.  CallerID
		// (further down) stays equal to the cert CN for these certs.
		userID = deviceID
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
	// a service disruption.  The audit log always records the actual OU value
	// via Identity.CallerOU below so forensics can distinguish a recognised
	// value from a defaulted one.
	role := identity.RoleDeveloper
	var ouRaw string
	if len(cert.Subject.OrganizationalUnit) > 0 {
		ouRaw = strings.TrimSpace(cert.Subject.OrganizationalUnit[0])
		switch strings.ToLower(ouRaw) {
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

	// CallerID prefers UserID (the human/logical principal) when the cert
	// follows the user/device convention so that the legacy single-string
	// identifier resolves to the same value across all of a user's device
	// certs.  For legacy device-only certs and non-SPIFFE certs it stays
	// equal to the cert CN — same value as before this change.
	callerID := cn
	if userID != "" && userID != deviceID {
		callerID = userID
	}

	return &identity.Identity{
		CallerID:        callerID,
		UserID:          userID,
		DeviceID:        deviceID,
		Tenant:          tenant,
		TeamID:          teamID,
		Role:            role,
		SPIFFEID:        spiffeID,
		CertFingerprint: fingerprint,
		CallerOU:        ouRaw,
	}, nil
}

// ParseTenantPrincipalExported is the exported wrapper around parseTenantPrincipal
// for use by packages that need to extract (userID, deviceID, tenant) from a
// SPIFFE URI string without going through a full certificate parse.
func ParseTenantPrincipalExported(spiffeID string) (userID, deviceID, tenant string) {
	return parseTenantPrincipal(spiffeID)
}

// parseTenantPrincipal walks the path segments of a SPIFFE URI and extracts
// (userID, deviceID, tenant) for the two shapes that the zero-trust identity
// model recognises:
//
//	spiffe://<trust-domain>/tenant/<t>/user/<u>/device/<d>
//	spiffe://<trust-domain>/tenant/<t>/device/<d>     (legacy)
//
// Returns ("", "", "") for any other shape so callers can fall back to the
// CN-based path without conflating the two regimes.
//
// The function is intentionally case-sensitive: SPIFFE path segments are
// defined to be opaque and case-significant by the spec.
func parseTenantPrincipal(spiffeID string) (userID, deviceID, tenant string) {
	if spiffeID == "" {
		return "", "", ""
	}
	const prefix = "spiffe://"
	if !strings.HasPrefix(spiffeID, prefix) {
		return "", "", ""
	}
	// Everything after the trust domain.
	rest := spiffeID[len(prefix):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return "", "", ""
	}
	path := rest[slash+1:]
	segments := strings.Split(path, "/")

	// Walk pairs: "tenant/<t>", "user/<u>", "device/<d>" — in that order.
	// We don't accept any other order because policy and audit reason
	// about a fixed left-to-right specificity chain.
	for i := 0; i+1 < len(segments); i += 2 {
		k, v := segments[i], segments[i+1]
		if v == "" {
			return "", "", ""
		}
		switch k {
		case "tenant":
			if tenant != "" {
				return "", "", ""
			}
			tenant = v
		case "user":
			if userID != "" {
				return "", "", ""
			}
			userID = v
		case "device":
			if deviceID != "" {
				return "", "", ""
			}
			deviceID = v
		default:
			// Unknown segment kind — reject the whole URI so we don't half-
			// parse a workload/agent URI as a user/device URI.
			return "", "", ""
		}
	}
	// Required: tenant + device.  user is optional (legacy device-only URI).
	if tenant == "" || deviceID == "" {
		return "", "", ""
	}
	return userID, deviceID, tenant
}
