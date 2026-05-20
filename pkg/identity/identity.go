// Package identity defines the AgentKMS identity model.
//
// Four-tier hierarchy: Enterprise → Team → Individual Builder → Agent Session.
// Identity is extracted from mTLS client certificates (CN, O, OU, SPIFFE SAN).
// Every audit event carries all four tiers simultaneously so that compliance
// queries can filter by any combination of identity dimensions.
package identity

// Role identifies the category of identity in the four-tier hierarchy.
// The role is encoded in the certificate's Organisational Unit (OU) field.
type Role string

const (
	// RoleDeveloper is a human developer enrolled via SSO or agentkms enroll.
	RoleDeveloper Role = "developer"

	// RoleService is a non-human workload (CI/CD runner, backend service).
	RoleService Role = "service"

	// RoleAgent is an ephemeral per-Pi-session identity derived from a
	// developer or service identity.
	RoleAgent Role = "agent"
)

// KnownRoles lists all valid Role values.  Used for validation.
var KnownRoles = []Role{RoleDeveloper, RoleService, RoleAgent}

// IsValid reports whether r is a known role value.
func (r Role) IsValid() bool {
	for _, kr := range KnownRoles {
		if r == kr {
			return true
		}
	}
	return false
}

// Identity holds the caller identity extracted from a verified mTLS client
// certificate.  All fields are derived from the certificate; no field is
// user-supplied at request time.
//
// SECURITY NOTE: Identity is an immutable value type after construction.
// Handler code must not modify an Identity once it has been built from the
// verified certificate — doing so would allow callers to escalate privileges
// in-process.
//
// Mapping from X.509 certificate fields:
//
//	CN  → CallerID          e.g. "bert@platform-team"
//	O   → TeamID            e.g. "platform-team"
//	OU  → Role              e.g. "developer", "service", "agent"
//	SAN → SPIFFEID          e.g. "spiffe://agentkms.org/team/platform-team/identity/bert"
type Identity struct {
	// CallerID is the legacy single-string caller identifier.
	//
	// For backward compatibility this field is always populated:
	//   - For SPIFFE URIs of shape tenant/<t>/user/<u>/device/<d> it equals UserID.
	//   - For legacy device-only SPIFFE URIs (or non-SPIFFE certs) it equals
	//     the cert's Common Name.
	//
	// New code should prefer UserID (logical principal) and DeviceID (the
	// specific cert/device) over CallerID.  CallerID is preserved so existing
	// handlers, policy CallerIDPattern, and audit fields keep working unchanged.
	// Example: "bert@platform-team", "bert", "ci-runner@payments-team".
	CallerID string

	// UserID is the logical human (or workload) principal extracted from the
	// SPIFFE URI's /user/<u>/ segment, when present.  Multiple device certs
	// belonging to the same human all resolve to the same UserID, so audit,
	// secret stash, and policy can reference the human-level principal
	// independently of which device cert was actually used today.
	//
	// Empty when the certificate's SPIFFE URI does not encode a user segment
	// (legacy device-only certs).  See identityFromCert.
	UserID string

	// DeviceID is the specific device cert principal extracted from the
	// SPIFFE URI's /device/<d> segment.  Always populated for SPIFFE-bearing
	// certs that follow the user/device convention; equal to the cert CN
	// otherwise.  Used for per-device forensics in the audit trail.
	DeviceID string

	// Tenant is the organisational unit within an operator's trust domain,
	// extracted from the SPIFFE URI's /tenant/<t>/ segment.  Empty for
	// non-SPIFFE certs.
	Tenant string

	// TeamID is the certificate's Organisation (O) field.
	// Example: "platform-team", "payments-team".
	TeamID string

	// Role is the certificate's Organisational Unit (OU) field, parsed into
	// one of the Role constants.  Defaults to RoleDeveloper when the OU is
	// absent or unrecognised.
	Role Role

	// AgentSession is the per-Pi-session identifier, assigned at token
	// issuance time.  Present only for agent-session identities (RoleAgent).
	// Used to correlate all operations within a single session in audit logs.
	// Empty for developer and service identities before a session is started.
	AgentSession string

	// SPIFFEID is the SPIFFE ID extracted from the Subject Alternative Name
	// URI field.  May be empty if the certificate does not include a SPIFFE
	// SAN URI.
	// Format: "spiffe://agentkms.org/team/{teamID}/identity/{identityID}"
	SPIFFEID string

	// CertFingerprint is the hex-encoded SHA-256 digest of the raw DER bytes
	// of the client certificate.  Used to bind session tokens to a specific
	// certificate and detect token replay attacks across connections.
	CertFingerprint string

	// CallerOU is the raw Organisational Unit (OU) field as it appeared on
	// the client certificate, preserved verbatim (with leading/trailing
	// whitespace trimmed).  Role above is the parsed enum derived from this
	// value; CallerOU preserves the original text so forensics can
	// distinguish, for example, "developer" vs. an unknown OU that was
	// defaulted to RoleDeveloper.
	CallerOU string

	// Scopes is the set of operations and resources the identity is permitted
	// to access.  If non-empty, the identity's permissions are restricted to
	// only those explicitly granted by the scopes, even if the policy would
	// allow more.
	//
	// Format: "operation:resource" (e.g. "sign:key-123", "encrypt:*").
	Scopes []string

	// AuthMethod records how this identity was authenticated.
	// Used by the policy engine to enforce per-operation auth requirements.
	AuthMethod AuthMethod
}

// AuthMethod identifies how a session was established.
type AuthMethod string

const (
	AuthMethodWebAuthn    AuthMethod = "webauthn"
	AuthMethodMTLSEnclave AuthMethod = "mtls_enclave"
	AuthMethodMTLSCert    AuthMethod = "mtls_cert"
	AuthMethodMTLSPKCS11  AuthMethod = "mtls_pkcs11"
)
