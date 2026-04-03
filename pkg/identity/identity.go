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
	// CallerID is the certificate's Common Name (CN).
	// Example: "bert@platform-team", "ci-runner@payments-team".
	CallerID string

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
}
