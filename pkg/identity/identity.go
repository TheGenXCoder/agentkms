// Package identity defines the AgentKMS identity model.
//
// Four-tier hierarchy: Enterprise → Team → Individual Builder → Agent Session.
// Every principal that interacts with AgentKMS has a fully-qualified identity
// extracted from its mTLS certificate or workload identity token.
//
// Every audit event carries all populated tiers simultaneously so that
// compliance queries can filter by any combination of identity dimensions.
package identity

// Role identifies the type of principal within the system.
// It is encoded in the mTLS certificate's Organisational Unit (OU) field.
type Role string

const (
	// RoleDeveloper is a human developer identity enrolled via SSO.
	// Issued by: the team Intermediate CA.
	RoleDeveloper Role = "developer"

	// RoleService is a non-human workload identity (CI/CD runner, service).
	// Issued by: the team Intermediate CA with automated OIDC attestation.
	RoleService Role = "service"

	// RoleAgent is an ephemeral per-session identity for a Pi agent session.
	// Derived from the developer or service identity that initiated the session.
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

// Identity represents a verified caller identity.  Fields are populated
// during mTLS certificate validation in internal/auth/mtls.go; all fields
// that cannot be determined from the certificate are left as zero values.
//
// SECURITY NOTE: Identity is an immutable value type after construction.
// Handler code must not modify an Identity once it has been built from the
// verified certificate — doing so would allow callers to escalate privileges
// in-process.
type Identity struct {
	// CallerID is the principal's name, extracted from the certificate CN.
	// Format: "<name>@<team-domain>" (e.g. "bert@platform-team",
	// "ci-runner@payments-team").
	CallerID string

	// TeamID is the team that owns this identity, from the certificate O field.
	// Examples: "platform-team", "payments-team", "ml-team".
	TeamID string

	// Role is the caller's role in the system, from the certificate OU field.
	// See Role constants above.  May be empty for identities that pre-date
	// the OU field convention; the policy engine treats an empty Role as
	// matching no explicit role constraint.
	Role Role

	// SessionID is the per-session identifier assigned at token issuance time.
	// Present only for agent-session identities (RoleAgent).
	// Empty for developer and service identities.
	SessionID string

	// SPIFFEID is the SPIFFE URI SAN from the mTLS certificate, if present.
	// Format: "spiffe://agentkms.org/team/{teamID}/identity/{identityID}"
	// May be empty for legacy certificates that pre-date SPIFFE adoption.
	SPIFFEID string
}
