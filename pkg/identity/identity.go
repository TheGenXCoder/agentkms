// Package identity defines the AgentKMS identity model.
//
// Four-tier hierarchy: Enterprise → Team → Individual Builder → Agent Session.
// Identity is extracted from mTLS client certificates (CN, O, OU, SPIFFE SAN).
// Every audit event carries all four tiers simultaneously.
package identity

import (
	"crypto/x509"
)

// Role identifies the tier of the calling entity within the AgentKMS identity
// hierarchy.  Values are written into client-certificate OU fields and carried
// in session tokens.
type Role string

const (
	// RoleDeveloper is a human developer enrolled via SSO or the dev enroll CLI.
	RoleDeveloper Role = "developer"

	// RoleService is a non-human workload (CI/CD runner, deployed service).
	RoleService Role = "service"

	// RoleAgent is an ephemeral agent session derived from a developer or
	// service identity.
	RoleAgent Role = "agent"
)

// Identity is the resolved caller identity extracted from an mTLS client
// certificate.  It is immutable after creation and safe for concurrent use.
//
// SECURITY NOTE: This struct contains identity metadata only.  It must never
// be extended with fields that could carry key material, plaintext, or LLM
// API credentials.
type Identity struct {
	// CallerID is the Common Name (CN) from the mTLS client certificate.
	// Format: "username@team" for developers, "service-name@team" for services.
	// Example: "bert@platform-team", "ci-runner@payments-team".
	CallerID string

	// TeamID is the Organisation (O) field from the certificate.
	// Example: "platform-team", "payments-team".
	TeamID string

	// Role is the Organisational Unit (OU) from the certificate.
	// Values: RoleDeveloper, RoleService, RoleAgent.
	Role Role

	// SPIFFEID is the SPIFFE Verifiable Identity Document URI extracted from
	// the Subject Alternative Name URI field of the certificate.
	// Format: "spiffe://agentkms.local/team/{teamID}/identity/{identityID}"
	// Empty string if no URI SAN is present.
	SPIFFEID string

	// CertSerial is the hexadecimal-encoded serial number of the client
	// certificate.  Used to correlate cert usage with CRL entries during
	// revocation checks.
	CertSerial string

	// CertFingerprint is a SHA-256 hash of the DER-encoded client certificate.
	// Used for strong binding between tokens and certificates to prevent replay
	// with different certificates that happen to have the same Common Name.
	CertFingerprint string

	// Certificate is the raw client certificate used during initial auth
	// to calculate fingerprints and extract fields.  It is NOT persisted in
	// tokens or audit events.
	//
	// json:"-" prevents accidental serialisation into HTTP responses, audit
	// events, or log output.  x509.Certificate contains the public key and
	// all certificate fields; while not private-key material, its presence
	// in structured output would be unexpected and potentially large.
	Certificate *x509.Certificate `json:"-"`
}
