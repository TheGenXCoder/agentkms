// Package identity defines the AgentKMS identity model.
//
// Four-tier hierarchy: Enterprise → Team → Individual Builder → Agent Session.
// Identity is extracted from mTLS client certificates (CN, O, OU, SPIFFE SAN)
// by the auth layer (internal/auth/mtls.go, backlog A-02) and carried through
// every request in the context.
//
// Every audit event records all four tiers simultaneously.
package identity

// Identity holds the verified, immutable attributes of an authenticated caller
// for the duration of a single request.
//
// Identity is populated by the mTLS certificate validation middleware (A-02)
// and enriched with session information by the token validation middleware
// (A-04).  Handlers receive it from the request context and must not modify
// it.
//
// SECURITY CONTRACT: Identity values in handlers and audit events are always
// derived from verified cryptographic material (mTLS cert, session token).
// Never construct an Identity from user-supplied request body fields.
type Identity struct {
	// CallerID uniquely identifies the calling entity, extracted from the
	// mTLS certificate Common Name.
	// Format: "<name>@<team-id>" for humans and workloads alike.
	// Example: "bert@platform-team", "ci-runner@payments-team".
	CallerID string

	// TeamID is the team that owns this identity, from the certificate O
	// (Organisation) field.
	// Example: "platform-team", "payments-team".
	TeamID string

	// Role is the identity's role in the organisation hierarchy, from the
	// certificate OU (Organisational Unit) field.
	// Permitted values: "developer", "service", "agent".
	Role string

	// AgentSession is the per-Pi-session identifier, populated from the
	// validated session token by the A-04 middleware.
	// Empty for service-to-service calls that do not use Pi sessions.
	AgentSession string

	// SPIFFEID is the SPIFFE URI from the certificate Subject Alternative
	// Name (URI SAN), if present.
	// Format: "spiffe://agentkms.org/team/{teamID}/identity/{identityID}"
	// Empty if the certificate does not carry a SPIFFE SAN (e.g., in dev
	// mode with a locally generated cert).
	SPIFFEID string
}
