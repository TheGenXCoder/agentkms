// Package identity defines the AgentKMS identity model.
//
// Four-tier hierarchy: Enterprise → Team → Individual Builder → Agent Session.
// Identity is extracted from mTLS client certificates (CN, O, OU, SPIFFE SAN).
// Every audit event carries all four tiers simultaneously.
package identity
