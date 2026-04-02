// Package auth implements mTLS client certificate validation, workload
// identity extraction, short-lived session token issuance and revocation.
//
// Token TTL: 15 minutes.  Tokens are bound to the mTLS connection identity
// and cannot be replayed on a different connection.
//
// Backlog: A-01 to A-13.
package auth
