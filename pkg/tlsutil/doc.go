// Package tlsutil provides mTLS server configuration helpers and client
// certificate parsing utilities.
//
// TLS 1.3 minimum.  Client certificates are required and verified against
// the team Intermediate CA.  SPIFFE SVIDs are parsed from SAN URIs.
//
// Backlog: A-01 (server setup), A-02 (identity extraction).
package tlsutil
