// Package credentials implements LLM provider credential vending.
//
// Credentials are scoped to the requesting session identity, carry a 60-minute
// TTL, and are revoked immediately when the parent session is revoked.
// Key material (LLM API keys) is fetched from the Backend at vend time and
// never stored outside the backend.
//
// Backlog: LV-01 to LV-06.
package credentials
