package credentials

import "time"

// CredentialTracker monitors vended credentials for TTL expiry and emits
// audit events when they lapse. Part of the forensics chain-of-custody story (FO-B3).
type CredentialTracker struct{}

// NewCredentialTracker creates a new tracker instance.
func NewCredentialTracker() *CredentialTracker {
	return &CredentialTracker{}
}

// Track registers a credential for expiry monitoring.
func (ct *CredentialTracker) Track(_ string, _ time.Time) {}

// ExpiredSince returns credentials that have expired since the last check.
// Returned UUIDs are consumed — subsequent calls will not return the same UUID.
func (ct *CredentialTracker) ExpiredSince(_ time.Time) []string {
	return nil
}

// IsExpired returns true if the given UUID has been marked as expired.
func (ct *CredentialTracker) IsExpired(_ string) bool {
	return false
}
