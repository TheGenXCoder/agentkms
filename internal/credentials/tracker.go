package credentials

import "time"

// CredentialTracker monitors vended credentials for TTL expiry and emits
// audit events when they lapse. Part of the forensics chain-of-custody story (FO-B3).
type CredentialTracker struct {
	// credentials stores expiresAt by UUID
	credentials map[string]time.Time
	// expired tracks UUIDs that have been consumed by ExpiredSince
	expired map[string]bool
}

// NewCredentialTracker creates a new tracker instance.
func NewCredentialTracker() *CredentialTracker {
	return &CredentialTracker{
		credentials: make(map[string]time.Time),
		expired:     make(map[string]bool),
	}
}

// Track registers a credential for expiry monitoring.
func (ct *CredentialTracker) Track(uuid string, expiresAt time.Time) {
	ct.credentials[uuid] = expiresAt
}

// ExpiredSince returns credentials that have expired since the last check.
// Returned UUIDs are consumed — subsequent calls will not return the same UUID.
func (ct *CredentialTracker) ExpiredSince(now time.Time) []string {
	var result []string
	for uuid, expiresAt := range ct.credentials {
		if ct.expired[uuid] {
			continue
		}
		if expiresAt.IsZero() || !expiresAt.After(now) {
			result = append(result, uuid)
			ct.expired[uuid] = true
		}
	}
	return result
}

// IsExpired returns true if the given UUID has been marked as expired.
func (ct *CredentialTracker) IsExpired(uuid string) bool {
	return ct.expired[uuid]
}
