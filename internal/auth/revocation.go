package auth

import (
	"sync"
	"time"
)

// RevocationList is a thread-safe in-memory set of revoked session token JTIs.
//
// When a token is revoked (via POST /auth/revoke or on session shutdown),
// its JTI is added to this list.  All subsequent calls to TokenService.Validate
// with that token return ErrTokenRevoked.
//
// TIER 0 LIMITATION: this list is in-memory only.  Revocations are lost on
// service restart.  For Tier 1+ (production), the revocation list must be
// backed by persistent storage (OpenBao, Redis, or similar) so that
// revocations survive restarts.  Backlog item A-05 notes this.
//
// Memory management: JTIs are pruned from the list after their natural token
// expiry has passed.  Since expired tokens are rejected independently by the
// TTL check in Validate, there is no security loss from pruning — it only
// prevents unbounded memory growth.
//
// Concurrency: safe for concurrent use by multiple goroutines.
//
// A-05.
type RevocationList struct {
	mu      sync.RWMutex
	entries map[string]time.Time // jti → token natural expiry (UTC)
}

// NewRevocationList returns an empty RevocationList ready for use.
func NewRevocationList() *RevocationList {
	return &RevocationList{
		entries: make(map[string]time.Time),
	}
}

// Revoke adds jti to the blocklist.
//
// expiry is the natural expiry time of the token (from its "exp" claim).
// After expiry has passed, the JTI will be pruned from the list on the next
// write operation, since the token would be rejected by the TTL check anyway.
//
// Revoking a JTI that is already in the list is a no-op (idempotent).
// Revoking an already-expired JTI is also safe but has no practical effect.
func (r *RevocationList) Revoke(jti string, expiry time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[jti] = expiry.UTC()
	r.pruneExpired() // opportunistic pruning to bound memory use
}

// IsRevoked reports whether jti is present in the revocation blocklist.
// Returns false for JTIs that have never been revoked, and for JTIs that
// have been pruned after their expiry passed.
func (r *RevocationList) IsRevoked(jti string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.entries[jti]
	return ok
}

// Len returns the number of entries currently in the blocklist.
// Used for monitoring and testing.
func (r *RevocationList) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// pruneExpired removes all entries whose natural expiry has passed.
// Must be called with r.mu write-locked.
//
// Pruning is safe because a JTI whose natural expiry has passed would be
// rejected by the token TTL check before the revocation check is ever reached.
// Removing it from the list does not create any bypass opportunity.
func (r *RevocationList) pruneExpired() {
	now := time.Now().UTC()
	for jti, exp := range r.entries {
		if now.After(exp) {
			delete(r.entries, jti)
		}
	}
}
