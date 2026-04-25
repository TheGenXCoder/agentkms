package ghsecret

import (
	"sync"
	"time"
)

const pubkeyCacheTTL = time.Hour

// cacheEntry stores a fetched public key with its expiry time.
type cacheEntry struct {
	keyID     string
	base64Key string
	expiresAt time.Time
}

// pubkeyCache is a thread-safe cache of GitHub Actions public keys keyed by
// (owner, repo). Each entry has a 1-hour TTL from fetch time.
//
// The cache invariant:
//   - On first Deliver for an (owner, repo), fetch and cache.
//   - Within TTL, return cached values without an API call.
//   - After TTL expiry, re-fetch on next access.
//   - Explicit invalidation (e.g., on 422 stale-key error) removes the entry.
type pubkeyCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry // key = "owner/repo"
	nowFunc func() time.Time      // injectable for tests
}

// newPubkeyCache creates a new empty public key cache.
func newPubkeyCache() *pubkeyCache {
	return &pubkeyCache{
		entries: make(map[string]cacheEntry),
		nowFunc: func() time.Time { return time.Now() },
	}
}

// cacheKey returns the map key for (owner, repo).
func cacheKey(owner, repo string) string { return owner + "/" + repo }

// Get returns the cached (keyID, base64Key) for (owner, repo) if present and
// not expired. The second return value is false on a cache miss.
func (c *pubkeyCache) Get(owner, repo string) (keyID, base64Key string, ok bool) {
	k := cacheKey(owner, repo)

	c.mu.RLock()
	entry, found := c.entries[k]
	c.mu.RUnlock()

	if !found {
		return "", "", false
	}
	if c.nowFunc().After(entry.expiresAt) {
		// Expired — treat as miss but don't evict yet (eviction on next Set).
		return "", "", false
	}
	return entry.keyID, entry.base64Key, true
}

// Set stores or replaces the cache entry for (owner, repo) with a TTL of 1 hour.
func (c *pubkeyCache) Set(owner, repo, keyID, base64Key string) {
	k := cacheKey(owner, repo)
	c.mu.Lock()
	c.entries[k] = cacheEntry{
		keyID:     keyID,
		base64Key: base64Key,
		expiresAt: c.nowFunc().Add(pubkeyCacheTTL),
	}
	c.mu.Unlock()
}

// Invalidate removes the cache entry for (owner, repo), forcing the next
// access to re-fetch from the GitHub API.
func (c *pubkeyCache) Invalidate(owner, repo string) {
	k := cacheKey(owner, repo)
	c.mu.Lock()
	delete(c.entries, k)
	c.mu.Unlock()
}

// Len returns the number of entries in the cache (including expired ones that
// haven't been evicted yet). Used in tests.
func (c *pubkeyCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
