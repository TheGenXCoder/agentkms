package credentials

import (
	"sync"
	"time"
)

// cacheEntry holds a cached result along with an in-flight coordination channel.
type cacheEntry struct {
	result    *ScopedResult
	err       error
	createdAt time.Time
	done      chan struct{} // closed when vend completes
}

// Coalescer wraps a vend function and deduplicates concurrent identical requests.
// Two requests are "identical" if they produce the same ScopeHash.
type Coalescer struct {
	ttl   time.Duration
	mu    sync.Mutex
	cache map[string]*cacheEntry
}

// NewCoalescer creates a Coalescer with the given TTL for cached entries.
func NewCoalescer(ttl time.Duration) *Coalescer {
	return &Coalescer{
		ttl:   ttl,
		cache: make(map[string]*cacheEntry),
	}
}

// CoalesceOrCall checks if a result for the given scopeHash is cached and still valid.
// If yes, returns the cached result. If no, calls the provided vend function,
// caches the result, and returns it.
func (c *Coalescer) CoalesceOrCall(scopeHash string, vend func() (*ScopedResult, error)) (*ScopedResult, error) {
	c.mu.Lock()

	if entry, ok := c.cache[scopeHash]; ok {
		// Entry exists — check if it's still in-flight or completed.
		select {
		case <-entry.done:
			// Completed. Check if it was successful and not expired.
			if entry.err == nil && time.Since(entry.createdAt) < c.ttl {
				c.mu.Unlock()
				return entry.result, nil
			}
			// Expired or was an error — fall through to create new entry.
		default:
			// Still in-flight — wait for it.
			c.mu.Unlock()
			<-entry.done
			return entry.result, entry.err
		}
	}

	// Create a new in-flight entry.
	entry := &cacheEntry{
		done: make(chan struct{}),
	}
	c.cache[scopeHash] = entry
	c.mu.Unlock()

	// Call vend outside the lock.
	result, err := vend()

	entry.result = result
	entry.err = err
	entry.createdAt = time.Now()
	close(entry.done)

	// If vend returned an error, remove from cache so future calls retry.
	if err != nil {
		c.mu.Lock()
		// Only delete if it's still our entry (no race with another writer).
		if c.cache[scopeHash] == entry {
			delete(c.cache, scopeHash)
		}
		c.mu.Unlock()
	}

	return result, err
}

// Size returns the number of currently cached entries.
func (c *Coalescer) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cache)
}

// Flush removes all cached entries.
func (c *Coalescer) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*cacheEntry)
}
