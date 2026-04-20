package credentials

import "time"

// Coalescer wraps a vend function and deduplicates concurrent identical requests.
// Two requests are "identical" if they produce the same ScopeHash.
type Coalescer struct{}

// NewCoalescer creates a Coalescer with the given TTL for cached entries.
func NewCoalescer(ttl time.Duration) *Coalescer {
	_ = ttl
	return &Coalescer{}
}

// CoalesceOrCall checks if a result for the given scopeHash is cached and still valid.
// If yes, returns the cached result. If no, calls the provided vend function,
// caches the result, and returns it.
func (c *Coalescer) CoalesceOrCall(scopeHash string, vend func() (*ScopedResult, error)) (*ScopedResult, error) {
	_ = scopeHash
	_ = vend
	return nil, nil
}

// Size returns the number of currently cached entries.
func (c *Coalescer) Size() int {
	return 0
}

// Flush removes all cached entries.
func (c *Coalescer) Flush() {}
