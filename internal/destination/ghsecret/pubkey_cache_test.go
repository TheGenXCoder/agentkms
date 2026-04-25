package ghsecret

import (
	"testing"
	"time"
)

// TestPubKeyCache_HitMiss verifies cache hit/miss/TTL expiry behaviour.
func TestPubKeyCache_HitMiss(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cache := newPubkeyCache()
	cache.nowFunc = func() time.Time { return now }

	// Miss on empty cache.
	if _, _, ok := cache.Get("owner", "repo"); ok {
		t.Fatal("expected miss on empty cache")
	}

	// Populate.
	cache.Set("owner", "repo", "keyid1", "pubkey1")

	// Hit within TTL.
	kid, key, ok := cache.Get("owner", "repo")
	if !ok {
		t.Fatal("expected hit after Set")
	}
	if kid != "keyid1" || key != "pubkey1" {
		t.Errorf("got (%q, %q), want (keyid1, pubkey1)", kid, key)
	}

	// Advance past TTL.
	cache.nowFunc = func() time.Time { return now.Add(pubkeyCacheTTL + time.Second) }

	// Miss after TTL.
	if _, _, ok := cache.Get("owner", "repo"); ok {
		t.Fatal("expected miss after TTL expiry")
	}

	// Re-fetch (simulate).
	cache.Set("owner", "repo", "keyid2", "pubkey2")

	// Hit again with new values.
	kid, key, ok = cache.Get("owner", "repo")
	if !ok {
		t.Fatal("expected hit after second Set")
	}
	if kid != "keyid2" || key != "pubkey2" {
		t.Errorf("got (%q, %q), want (keyid2, pubkey2)", kid, key)
	}
}

// TestPubKeyCache_Invalidate verifies that Invalidate forces a re-fetch.
func TestPubKeyCache_Invalidate(t *testing.T) {
	t.Parallel()

	cache := newPubkeyCache()
	cache.Set("owner", "repo", "keyid1", "pubkey1")

	// Sanity: hit before invalidation.
	if _, _, ok := cache.Get("owner", "repo"); !ok {
		t.Fatal("expected hit before invalidation")
	}

	cache.Invalidate("owner", "repo")

	// Miss after invalidation.
	if _, _, ok := cache.Get("owner", "repo"); ok {
		t.Fatal("expected miss after Invalidate")
	}
}

// TestPubKeyCache_MultipleRepos verifies independent entries per (owner, repo).
func TestPubKeyCache_MultipleRepos(t *testing.T) {
	t.Parallel()

	cache := newPubkeyCache()
	cache.Set("org", "repo1", "kid1", "key1")
	cache.Set("org", "repo2", "kid2", "key2")

	kid1, k1, ok1 := cache.Get("org", "repo1")
	kid2, k2, ok2 := cache.Get("org", "repo2")

	if !ok1 || kid1 != "kid1" || k1 != "key1" {
		t.Errorf("repo1: got (%q, %q, %v)", kid1, k1, ok1)
	}
	if !ok2 || kid2 != "kid2" || k2 != "key2" {
		t.Errorf("repo2: got (%q, %q, %v)", kid2, k2, ok2)
	}

	// Invalidating one doesn't affect the other.
	cache.Invalidate("org", "repo1")
	if _, _, ok := cache.Get("org", "repo1"); ok {
		t.Error("repo1 should be gone after Invalidate")
	}
	if _, _, ok := cache.Get("org", "repo2"); !ok {
		t.Error("repo2 should still be present")
	}
}
