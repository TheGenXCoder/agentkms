package github

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// hashTokenID mirrors the expected production logic: SHA-256 hex of tokenID.
func hashTokenID(tokenID string) string {
	h := sha256.Sum256([]byte(tokenID))
	return hex.EncodeToString(h[:])
}

func TestIngester_Correlate_MatchingEntry(t *testing.T) {
	tokenID := "ghp_abc123"
	hash := hashTokenID(tokenID)
	ing := NewIngester([]string{hash})

	entries := []AuditEntry{
		{
			Action:    "repo.clone",
			Actor:     "bot-user",
			CreatedAt: time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC),
			Repo:      "org/repo",
			TokenID:   tokenID,
		},
	}

	results := ing.Correlate(entries)
	if len(results) != 1 {
		t.Fatalf("expected 1 UsageRecord, got %d", len(results))
	}
	if results[0].ProviderTokenHash != hash {
		t.Errorf("expected hash %s, got %s", hash, results[0].ProviderTokenHash)
	}
}

func TestIngester_Correlate_NoMatch(t *testing.T) {
	knownHash := hashTokenID("ghp_known")
	ing := NewIngester([]string{knownHash})

	entries := []AuditEntry{
		{
			Action:    "repo.push",
			Actor:     "unknown-bot",
			CreatedAt: time.Now(),
			Repo:      "org/other",
			TokenID:   "ghp_unknown",
		},
	}

	results := ing.Correlate(entries)
	if len(results) != 0 {
		t.Fatalf("expected 0 UsageRecords for non-matching entry, got %d", len(results))
	}
}

func TestIngester_Correlate_MultipleEntries_SomeMatch(t *testing.T) {
	token1 := "ghp_match1"
	token2 := "ghp_match2"
	hash1 := hashTokenID(token1)
	hash2 := hashTokenID(token2)
	ing := NewIngester([]string{hash1, hash2})

	entries := []AuditEntry{
		{Action: "repo.clone", TokenID: token1, CreatedAt: time.Now()},
		{Action: "repo.push", TokenID: "ghp_nope1", CreatedAt: time.Now()},
		{Action: "org.invite", TokenID: token2, CreatedAt: time.Now()},
		{Action: "repo.delete", TokenID: "ghp_nope2", CreatedAt: time.Now()},
		{Action: "repo.read", TokenID: "ghp_nope3", CreatedAt: time.Now()},
	}

	results := ing.Correlate(entries)
	if len(results) != 2 {
		t.Fatalf("expected 2 UsageRecords from 5 entries, got %d", len(results))
	}
}

func TestIngester_Correlate_EmptyTokenID(t *testing.T) {
	ing := NewIngester([]string{hashTokenID("")}) // even if empty hash is "known"

	entries := []AuditEntry{
		{Action: "repo.clone", TokenID: "", CreatedAt: time.Now()},
	}

	// Entries with empty TokenID must be skipped regardless.
	results := ing.Correlate(entries)
	if len(results) != 0 {
		t.Fatalf("expected empty TokenID to be skipped, got %d results", len(results))
	}
}

func TestIngester_Correlate_PreservesFields(t *testing.T) {
	tokenID := "ghp_fields"
	hash := hashTokenID(tokenID)
	ing := NewIngester([]string{hash})

	ts := time.Date(2026, 4, 16, 12, 30, 0, 0, time.UTC)
	entries := []AuditEntry{
		{
			Action:    "repo.push",
			Actor:     "deploy-bot",
			CreatedAt: ts,
			Repo:      "org/service",
			TokenID:   tokenID,
		},
	}

	results := ing.Correlate(entries)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Action != "repo.push" {
		t.Errorf("Action: expected %q, got %q", "repo.push", r.Action)
	}
	if r.Repo != "org/service" {
		t.Errorf("Repo: expected %q, got %q", "org/service", r.Repo)
	}
	if !r.Timestamp.Equal(ts) {
		t.Errorf("Timestamp: expected %v, got %v", ts, r.Timestamp)
	}
	if r.ProviderTokenHash != hash {
		t.Errorf("ProviderTokenHash: expected %s, got %s", hash, r.ProviderTokenHash)
	}
}

func TestIngester_Correlate_EmptyBatch(t *testing.T) {
	ing := NewIngester([]string{hashTokenID("ghp_something")})

	results := ing.Correlate([]AuditEntry{})
	if results == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results for empty batch, got %d", len(results))
	}
}

func TestIngester_NewIngester_EmptyHashes(t *testing.T) {
	ing := NewIngester([]string{})

	entries := []AuditEntry{
		{Action: "repo.clone", TokenID: "ghp_any", CreatedAt: time.Now()},
		{Action: "repo.push", TokenID: "ghp_other", CreatedAt: time.Now()},
	}

	results := ing.Correlate(entries)
	if len(results) != 0 {
		t.Fatalf("expected 0 results when no hashes known, got %d", len(results))
	}
}
