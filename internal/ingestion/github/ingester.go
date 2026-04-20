package github

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// AuditEntry represents a single GitHub audit log entry (simplified).
type AuditEntry struct {
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
	Repo      string    `json:"repo"`
	TokenID   string    `json:"token_id"`
}

// UsageRecord is a correlated usage event for a vended credential.
type UsageRecord struct {
	ProviderTokenHash string
	Action            string
	Repo              string
	Timestamp         time.Time
}

// Ingester processes GitHub audit log entries and correlates with known credentials.
type Ingester struct {
	knownHashes map[string]struct{}
}

// NewIngester creates an Ingester that recognises the given set of token hashes.
func NewIngester(knownHashes []string) *Ingester {
	m := make(map[string]struct{}, len(knownHashes))
	for _, h := range knownHashes {
		m[h] = struct{}{}
	}
	return &Ingester{knownHashes: m}
}

// Correlate takes a batch of audit entries and returns UsageRecords
// for entries that match known credential hashes.
func (ing *Ingester) Correlate(entries []AuditEntry) []UsageRecord {
	results := make([]UsageRecord, 0)
	for _, entry := range entries {
		if entry.TokenID == "" {
			continue
		}
		sum := sha256.Sum256([]byte(entry.TokenID))
		hash := hex.EncodeToString(sum[:])
		if _, ok := ing.knownHashes[hash]; ok {
			results = append(results, UsageRecord{
				ProviderTokenHash: hash,
				Action:            entry.Action,
				Repo:              entry.Repo,
				Timestamp:         entry.CreatedAt,
			})
		}
	}
	return results
}
