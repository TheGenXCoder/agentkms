package github

import "time"

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
type Ingester struct{}

// NewIngester creates an Ingester that recognises the given set of token hashes.
func NewIngester(knownHashes []string) *Ingester {
	return &Ingester{}
}

// Correlate takes a batch of audit entries and returns UsageRecords
// for entries that match known credential hashes.
func (ing *Ingester) Correlate(entries []AuditEntry) []UsageRecord {
	return nil
}
