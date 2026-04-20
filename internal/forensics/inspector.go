package forensics

import (
	"encoding/json"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
)

// Inspector queries audit events and produces forensic reports.
type Inspector struct {
	events []audit.AuditEvent
}

// NewInspector creates an Inspector from a slice of audit events.
func NewInspector(events []audit.AuditEvent) *Inspector {
	return &Inspector{events: events}
}

// InspectByTokenHash finds the credential lifecycle for the given
// provider token hash and returns a structured report.
func (i *Inspector) InspectByTokenHash(hash string) (*Report, error) {
	// TODO: implement
	return nil, nil
}

// InspectByToken hashes the token and delegates to InspectByTokenHash.
func (i *Inspector) InspectByToken(rawToken string) (*Report, error) {
	// TODO: implement
	return nil, nil
}

// Report is the structured forensic chain-of-custody report for a credential.
type Report struct {
	CredentialUUID     string
	Provider           string
	CredentialType     string
	Kind               string
	IssuedAt           time.Time
	ExpiredAt          time.Time
	DetectedAt         time.Time // zero if not yet detected
	InvalidationReason string
	CallerID           string
	TeamID             string
	RuleID             string
	Scope              json.RawMessage
	ScopeHash          string
	UsageEvents        []UsageEvent
	Assessment         string // "no damage", "potential exposure", etc.
}

// UsageEvent represents a single usage of a credential in the audit trail.
type UsageEvent struct {
	Timestamp   time.Time
	Operation   string
	Description string
}
