package forensics

import (
	"encoding/json"
	"errors"
	"strings"
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

// InspectByToken hashes the token and delegates to InspectByTokenHash.
func (i *Inspector) InspectByToken(rawToken string) (*Report, error) {
	hash := audit.HashProviderToken([]byte(rawToken))
	return i.InspectByTokenHash(hash)
}

// InspectByTokenHash finds the credential lifecycle for the given
// provider token hash and returns a structured report.
func (i *Inspector) InspectByTokenHash(hash string) (*Report, error) {
	// Find the vend event matching the token hash.
	var vendEvent *audit.AuditEvent
	for idx := range i.events {
		if i.events[idx].ProviderTokenHash == hash && i.events[idx].Operation == audit.OperationCredentialVend {
			vendEvent = &i.events[idx]
			break
		}
	}
	if vendEvent == nil {
		return nil, errors.New("credential not found")
	}

	credUUID := vendEvent.CredentialUUID

	// Build report from vend event.
	report := &Report{
		CredentialUUID: credUUID,
		CredentialType: vendEvent.CredentialType,
		CallerID:       vendEvent.CallerID,
		TeamID:         vendEvent.TeamID,
		RuleID:         vendEvent.RuleID,
		Scope:          vendEvent.Scope,
		ScopeHash:      vendEvent.ScopeHash,
		IssuedAt:       vendEvent.Timestamp,
	}

	// Parse expires_at from Scope JSON if present.
	if len(vendEvent.Scope) > 0 {
		var scopeData map[string]interface{}
		if err := json.Unmarshal(vendEvent.Scope, &scopeData); err == nil {
			if expiresAtStr, ok := scopeData["expires_at"].(string); ok {
				if t, err := time.Parse(time.RFC3339, expiresAtStr); err == nil {
					report.ExpiredAt = t
				}
			}
		}
	}

	// Find usage events and detection events.
	for idx := range i.events {
		ev := &i.events[idx]
		if ev.CredentialUUID != credUUID {
			continue
		}
		// Usage events
		if ev.Operation == audit.OperationCredentialUse {
			report.UsageEvents = append(report.UsageEvents, UsageEvent{
				Timestamp: ev.Timestamp,
				Operation: ev.Operation,
			})
		}
		// Detection events - check for leak/compromised in InvalidationReason
		if ev.InvalidationReason != "" &&
			(strings.Contains(ev.InvalidationReason, "leak") ||
				strings.Contains(ev.InvalidationReason, "compromised")) {
			report.DetectedAt = ev.Timestamp
			report.InvalidationReason = ev.InvalidationReason
		}
	}

	// Compute assessment.
	if !report.DetectedAt.IsZero() {
		if !report.ExpiredAt.IsZero() && report.ExpiredAt.Before(report.DetectedAt) {
			report.Assessment = "no damage"
		} else {
			report.Assessment = "potential exposure"
		}
	}

	return report, nil
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
