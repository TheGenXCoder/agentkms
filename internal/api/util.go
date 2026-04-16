package api

import (
	"encoding/json"
	"net/http"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
)

// populateAnomalies copies rules-based anomaly messages from a policy
// Decision to an AuditEvent.
func populateAnomalies(ev *audit.AuditEvent, anomalies []policy.AnomalyRecord) {
	for _, a := range anomalies {
		ev.Anomalies = append(ev.Anomalies, a.Message)
	}
}

// populateIdentityFields copies the forensics-relevant identity fields from
// id into ev.  CallerID / TeamID / AgentSession are preserved as before;
// CertFingerprint / CallerOU / CallerRole are new in SchemaVersion 1.
//
// Safe to call on a zero-value Identity (all fields default to empty
// strings, matching the omitempty JSON tags).
func populateIdentityFields(ev *audit.AuditEvent, id identity.Identity) {
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession
	// SchemaVersion 1 forensics fields.
	ev.CertFingerprint = id.CertFingerprint
	ev.CallerOU = id.CallerOU
	ev.CallerRole = string(id.Role)
}

// populateDecisionFields copies policy-decision forensics fields into ev.
// Must be called on both allow and deny paths so that RuleID is captured
// even on successful allows (not only denials).
func populateDecisionFields(ev *audit.AuditEvent, decision policy.Decision) {
	ev.RuleID = decision.MatchedRuleID
	populateAnomalies(ev, decision.Anomalies)
}

// writeJSONError writes a simple {"error": "<msg>"} JSON response.
// Used by the auth handler and auth middleware.
//
// SECURITY: msg must not contain key material, tokens, or internal details.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write(body)
}

// decodeJSON decodes a JSON request body into the given destination.
func decodeJSON(r *http.Request, dest any) error {
	return json.NewDecoder(r.Body).Decode(dest)
}

// sourceIP is an alias for extractRemoteIP. Used by auth.go.
func sourceIP(r *http.Request) string { return extractRemoteIP(r) }

// userAgent returns the User-Agent header trimmed to a safe maximum length.
func userAgent(r *http.Request) string {
	ua := r.UserAgent()
	const maxLen = 256
	if len(ua) > maxLen {
		return ua[:maxLen]
	}
	return ua
}
