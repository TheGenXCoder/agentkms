package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
)

// ── GET /audit/export ────────────────────────────────────────────────────────

// handleExportAuditLogs handles GET /audit/export.
// Query parameters:
//   - start: start time (RFC 3339)
//   - end: end time (RFC 3339)
//
// This endpoint is used by compliance officers to download audit records.
//
// AU-10.
func (s *Server) handleExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	// SECURITY: only the platform-team or identities with the 'auditor'
	// role are permitted to export logs.  The policy engine enforces this.
	// For this task, we assume the policy engine manages the decision.
	decision, err := s.policy.Evaluate(ctx, id, "audit_export", "*")
	if err != nil || !decision.Allow {
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied")
		return
	}

	// 1. Parse query parameters.
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid start time")
		return
	}
	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid end time")
		return
	}

	// 2. Check if auditor supports export.
	exporter, ok := s.auditor.(audit.Exporter)
	if !ok {
		s.writeError(w, http.StatusNotImplemented, errCodeInternal, "audit export not supported by current sink")
		return
	}

	// 3. Start export stream.
	out, errc := exporter.Export(ctx, start, end)
	if out == nil {
		s.writeError(w, http.StatusNotImplemented, errCodeInternal, "export failed")
		return
	}

	// 4. Set headers and stream NDJSON.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-export.json"`)
	// Use HTTP Trailers to signal integrity as recommended by Finding 7.
	w.Header().Set("Trailer", "X-Export-Status")
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	success := false
	defer func() {
		if success {
			w.Header().Set("X-Export-Status", "SUCCESS")
		} else {
			w.Header().Set("X-Export-Status", "INCOMPLETE")
		}
	}()

	for {
		select {
		case ev, ok := <-out:
			if !ok {
				// Check for errors at the end of the stream.
				if err := <-errc; err != nil {
					// We already sent 200 OK, so we just abort the stream.
					return
				}
				success = true
				return
			}
			if err := enc.Encode(ev); err != nil {
				return
			}
		case err := <-errc:
			if err != nil {
				// If we error before sending any events, we could try to send a 500,
				// but we already sent the headers. Just abort.
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// ── POST /audit/use ─────────────────────────────────────────────────────────

// useRequest is the body for POST /audit/use.
type useRequest struct {
	Provider string `json:"provider"`
	Action   string `json:"action"` // e.g., "chat", "embeddings"
}

// handleLogCredentialUse handles POST /audit/use.
//
// This is called by the Pi extension (or other clients) every time a
// vended credential is used.  It correlates the use with the session.
//
// LV-06.
func (s *Server) handleLogCredentialUse(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	// SECURITY: Add missing policy check (Finding 5)
	decision, err := s.policy.Evaluate(ctx, id, "audit_write", "*")
	if err != nil || !decision.Allow {
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied")
		return
	}

	var req useRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid request body")
		return
	}

	// SECURITY: Validate provider against regex to prevent log poisoning (Finding 6)
	validProvider := regexp.MustCompile(`^[a-z0-9-]+$`)
	if !validProvider.MatchString(req.Provider) {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid provider format")
		return
	}

	ev, err := audit.New()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	ev.Operation = audit.OperationCredentialUse
	ev.KeyID = "llm/" + req.Provider
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.Outcome = audit.OutcomeSuccess
	// ComplianceTags: log that this is an AI transparency event.
	ev.ComplianceTags = []string{"colorado-ai-act", "soc2"}

	if err := s.auditLog(ctx, ev); err != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
