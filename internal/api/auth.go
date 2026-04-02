package api

import (
	"net/http"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
)

// ── Request / response types ──────────────────────────────────────────────────

type sessionResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"` // RFC 3339
	SessionID string `json:"session_id"`
}

type refreshResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// handleAuthSession implements POST /auth/session.
//
// Authentication:  mTLS client certificate only — no Bearer token.
// Identity source: the verified TLS peer certificate (already validated by
//
//	the TLS stack against the dev CA).
//
// Response: session token (15-min TTL), expiry time, and session ID.
//
// Audit: operation=auth, caller from cert, outcome=success/error.
func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	ev, err := audit.New()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ev.Operation = audit.OperationAuth
	ev.Environment = s.env
	ev.SourceIP = sourceIP(r)
	ev.UserAgent = r.Header.Get("User-Agent")
	ev.Outcome = audit.OutcomeError // default; overwritten on success

	defer func() { s.logAudit(r, ev) }()

	// Extract identity from the mTLS client certificate.
	id, err := auth.IdentityFromTLS(r.TLS)
	if err != nil {
		// This path is unusual: the TLS stack should have rejected connections
		// without a valid client cert before we get here.  Log at WARN.
		s.logger.Warn("auth/session: identity extraction failed",
			"source_ip", sourceIP(r), "error", err.Error())
		
		// Add placeholder identifiers for the audit event
		// This ensures auth failures are properly recorded
		ev.CallerID = "INVALID_CERTIFICATE"
		ev.TeamID = "UNKNOWN"
		ev.ErrorDetail = err.Error() // Record the specific error
		
		writeError(w, http.StatusUnauthorized, "client certificate required")
		return
	}

	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID

	// Issue session token.
	tokenStr, tok, err := s.tokens.Issue(id)
	if err != nil {
		s.logger.Error("auth/session: token issuance failed", "caller_id", id.CallerID, "error", err)
		writeError(w, http.StatusInternalServerError, "token issuance failed")
		return
	}

	ev.AgentSession = tok.SessionID
	ev.Outcome = audit.OutcomeSuccess

	writeJSON(w, sessionResponse{
		Token:     tokenStr,
		ExpiresAt: tok.ExpiresAt.Format(time.RFC3339),
		SessionID: tok.SessionID,
	})
}

// handleAuthRefresh implements POST /auth/refresh.
//
// Authentication: Bearer token (validated by requireToken middleware).
// Issues a new token for the same identity with a fresh 15-min TTL.
// The old token remains valid until its natural expiry — callers should
// stop using it immediately.
//
// Audit: operation=auth_refresh.
func (s *Server) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromContext(r.Context())

	ev, err := audit.New()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ev.Operation = audit.OperationAuthRefresh
	ev.Environment = s.env
	ev.CallerID = tok.CallerID
	ev.TeamID = tok.TeamID
	ev.AgentSession = tok.SessionID
	ev.SourceIP = sourceIP(r)
	ev.UserAgent = r.Header.Get("User-Agent")
	ev.Outcome = audit.OutcomeError

	defer func() { s.logAudit(r, ev) }()

	newTokenStr, newTok, err := s.tokens.Issue(tok.Identity)
	if err != nil {
		s.logger.Error("auth/refresh: token issuance failed", "caller_id", tok.CallerID, "error", err)
		writeError(w, http.StatusInternalServerError, "token refresh failed")
		return
	}

	ev.Outcome = audit.OutcomeSuccess

	writeJSON(w, refreshResponse{
		Token:     newTokenStr,
		ExpiresAt: newTok.ExpiresAt.Format(time.RFC3339),
	})
}

// handleAuthRevoke implements POST /auth/revoke.
//
// Authentication: Bearer token (validated by requireToken middleware).
// Adds the presented token to the server-side revocation list.  Subsequent
// Validate calls for this token will return an error immediately.
//
// Response: 204 No Content on success.
// Audit: operation=revoke.
func (s *Server) handleAuthRevoke(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromContext(r.Context())

	ev, err := audit.New()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ev.Operation = audit.OperationRevoke
	ev.Environment = s.env
	ev.CallerID = tok.CallerID
	ev.TeamID = tok.TeamID
	ev.AgentSession = tok.SessionID
	ev.SourceIP = sourceIP(r)
	ev.UserAgent = r.Header.Get("User-Agent")
	ev.Outcome = audit.OutcomeError

	defer func() { s.logAudit(r, ev) }()

	// Extract the raw token string from the Authorization header for revocation.
	// requireToken already validated it, so we know it is well-formed.
	const bearerPrefix = "Bearer "
	tokenStr := r.Header.Get("Authorization")[len(bearerPrefix):]

	if err := s.tokens.Revoke(tokenStr); err != nil {
		s.logger.Error("auth/revoke: revocation failed", "token_id", tok.TokenID, "error", err)
		writeError(w, http.StatusInternalServerError, "revocation failed")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	w.WriteHeader(http.StatusNoContent)
}
