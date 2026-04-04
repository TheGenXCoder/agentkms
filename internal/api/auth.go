package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/policy"
)

// AuthHandler implements the /auth/* HTTP endpoints.
//
//	POST /auth/session  — A-06: exchange mTLS cert for a session token
//	POST /auth/refresh  — A-07: refresh an expiring session token
//	POST /auth/revoke   — A-08: revoke a session token
//	POST /auth/delegate — FX-02: delegate a scoped token to a sub-agent
//
// All endpoints are mTLS-only (TLS is enforced at the server level).
// /auth/session is unauthenticated by token (it bootstraps the first token).
// /auth/refresh, /auth/revoke, and /auth/delegate are guarded by
// auth.RequireToken middleware.
type AuthHandler struct {
	tokens      *auth.TokenService
	pki         *auth.PKIClient             // optional; for cert revocation
	certChecker *auth.CertRevocationChecker // optional; for cert revocation
	auditor     audit.Auditor
	policy      policy.EngineI // for scope validation (FX-02)
	environment string         // "dev", "staging", "production"
}

// NewAuthHandler constructs an AuthHandler.
// environment is included in all audit events (e.g. "dev", "production").
func NewAuthHandler(tokens *auth.TokenService, auditor audit.Auditor, eng policy.EngineI, environment string) *AuthHandler {
	return &AuthHandler{
		tokens:      tokens,
		auditor:     auditor,
		policy:      eng,
		environment: environment,
	}
}

// SetPKI wires in the PKI client and cert checker for certificate revocation support.
func (h *AuthHandler) SetPKI(pki *auth.PKIClient, checker *auth.CertRevocationChecker) {
	h.pki = pki
	h.certChecker = checker
}

// ── POST /auth/session ────────────────────────────────────────────────────────

// Session handles POST /auth/session.
//
// Authentication: mTLS only.  No session token required.
// Extracts the caller identity from the verified client certificate and issues
// a new session token (15-minute TTL).
//
// Response 200:
//
//	{
//	  "token":      "<bearer-token>",
//	  "token_type": "Bearer",
//	  "expires_in": 900,
//	  "session_id": "<jti-uuid>"
//	}
//
// A-06.
func (h *AuthHandler) Session(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	id, err := auth.ExtractIdentity(r)
	if err != nil {
		// Do not include err details in the response — the cert error is
		// logged; the client receives a generic message.
		h.logAuditError(r.Context(), r, "", "", audit.OperationAuth,
			"mTLS identity extraction failed")
		writeJSONError(w, http.StatusUnauthorized, "client certificate required")
		return
	}

	// A-13: check for certificate revocation if checker is configured.
	if h.certChecker != nil {
		// We need the raw certificate to get the serial number.
		if len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
			cert := r.TLS.VerifiedChains[0][0]
			if h.certChecker.IsRevoked(cert.SerialNumber) {
				h.logAuditError(r.Context(), r, id.CallerID, id.TeamID,
					audit.OperationAuth, "client certificate revoked")
				writeJSONError(w, http.StatusUnauthorized, "client certificate revoked")
				return
			}
		}
	}

	tokenStr, tok, err := h.tokens.Issue(id)
	if err != nil {
		// tok is nil when Issue returns an error (e.g. JTI generation fails).
		// Use logAuditError which does not require a session ID, to avoid
		// a nil-pointer dereference on tok.JTI.
		h.logAuditError(r.Context(), r, id.CallerID, id.TeamID,
			audit.OperationAuth, "token issuance failed")
		slog.Error("session token issuance failed",
			"caller", id.CallerID,
			"team", id.TeamID,
			"error", err.Error(),
		)
		writeJSONError(w, http.StatusInternalServerError, "session creation failed")
		return
	}

	h.logAudit(r.Context(), r, id.CallerID, id.TeamID, tok.JTI,
		audit.OperationAuth, audit.OutcomeSuccess, "")

	writeJSON(w, http.StatusOK, sessionResponse{
		Token:     tokenStr,
		TokenType: "Bearer",
		ExpiresIn: int(auth.TokenTTL / time.Second),
		SessionID: tok.JTI,
	})
}

// ── Certificate Revocation (A-13) ─────────────────────────────────────────────

// RevokeCertificate handles POST /auth/certificate/revoke.
//
// Admin-only endpoint to revoke a client certificate.
func (h *AuthHandler) RevokeCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if h.pki == nil {
		writeJSONError(w, http.StatusNotImplemented, "PKI support not configured")
		return
	}

	var req struct {
		SerialNumber string `json:"serial_number"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SerialNumber == "" {
		writeJSONError(w, http.StatusBadRequest, "serial_number is required")
		return
	}

	if err := h.pki.RevokeCert(r.Context(), req.SerialNumber); err != nil {
		h.logAuditError(r.Context(), r, "", "", audit.OperationRevokeCert,
			fmt.Sprintf("certificate revocation failed: %v", err))
		writeJSONError(w, http.StatusInternalServerError, "failed to revoke certificate")
		return
	}

	h.logAudit(r.Context(), r, "", "", "", audit.OperationRevokeCert, audit.OutcomeSuccess, "")
	w.WriteHeader(http.StatusNoContent)
}

// CRL handles GET /auth/certificate/crl.
//
// Returns the current CRL from the PKI engine.
func (h *AuthHandler) CRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if h.pki == nil {
		writeJSONError(w, http.StatusNotImplemented, "PKI support not configured")
		return
	}

	crlDER, err := h.pki.FetchCRL(r.Context())
	if err != nil {
		h.logAuditError(r.Context(), r, "", "", audit.OperationGetCRL,
			fmt.Sprintf("CRL fetch failed: %v", err))
		writeJSONError(w, http.StatusInternalServerError, "failed to fetch CRL")
		return
	}

	h.logAudit(r.Context(), r, "", "", "", audit.OperationGetCRL, audit.OutcomeSuccess, "")
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(crlDER)
}

// ── POST /auth/refresh ────────────────────────────────────────────────────────

// Refresh handles POST /auth/refresh.
//
// Authentication: requires a valid session token (via RequireToken middleware).
// Issues a new token with a fresh 15-minute TTL and revokes the old token.
// The caller must immediately switch to the new token.
//
// Response 200: same structure as /auth/session.
//
// A-07.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// The token is already validated by RequireToken middleware; we retrieve
	// the parsed Token from context.
	oldTok := auth.TokenFromContext(r.Context())
	if oldTok == nil {
		// Should never happen if middleware is wired correctly.
		writeJSONError(w, http.StatusUnauthorized, "authorization required")
		return
	}

	newTokenStr, newTok, err := h.tokens.Issue(&oldTok.Identity)
	if err != nil {
		h.logAudit(r.Context(), r, oldTok.Identity.CallerID, oldTok.Identity.TeamID, oldTok.JTI,
			audit.OperationAuthRefresh, audit.OutcomeError, "token issuance failed")
		writeJSONError(w, http.StatusInternalServerError, "token refresh failed")
		return
	}

	// Revoke the old token.  This is best-effort: if revocation fails, the
	// old token will expire naturally in at most 15 minutes.  We log on
	// failure but do not fail the refresh.
	oldTokenStr := auth.ExtractBearerToken(r)
	if _, err := h.tokens.Revoke(oldTokenStr); err != nil {
		slog.Warn("failed to revoke old token during refresh",
			"caller", oldTok.Identity.CallerID,
			"old_jti", oldTok.JTI,
			"error", err.Error(),
		)
	}

	h.logAudit(r.Context(), r, oldTok.Identity.CallerID, oldTok.Identity.TeamID, newTok.JTI,
		audit.OperationAuthRefresh, audit.OutcomeSuccess, "")

	writeJSON(w, http.StatusOK, sessionResponse{
		Token:     newTokenStr,
		TokenType: "Bearer",
		ExpiresIn: int(auth.TokenTTL / time.Second),
		SessionID: newTok.JTI,
	})
}

// ── POST /auth/revoke ─────────────────────────────────────────────────────────

// Revoke handles POST /auth/revoke.
//
// Authentication: requires a valid session token (via RequireToken middleware).
// Immediately adds the token to the server-side revocation blocklist.
//
// The response is always 204 No Content, regardless of whether the revocation
// succeeded.  This prevents oracle attacks where an attacker could probe
// whether a given token was valid by observing success vs. error responses.
//
// A-08.
func (h *AuthHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// The token is already validated by RequireToken middleware.
	tok := auth.TokenFromContext(r.Context())
	if tok == nil {
		// tok == nil means middleware was not wired (should never happen in
		// production).  Return 204 (no oracle) but record the anomaly.
		h.logAuditError(r.Context(), r, "", "",
			audit.OperationRevoke, "revoke called without token in context")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Revoke the token.  The string is re-extracted from the header since
	// the middleware only stored the parsed Token, not the raw string.
	tokenStr := auth.ExtractBearerToken(r)
	outcome := audit.OutcomeSuccess
	if _, err := h.tokens.Revoke(tokenStr); err != nil {
		// Log the internal failure and record OutcomeError in the audit trail.
		// Still return 204 — do not create an oracle for token validity.
		slog.Warn("token revocation failed",
			"caller", tok.Identity.CallerID,
			"jti", tok.JTI,
			"error", err.Error(),
		)
		outcome = audit.OutcomeError
	}

	h.logAudit(r.Context(), r, tok.Identity.CallerID, tok.Identity.TeamID, tok.JTI,
		audit.OperationRevoke, outcome, "")

	w.WriteHeader(http.StatusNoContent)
}

// ── POST /auth/delegate ──────────────────────────────────────────────────────

// Delegate handles POST /auth/delegate.
//
// Authentication: requires a valid session token (via RequireToken middleware).
// Issues a new, short-lived session token with restricted scopes.
//
// The parent token's identity is used as the base.  Each requested scope is
// validated against the parent's current policy permissions.  If any requested
// scope is not allowed by the parent's policy, the entire request is rejected.
//
// FX-02.
func (h *AuthHandler) Delegate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	parentTok := auth.TokenFromContext(r.Context())
	if parentTok == nil {
		writeJSONError(w, http.StatusUnauthorized, "authorization required")
		return
	}

	var req struct {
		Scopes []string `json:"scopes"`
		TTL    int      `json:"ttl_seconds"` // optional; max 15 mins
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Scopes) == 0 {
		writeJSONError(w, http.StatusBadRequest, "scopes are required")
		return
	}

	// Validate requested scopes against policy for the parent identity.
	// A delegation must be a strict subset of the parent's current permissions.
	for _, s := range req.Scopes {
		op, keyID, err := parseScope(s)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid scope format %q: %v", s, err))
			return
		}

		decision, err := h.policy.Evaluate(r.Context(), parentTok.Identity, op, keyID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "policy evaluation failed")
			return
		}
		if !decision.Allow {
			h.logAudit(r.Context(), r, parentTok.Identity.CallerID, parentTok.Identity.TeamID, parentTok.JTI,
				audit.OperationAuthDelegate, audit.OutcomeDenied,
				fmt.Sprintf("delegation of %q denied: %s", s, decision.DenyReason))
			writeJSONError(w, http.StatusForbidden, fmt.Sprintf("delegation of scope %q is not permitted by policy", s))
			return
		}
	}

	// Determine delegation TTL.  Default is 5 minutes; max is parent token's
	// remaining life or 15 minutes (whichever is smaller).
	ttl := 5 * time.Minute
	if req.TTL > 0 {
		ttl = time.Duration(req.TTL) * time.Second
	}
	if ttl > 15*time.Minute {
		ttl = 15 * time.Minute
	}
	remaining := time.Until(parentTok.ExpiresAt)
	if ttl > remaining {
		ttl = remaining
	}

	tokenStr, tok, err := h.tokens.IssueDelegated(&parentTok.Identity, ttl, req.Scopes)
	if err != nil {
		h.logAudit(r.Context(), r, parentTok.Identity.CallerID, parentTok.Identity.TeamID, parentTok.JTI,
			audit.OperationAuthDelegate, audit.OutcomeError, "token issuance failed")
		writeJSONError(w, http.StatusInternalServerError, "delegation failed")
		return
	}

	h.logAudit(r.Context(), r, parentTok.Identity.CallerID, parentTok.Identity.TeamID, tok.JTI,
		audit.OperationAuthDelegate, audit.OutcomeSuccess, "")

	writeJSON(w, http.StatusOK, sessionResponse{
		Token:     tokenStr,
		TokenType: "Bearer",
		ExpiresIn: int(ttl / time.Second),
		SessionID: tok.JTI,
	})
}

// parseScope splits an "op:resource" string.
func parseScope(s string) (string, string, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected op:resource")
	}
	return parts[0], parts[1], nil
}

// ── Audit helpers ──────────────────────────────────────────────────────────────

// logAudit writes a structured audit event.  Errors from the auditor are
// logged to the structured logger but do not fail the request — the operation
// has already completed; failing the response for an audit write error would
// create a denial-of-service vector via audit sink exhaustion.
//
// NOTE: Per AGENTS.md security rules, the auditor must be called for EVERY
// operation.  Silent audit failures are not permitted.  If the auditor
// returns an error, it must be visible in the service logs.
//
// ctx is intentionally detached from the request context via
// context.WithoutCancel so that audit events are written even if the client
// disconnects before the write completes.  Per audit.Auditor contract: callers
// MUST use a detached context to prevent silent drops (SOC 2 CC7.2,
// PCI-DSS Req 10).
func (h *AuthHandler) logAudit(
	ctx context.Context,
	r *http.Request,
	callerID, teamID, sessionID string,
	operation, outcome, denyReason string,
) {
	// Detach from request context: ensures audit write is not cancelled
	// if the client disconnects mid-request.
	auditCtx := context.WithoutCancel(ctx)

	ev, err := audit.New()
	if err != nil {
		slog.Error("audit event ID generation failed", "error", err.Error())
		return
	}
	ev.CallerID = callerID
	ev.TeamID = teamID
	ev.AgentSession = sessionID
	ev.Operation = operation
	ev.Outcome = outcome
	ev.DenyReason = denyReason
	ev.SourceIP = sourceIP(r)
	ev.UserAgent = userAgent(r)
	ev.Environment = h.environment
	ev.ComplianceTags = []string{"soc2", "iso27001"}

	if err := h.auditor.Log(auditCtx, ev); err != nil {
		slog.Error("audit write failed",
			"operation", operation,
			"caller", callerID,
			"error", err.Error(),
		)
	}
}

// logAuditError is a convenience wrapper for error outcomes when the caller
// identity is not yet known (e.g. identity extraction failed).
func (h *AuthHandler) logAuditError(
	ctx context.Context,
	r *http.Request,
	callerID, teamID string,
	operation, denyReason string,
) {
	h.logAudit(ctx, r, callerID, teamID, "", operation, audit.OutcomeError, denyReason)
}

// ── Response types ────────────────────────────────────────────────────────────

// sessionResponse is the JSON body returned by /auth/session and /auth/refresh.
type sessionResponse struct {
	// Token is the Bearer token string to include in subsequent requests.
	Token string `json:"token"`

	// TokenType is always "Bearer".
	TokenType string `json:"token_type"`

	// ExpiresIn is the number of seconds until the token expires.
	// Always 900 (15 minutes) for freshly issued tokens.
	ExpiresIn int `json:"expires_in"`

	// SessionID is the JTI of this token, used as the AgentSession identifier
	// in audit events to correlate all operations within this session.
	SessionID string `json:"session_id"`
}
