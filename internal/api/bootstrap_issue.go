package api

// bootstrap_issue.go — POST /auth/bootstrap/issue
//
// Allows an operator with a cert+human-strength session to self-mint a
// single-use bootstrap token that a device can later redeem via
// POST /auth/cert/issue (Mode 1 of HandleCertIssue).
//
// Wire format:
//
//	POST /auth/bootstrap/issue
//	Authorization: Bearer <session-token>   (auth_strength >= cert+human required)
//	{
//	  "device_name_pattern": "<[a-z0-9-]{1,64} or *>",
//	  "ttl_seconds":         <int, default 3600, max 86400>
//	}
//
// Response 200:
//
//	{
//	  "bootstrap_token": "<64-hex-char opaque single-use token>",
//	  "expires_at":      "<RFC3339>"
//	}

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
)

const (
	bootstrapDefaultTTL = 3600
	bootstrapMaxTTL     = 86400
	bootstrapMinTTL     = 60
)

// deviceNamePatternRE matches valid device_name_pattern values: [a-z0-9-]{1,64}.
// The single literal "*" is accepted separately by the handler before the regex
// check so the regex stays readable without a conditional alternation.
var deviceNamePatternRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// ── Request / response types ──────────────────────────────────────────────────

type bootstrapIssueRequest struct {
	DeviceNamePattern string `json:"device_name_pattern"`
	TTLSeconds        int    `json:"ttl_seconds"`
}

type bootstrapIssueResponse struct {
	BootstrapToken string `json:"bootstrap_token"`
	ExpiresAt      string `json:"expires_at"`
}

// ── POST /auth/bootstrap/issue ────────────────────────────────────────────────

// HandleBootstrapIssue handles POST /auth/bootstrap/issue.
//
// The caller must hold a session token with auth_strength=cert+human.  On
// success, a single-use opaque bootstrap token is written to the bootstrap
// store and the 64-char hex raw token is returned to the caller.  The raw
// token is never logged — only its SHA-256 hash is persisted in the store.
func (h *AuthHandler) HandleBootstrapIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// ── Auth: require bearer ──────────────────────────────────────────────────
	bearerToken := auth.ExtractBearerToken(r)
	if bearerToken == "" {
		writeJSONError(w, http.StatusUnauthorized, "authorization required")
		return
	}

	tok, err := h.tokens.Validate(bearerToken)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid or expired session token")
		return
	}

	// ── Auth: require cert+human strength ────────────────────────────────────
	if !tok.AuthStrength.AtLeast(auth.AuthStrengthCertHuman) {
		h.logAuditError(r.Context(), r, tok.Identity.CallerID, tok.Identity.TeamID,
			audit.OperationBootstrapIssue,
			"insufficient auth_strength: cert+human required to issue a bootstrap token")
		writeJSONError(w, http.StatusForbidden,
			"cert+human authentication required to issue a bootstrap token")
		return
	}

	// ── Decode request body ───────────────────────────────────────────────────
	var req bootstrapIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// ── Validate device_name_pattern ─────────────────────────────────────────
	// Accept the single literal "*" or a string matching [a-z0-9-]{1,64}.
	if req.DeviceNamePattern != "*" && !deviceNamePatternRE.MatchString(req.DeviceNamePattern) {
		writeJSONError(w, http.StatusBadRequest,
			"device_name_pattern must match [a-z0-9-]{1,64} or be the literal '*'")
		return
	}

	// ── Validate ttl_seconds ──────────────────────────────────────────────────
	ttl := req.TTLSeconds
	if ttl == 0 {
		ttl = bootstrapDefaultTTL
	}
	if ttl > bootstrapMaxTTL {
		writeJSONError(w, http.StatusBadRequest,
			fmt.Sprintf("ttl_seconds must not exceed %d (24h)", bootstrapMaxTTL))
		return
	}
	if ttl < bootstrapMinTTL {
		writeJSONError(w, http.StatusBadRequest,
			fmt.Sprintf("ttl_seconds must be at least %d", bootstrapMinTTL))
		return
	}

	// ── Bootstrap store must be configured ───────────────────────────────────
	if h.bootstrapStore == nil {
		writeJSONError(w, http.StatusInternalServerError, "bootstrap token support not configured")
		return
	}

	// ── Build the record ──────────────────────────────────────────────────────
	expiresAt := time.Now().UTC().Add(time.Duration(ttl) * time.Second)

	userID := tok.Identity.UserID
	if userID == "" {
		userID = tok.Identity.CallerID
	}

	record := auth.BootstrapRecord{
		UserID:            userID,
		DeviceNamePattern: req.DeviceNamePattern,
		ExpiresAt:         expiresAt,
		Used:              false,
	}

	// ── Write to store ────────────────────────────────────────────────────────
	rawToken, err := h.bootstrapStore.Create(r.Context(), record)
	if err != nil {
		slog.Error("bootstrap_issue: store write failed",
			"user_id", userID,
			"pattern", req.DeviceNamePattern,
			"error", err,
		)
		writeJSONError(w, http.StatusInternalServerError, "failed to create bootstrap token")
		return
	}

	// ── Audit ─────────────────────────────────────────────────────────────────
	h.logBootstrapIssueAudit(r, tok.JTI, userID, req.DeviceNamePattern, expiresAt)

	// ── Respond ───────────────────────────────────────────────────────────────
	writeJSON(w, http.StatusOK, bootstrapIssueResponse{
		BootstrapToken: rawToken,
		ExpiresAt:      expiresAt.Format(time.RFC3339),
	})
}

// logBootstrapIssueAudit writes a structured audit event for a successful
// bootstrap token issuance.  The raw token is never included; KeyID encodes
// the user+pattern pair for SIEM correlation.
func (h *AuthHandler) logBootstrapIssueAudit(
	r *http.Request,
	sessionID, userID, pattern string,
	expiresAt time.Time,
) {
	ev, err := audit.New()
	if err != nil {
		slog.Error("audit event ID generation failed", "error", err)
		return
	}
	ev.CallerID = userID
	ev.AgentSession = sessionID
	ev.Operation = audit.OperationBootstrapIssue
	ev.Outcome = audit.OutcomeSuccess
	// Encode user+pattern in KeyID so SIEM can group by target user.
	// Pattern is safe: validated to [a-z0-9-]{1,64} or "*" — well below
	// the 64-char hex heuristic threshold.
	ev.KeyID = fmt.Sprintf("bootstrap/%s/%s", userID, pattern)
	ev.SourceIP = sourceIP(r)
	ev.UserAgent = userAgent(r)
	ev.Environment = h.environment
	ev.ComplianceTags = []string{"soc2", "iso27001"}

	slog.Info("bootstrap token issued",
		"user_id", userID,
		"pattern", pattern,
		"expires_at", expiresAt.Format(time.RFC3339),
	)

	if logErr := h.auditor.Log(r.Context(), ev); logErr != nil {
		slog.Error("audit write failed",
			"operation", audit.OperationBootstrapIssue,
			"error", logErr,
		)
	}
}
