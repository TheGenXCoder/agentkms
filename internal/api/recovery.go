package api

// recovery.go — HTTP handlers for recovery code management.
//
// POST /auth/recovery/init     — generate recovery codes for the caller (enrolled devices only)
// POST /auth/recovery/redeem   — redeem a recovery code to get a bootstrap token
// GET  /auth/recovery/status   — how many codes remain for the caller
//
// These endpoints are intentionally rate-limited more aggressively than the
// normal credential vending path. The policy engine evaluates each request.

import (
	"encoding/json"
	"net/http"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
)

// ── POST /auth/recovery/init ─────────────────────────────────────────────────

type recoveryInitResponse struct {
	// Codes are the plaintext recovery codes.
	// SECURITY: shown ONCE — the server does not store these.
	// The caller must print/save them before this response is discarded.
	Codes []recoveryCodeEntry `json:"codes"`

	// Warning reminds the caller to save the codes.
	Warning string `json:"warning"`
}

type recoveryCodeEntry struct {
	Index     int    `json:"index"`
	Plaintext string `json:"code"`
}

func (s *Server) handleRecoveryInit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	ev, _ := audit.New()
	populateIdentityFields(&ev, id)
	ev.Operation = "recovery_init"
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)

	if s.recoveryStore == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "recovery not configured")
		return
	}

	codes, err := s.recoveryStore.GenerateRecoveryCodes(id.CallerID)
	if err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "failed to generate recovery codes")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	_ = s.auditLog(ctx, ev)

	entries := make([]recoveryCodeEntry, len(codes))
	for i, c := range codes {
		entries[i] = recoveryCodeEntry{Index: c.Index, Plaintext: c.Plaintext}
	}

	writeJSON(w, http.StatusOK, recoveryInitResponse{
		Codes:   entries,
		Warning: "SAVE THESE CODES NOW. They will not be shown again. Store them offline, not on this machine.",
	})
}

// ── POST /auth/recovery/redeem ───────────────────────────────────────────────

type recoveryRedeemRequest struct {
	CallerID string `json:"caller_id"`
	Code     string `json:"code"`
}

type recoveryRedeemResponse struct {
	// BootstrapToken is a short-lived token for re-enrollment on a new device.
	// Treat this as a temporary password — it expires in 15 minutes.
	BootstrapToken string `json:"bootstrap_token"`
	ExpiresIn      string `json:"expires_in"`
}

func (s *Server) handleRecoveryRedeem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req recoveryRedeemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CallerID == "" || req.Code == "" {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "caller_id and code are required")
		return
	}

	ev, _ := audit.New()
	ev.CallerID = req.CallerID // note: unauthenticated claim at this point
	ev.Operation = "recovery_redeem"
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)

	if s.recoveryStore == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "recovery not configured")
		return
	}

	if err := s.recoveryStore.RedeemRecoveryCode(req.CallerID, req.Code); err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid recovery code"
		_ = s.auditLog(ctx, ev)
		// Generic error — don't leak whether the caller_id exists.
		s.writeError(w, http.StatusUnauthorized, errCodePolicyDenied, "invalid code or identity")
		return
	}

	// Issue a short-lived bootstrap token.
	bootstrapToken, err := s.tokenService.IssueBootstrapToken(req.CallerID)
	if err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	_ = s.auditLog(ctx, ev)

	writeJSON(w, http.StatusOK, recoveryRedeemResponse{
		BootstrapToken: bootstrapToken,
		ExpiresIn:      auth.RecoveryTokenTTL.String(),
	})
}

// ── GET /auth/recovery/status ────────────────────────────────────────────────

func (s *Server) handleRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	if s.recoveryStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "recovery not configured")
		return
	}

	remaining := s.recoveryStore.RemainingCodes(id.CallerID)
	writeJSON(w, http.StatusOK, map[string]any{
		"caller_id":       id.CallerID,
		"codes_remaining": remaining,
		"warning":         warnIfLow(remaining),
	})
}

func warnIfLow(n int) string {
	switch {
	case n == 0:
		return "CRITICAL: No recovery codes remaining. Run POST /auth/recovery/init immediately to generate new ones."
	case n <= 2:
		return "WARNING: Only a few recovery codes remain. Consider generating new codes soon."
	default:
		return ""
	}
}
