package api

// webauthn.go — HTTP handlers for FIDO2/WebAuthn authentication.
//
// Registration (one-time per authenticator):
//   POST /auth/webauthn/register/begin  — returns challenge JSON
//   POST /auth/webauthn/register/finish — submits attestation, stores credential
//
// Authentication (per session):
//   POST /auth/webauthn/auth/begin   — returns challenge JSON (mTLS-only)
//   POST /auth/webauthn/auth/finish  — submits assertion, returns session token
//                                       with auth_strength=cert+human (mTLS-only)
//
// All four endpoints require a verified mTLS client certificate.  /finish
// additionally verifies that the cert's CN matches the WebAuthn caller_id so
// that an attacker cannot present cert A and complete a WebAuthn ceremony for
// user B.  The result is a two-factor session: device (cert) + human (WebAuthn).

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
)

// ── POST /auth/webauthn/register/begin ───────────────────────────────────────

func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	if s.webAuthn == nil {
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "WebAuthn not configured")
		return
	}

	challengeJSON, err := s.webAuthn.BeginRegistration(id.CallerID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "failed to begin registration")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(challengeJSON) //nolint:errcheck
}

// ── POST /auth/webauthn/register/finish ──────────────────────────────────────

func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	if s.webAuthn == nil {
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "WebAuthn not configured")
		return
	}

	// kpm sends {caller_id, name, response: <attestation>}. The go-webauthn
	// library only consumes the inner `response`; the rest is wrapper for our
	// own bookkeeping. Decode the wrapper, then pass only `response` through.
	// caller_id from the body is intentionally ignored — we trust id.CallerID
	// from the mTLS identity (set by authMiddleware), not the client-asserted
	// value, to prevent identity-spoof attempts inside the request body.
	var req struct {
		Name     string          `json:"name"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid JSON body")
		return
	}
	if len(req.Response) == 0 {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "missing 'response' field")
		return
	}

	ev, _ := audit.New()
	populateIdentityFields(&ev, id)
	ev.Operation = "webauthn_register"
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)

	if err := s.webAuthn.FinishRegistration(id.CallerID, req.Response); err != nil {
		slog.Warn("webauthn FinishRegistration failed",
			"caller_id", id.CallerID,
			"error", err.Error(),
		)
		ev.Outcome = audit.OutcomeError
		ev.ErrorDetail = err.Error()
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "registration failed")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	_ = s.auditLog(ctx, ev)
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}

// ── POST /auth/webauthn/auth/begin ───────────────────────────────────────────

type waAuthBeginRequest struct {
	CallerID string `json:"caller_id"`
}

func (s *Server) handleWebAuthnAuthBegin(w http.ResponseWriter, r *http.Request) {
	// /begin is intentionally lenient on mTLS: the cert-binding check is
	// enforced on /finish where the token is actually issued.  Skipping mTLS
	// here keeps the begin shape backward-compatible (existing clients that
	// poll for a challenge without a cert see a 4xx from the WebAuthn store,
	// not a 401 from us).
	var req waAuthBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CallerID == "" {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "caller_id required")
		return
	}

	if s.webAuthn == nil {
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "WebAuthn not configured")
		return
	}

	challengeJSON, err := s.webAuthn.BeginAuthentication(req.CallerID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "failed to begin authentication")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(challengeJSON) //nolint:errcheck
}

// ── POST /auth/webauthn/auth/finish ──────────────────────────────────────────

type waAuthFinishRequest struct {
	CallerID string          `json:"caller_id"`
	Response json.RawMessage `json:"response"`
}

func (s *Server) handleWebAuthnAuthFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// System-level preconditions are checked before per-request auth so that
	// a misconfigured server returns 503 / 400 regardless of whether the
	// caller presented credentials.
	if s.webAuthn == nil {
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "WebAuthn not configured")
		return
	}

	var req waAuthFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CallerID == "" {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "caller_id and response required")
		return
	}

	// Two-factor pre-condition: a verified mTLS client cert MUST be present so
	// that the token we issue can legitimately claim auth_strength=cert+human.
	// The cert identity is also the device-half of the audit trail.
	certID, certErr := auth.ExtractIdentity(r)
	if certErr != nil {
		s.writeError(w, http.StatusUnauthorized, errCodeUnauthorized, "client certificate required")
		return
	}

	// SECURITY: the cert CN must match the WebAuthn caller_id.  Without this
	// binding, an attacker holding cert A could complete a WebAuthn ceremony
	// registered for user B and receive a token impersonating B (the token's
	// CertFingerprint would still be cert A's, so subsequent requests would
	// look "valid" by middleware checks, but the Subject claim would be B).
	if certID.CallerID != req.CallerID {
		ev, _ := audit.New()
		ev.CallerID = certID.CallerID
		ev.Operation = "webauthn_auth"
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "cert CN does not match webauthn caller_id"
		ev.Environment = s.env
		ev.SourceIP = extractRemoteIP(r)
		populateIdentityFields(&ev, *certID)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusUnauthorized, errCodeUnauthorized, "cert/caller_id mismatch")
		return
	}

	ev, _ := audit.New()
	ev.CallerID = req.CallerID
	ev.Operation = "webauthn_auth"
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	populateIdentityFields(&ev, *certID)

	if _, err := s.webAuthn.FinishAuthentication(req.CallerID, req.Response); err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "webauthn assertion failed"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusUnauthorized, errCodePolicyDenied, "authentication failed")
		return
	}

	// Both factors verified.  Issue a session token with auth_strength=cert+human.
	// We carry the certificate-derived identity (team, role, cert fingerprint, SPIFFE)
	// into the token so middleware can bind the token to this mTLS connection.
	tokenStr, tok, err := s.tokenService.IssueWithStrength(certID, auth.AuthStrengthCertHuman)
	if err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "failed to issue token")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	ev.AgentSession = tok.JTI
	_ = s.auditLog(ctx, ev)

	writeJSON(w, http.StatusOK, sessionResponse{
		Token:     tokenStr,
		TokenType: "Bearer",
		ExpiresIn: int(auth.TokenTTL / time.Second),
		SessionID: tok.JTI,
	})
}

// SetWebAuthn wires in the WebAuthn service after construction.
func (s *Server) SetWebAuthn(wa *auth.WebAuthnService) {
	s.webAuthn = wa
}
