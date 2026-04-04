package api

// webauthn.go — HTTP handlers for FIDO2/WebAuthn authentication.
//
// Registration (one-time per authenticator):
//   POST /auth/webauthn/register/begin  — returns challenge JSON
//   POST /auth/webauthn/register/finish — submits attestation, stores credential
//
// Authentication (per session):
//   POST /auth/webauthn/auth/begin   — returns challenge JSON
//   POST /auth/webauthn/auth/finish  — submits assertion, returns session token
//
// The begin/finish auth endpoints are unauthenticated (caller has no cert yet).
// The begin/finish register endpoints require an existing mTLS session.

import (
	"encoding/json"
	"net/http"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/pkg/identity"
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

	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid JSON body")
		return
	}

	ev, _ := audit.New()
	ev.CallerID = id.CallerID
	ev.Operation = "webauthn_register"
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)

	if err := s.webAuthn.FinishRegistration(id.CallerID, body); err != nil {
		ev.Outcome = audit.OutcomeError
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

	var req waAuthFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CallerID == "" {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "caller_id and response required")
		return
	}

	if s.webAuthn == nil {
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "WebAuthn not configured")
		return
	}

	ev, _ := audit.New()
	ev.CallerID = req.CallerID
	ev.Operation = "webauthn_auth"
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)

	callerID, err := s.webAuthn.FinishAuthentication(req.CallerID, req.Response)
	if err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "webauthn assertion failed"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusUnauthorized, errCodePolicyDenied, "authentication failed")
		return
	}

	// Issue a session token for the verified identity.
	id := &identity.Identity{
		CallerID:   callerID,
		Role:       identity.RoleDeveloper,
		AuthMethod: identity.AuthMethodWebAuthn,
	}

	tokenStr, tok, err := s.tokenService.Issue(id)
	if err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "failed to issue token")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	_ = s.auditLog(ctx, ev)

	writeJSON(w, http.StatusOK, map[string]any{
		"token":       tokenStr,
		"expires_at":  tok.ExpiresAt.Format("2006-01-02T15:04:05Z"),
		"auth_method": string(identity.AuthMethodWebAuthn),
	})
}

// SetWebAuthn wires in the WebAuthn service after construction.
func (s *Server) SetWebAuthn(wa *auth.WebAuthnService) {
	s.webAuthn = wa
}
