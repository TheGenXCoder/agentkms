package api

import (
	"net/http"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/pkg/identity"
)

// ── Authentication middleware ─────────────────────────────────────────────────

// authMiddleware validates the caller's session token and injects the verified
// Identity into the request context.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │  TODO(A-04) — Auth stream gate required before production deploy     │
// │                                                                     │
// │  This is a STUB.  It injects a placeholder identity without         │
// │  performing any authentication.  All requests pass through.         │
// │                                                                     │
// │  Replace with real implementation once internal/auth/tokens.go      │
// │  (backlog A-03, A-04) is complete.  The real middleware must:       │
// │                                                                     │
// │  1. Extract the session token from the Authorization header:        │
// │       Authorization: Bearer <token>                                 │
// │  2. Validate the HMAC signature and TTL (15 min max).              │
// │  3. Verify the token identity matches the mTLS cert identity on     │
// │     the current connection (prevents token replay on a different    │
// │     mTLS connection).                                               │
// │  4. Check the token is not in the revocation blocklist.             │
// │  5. On success: call setIdentityInContext with the validated         │
// │     Identity and call next.                                         │
// │  6. On failure: return 401 Unauthorized with                        │
// │       WWW-Authenticate: Bearer realm="agentkms"                    │
// │     Do NOT call next.                                               │
// │                                                                     │
// │  DO NOT deploy to any environment until A-04 is complete.           │
// └─────────────────────────────────────────────────────────────────────┘
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO(A-04): Replace stub with real token validation.
		//
		// Stub behaviour: inject a clearly labelled placeholder identity so
		// that handlers can be developed and tested against the full request
		// pipeline without a working auth layer.
		//
		// Handlers must not assume anything about the stub identity's
		// CallerID or TeamID values; those will change when A-04 is wired.
		placeholder := identity.Identity{
			CallerID:     "stub@placeholder",
			TeamID:       "placeholder-team",
			Role:         "developer",
			AgentSession: "stub-session-00000000",
			SPIFFEID:     "",
		}
		r = r.WithContext(setIdentityInContext(r.Context(), placeholder))
		next(w, r)
	}
}

// ── Recovery middleware ───────────────────────────────────────────────────────

// recoveryMiddleware catches any panic in a downstream handler and returns a
// generic 500 response.
//
// SECURITY: The panic value and Go stack trace are deliberately suppressed
// from the HTTP response.  They may contain key material, raw pointers,
// internal addresses, or other sensitive runtime details.
//
// A best-effort audit event is written for every caught panic.  This ensures
// that panic-triggering inputs (even if unintentional) leave a trace in the
// audit trail.  The panic value is NOT included in the audit event.
func (s *Server) recoveryMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// SECURITY: Do NOT include rec (the panic value) in the
				// response or the audit event.  It may contain key material,
				// raw pointers, or internal runtime state.
				//
				// Best-effort audit: write a minimal panic event so that
				// panic-triggering inputs leave a trace.  If the audit write
				// itself fails, we cannot do anything further.
				if ev, evErr := audit.New(); evErr == nil {
					id := identityFromContext(r.Context())
					ev.Operation = audit.OperationPanicRecovery
					ev.Outcome = audit.OutcomeError
					ev.DenyReason = "handler panicked — panic value suppressed"
					ev.CallerID = id.CallerID
					ev.TeamID = id.TeamID
					ev.AgentSession = id.AgentSession
					ev.SourceIP = extractRemoteIP(r)
					ev.UserAgent = r.UserAgent()
					ev.Environment = s.env
					// Use context.WithoutCancel: the request context may
					// already be cancelled after the panic unwind.
					_ = s.auditLog(r.Context(), ev) // best-effort; ignore error
				}
				s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			}
		}()
		next(w, r)
	}
}
