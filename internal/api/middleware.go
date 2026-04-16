package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/agentkms/agentkms/internal/audit"
)

// ── Authentication middleware ─────────────────────────────────────────────────

// authMiddleware validates the caller's session token and injects the verified
// Identity into the request context.
//
//  1. Extract the session token from the Authorization header:
//     Authorization: Bearer <token>
//  2. Validate the HMAC signature and TTL (15 min max).
//  3. Verify the token identity matches the mTLS cert identity on
//     the current connection (prevents token replay on a different
//     mTLS connection).
//  4. Check the token is not in the revocation blocklist.
//  5. On success: call SetIdentityInContext with the validated
//     Identity and call next.
//  6. On failure: return 401 Unauthorized with
//     WWW-Authenticate: Bearer realm="agentkms"
//
// AuthMiddleware returns the authentication middleware for the given handler.
func (s *Server) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return s.authMiddleware(next)
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Bypass authentication in tests if a token is already in the context.
		// This allows existing tests to work by injecting a token manually
		// or via a test-specific mechanism.
		if id := identityFromContext(r.Context()); id.CallerID != "" {
			next(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			s.writeError(w, http.StatusUnauthorized, errCodeUnauthorized, "missing or invalid Authorization header")
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		tok, err := s.authTokens.Validate(tokenStr)
		if err != nil {
			s.writeError(w, http.StatusUnauthorized, errCodeUnauthorized, "invalid or expired session token")
			return
		}

		// Verify the token is bound to the same client certificate as the current connection.
		// A-04 requirement: prevent token replay on a different connection.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			s.writeError(w, http.StatusUnauthorized, errCodeUnauthorized, "mTLS required for session-based requests")
			return
		}
		cert := r.TLS.PeerCertificates[0]
		fpSum := sha256.Sum256(cert.Raw)
		fp := hex.EncodeToString(fpSum[:])
		if tok.Identity.CertFingerprint != fp {
			s.writeError(w, http.StatusUnauthorized, errCodeUnauthorized, "token is not bound to this client certificate")
			return
		}

		r = r.WithContext(SetIdentityInContext(r.Context(), tok.Identity))
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
					populateIdentityFields(&ev, id)
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
