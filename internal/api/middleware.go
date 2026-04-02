package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/pkg/identity"
)

// contextKey is an unexported type for context keys in this package.
// Using a typed key prevents collisions with context values set by other
// packages.
type contextKey int

const (
	contextKeyToken    contextKey = iota // *auth.Token
	contextKeyIdentity contextKey = iota // *identity.Identity
)

// tokenFromContext returns the validated Token stored in ctx by requireToken.
// Returns nil if no token is present (should not occur in authenticated handlers).
func tokenFromContext(ctx context.Context) *auth.Token {
	tok, _ := ctx.Value(contextKeyToken).(*auth.Token)
	return tok
}

// identityFromContext returns the Identity stored in ctx by requireToken.
// Returns nil if no identity is present.
func identityFromContext(ctx context.Context) *identity.Identity {
	id, _ := ctx.Value(contextKeyIdentity).(*identity.Identity)
	return id
}

// requireMTLS is middleware that validates the mTLS connection without
// requiring a token. It ensures the client has presented a valid certificate
// that chains to the server's trusted CA, but doesn't check for a token.
//
// This is useful for endpoints like health checks that should require mTLS
// but don't need a token (supporting infrastructure monitoring).
//
// Returns 401 Unauthorized if the request doesn't have a valid mTLS connection.
func (s *Server) requireMTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get mTLS caller identity from the connection
		mtlsCallerID := auth.MTLSCallerID(r.TLS)
		if mtlsCallerID == "" {
			// No valid mTLS client certificate — log the denial and reject.
			// audit.New() handles EventID and Timestamp generation.
			ev, _ := audit.New()
			ev.Operation = "health.access"
			ev.Outcome = audit.OutcomeDenied
			ev.CallerID = "NO_MTLS_CERT"
			ev.SourceIP = r.RemoteAddr
			s.logAudit(r, ev)
			writeError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		// Valid mTLS connection, proceed to handler
		next.ServeHTTP(w, r)
	})
}

// requireToken is middleware that validates the Bearer session token on every
// request.
//
// It:
//  1. Extracts the Bearer token from the Authorization header.
//  2. Derives the mTLS caller ID from the TLS connection state (if present).
//  3. Calls TokenStore.Validate(token, mtlsCallerID) — which enforces
//     connection binding: the token subject must match the mTLS cert CN.
//  4. Stores the validated *auth.Token and *identity.Identity in the request
//     context for downstream handlers to read.
//
// Returns 401 Unauthorized for any of: missing header, wrong format,
// invalid/expired/revoked token, mTLS caller mismatch.
//
// SECURITY: The error response deliberately does not distinguish between
// "token not found", "expired", and "revoked" to avoid oracle attacks.
func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if authHdr == "" {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHdr, bearerPrefix) {
			writeError(w, http.StatusUnauthorized, "Authorization header must use Bearer scheme")
			return
		}
		tokenStr := authHdr[len(bearerPrefix):]

		// Extract the mTLS caller ID for connection binding.
		// When r.TLS is nil (e.g., in unit tests that bypass TLS), the binding
		// check is skipped inside TokenStore.Validate.  This must never happen
		// in production; the server TLS config enforces client certificate
		// authentication at the transport layer.
		//
		// SECURITY: Use MTLSCallerID (which reads VerifiedChains) rather than
		// PeerCertificates directly.  VerifiedChains guarantees the cert was
		// chain-verified against the CA pool.
		mtlsCallerID := auth.MTLSCallerID(r.TLS)

		// Pass r.TLS directly to Validate — never use a package-level global
		// to communicate TLS state.  A global would race between goroutines
		// handling concurrent requests on a live server.
		tok, err := s.tokens.Validate(tokenStr, mtlsCallerID, r.TLS)
		if err != nil {
			// Do not expose err.Error() to the caller — it may reveal internal
			// token state.  Log it server-side for debugging.
			s.logger.Debug("token validation failed",
				"source_ip", sourceIP(r),
				"error", err.Error())
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		ctx := context.WithValue(r.Context(), contextKeyToken, tok)
		ctx = context.WithValue(ctx, contextKeyIdentity, tok.Identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
