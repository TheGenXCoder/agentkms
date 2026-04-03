package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ── Context key ───────────────────────────────────────────────────────────────

// contextKey is an unexported type for context keys in the auth package.
// Using a typed key prevents collision with keys from other packages.
type contextKey int

const tokenContextKey contextKey = iota

// InjectTokenForTest stores tok in ctx under the package-internal token
// context key.  This is provided as a production-package export so that tests
// in OTHER packages (e.g. internal/api) can simulate a request that has
// already passed through RequireToken middleware without going through the full
// middleware stack.
//
// NOTE: export_test.go (package auth) cannot satisfy cross-package test
// imports; this function must live in a non-test file to be accessible to
// external packages during testing.
//
// This function is meaningful only in test scenarios.  Production code should
// always go through RequireToken; it should never call this directly.
func InjectTokenForTest(ctx context.Context, tok *Token) context.Context {
	return context.WithValue(ctx, tokenContextKey, tok)
}

// TokenFromContext retrieves the validated Token from a request context.
// Returns nil if no token is present (i.e. the request bypassed RequireToken).
// API handlers should call this after RequireToken middleware has run.
func TokenFromContext(ctx context.Context) *Token {
	t, _ := ctx.Value(tokenContextKey).(*Token)
	return t
}

// ── RequireToken middleware ───────────────────────────────────────────────────

// RequireToken is an HTTP middleware that enforces session token authentication.
//
// Applied to all endpoints EXCEPT POST /auth/session (which authenticates via
// mTLS only to bootstrap the first token).
//
// Validation performed:
//  1. Authorization: Bearer <token> header is present and well-formed.
//  2. Token signature is valid (HMAC-SHA256).
//  3. Token has not expired.
//  4. Token has not been revoked.
//  5. The mTLS client certificate on the current connection matches the
//     certificate fingerprint embedded in the token (replay protection).
//
// On success: the parsed *Token is stored in the request context under
// tokenContextKey; the next handler is invoked.
//
// On failure: HTTP 401 is returned with a generic JSON error body.
// SECURITY: no detail about WHY the token failed is returned to the caller.
// This prevents timing attacks and oracle attacks.
//
// A-04.
func RequireToken(svc *TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := ExtractBearerToken(r)
			if tokenStr == "" {
				writeJSONError(w, http.StatusUnauthorized, "authorization required")
				return
			}

			tok, err := svc.Validate(tokenStr)
			if err != nil {
				// SECURITY: do not propagate the specific error reason to the
				// caller.  The audit layer (applied by API handlers) records
				// the real reason.
				writeJSONError(w, http.StatusUnauthorized, "token invalid or expired")
				return
			}

			// ── Cert binding check ────────────────────────────────────────────
			// The token encodes the SHA-256 fingerprint of the certificate that
			// was presented at session creation.  We verify that the same cert
			// is present on this connection.  This prevents an attacker who has
			// stolen a token from using it on a connection authenticated with a
			// different certificate.
			//
			// If the connection has no TLS state or no verified chains, the
			// request has bypassed mTLS — reject it.
			if err := verifyCertBinding(r, tok.Identity.CertFingerprint); err != nil {
				// SECURITY: return the same 401 message as other auth failures.
				writeJSONError(w, http.StatusUnauthorized, "token invalid or expired")
				return
			}

			ctx := context.WithValue(r.Context(), tokenContextKey, tok)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// verifyCertBinding checks that the client certificate on the current TLS
// connection matches the fingerprint embedded in the token.
//
// Returns a non-nil error if:
//   - The request has no TLS state (mTLS bypass)
//   - The TLS state has no verified client certificate
//   - The certificate fingerprint does not match the token's cfp claim
func verifyCertBinding(r *http.Request, tokenCertFP string) error {
	if r.TLS == nil {
		return fmt.Errorf("auth: request has no TLS state — mTLS required")
	}
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return fmt.Errorf("auth: no verified client certificate on connection")
	}

	cert := r.TLS.VerifiedChains[0][0]
	fp := sha256.Sum256(cert.Raw)
	currentFP := hex.EncodeToString(fp[:])

	if currentFP != tokenCertFP {
		// Token was issued for a different certificate — potential replay attack.
		return fmt.Errorf("auth: token cert fingerprint mismatch (possible replay)")
	}
	return nil
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

// ExtractBearerToken extracts the token string from the Authorization header.
// Returns an empty string if the header is absent or not in "Bearer <token>"
// format.
func ExtractBearerToken(r *http.Request) string {
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		return ""
	}
	tok := strings.TrimPrefix(hdr, "Bearer ")
	return strings.TrimSpace(tok)
}

// writeJSONError writes an HTTP error response with a JSON body.
// Used by middleware; API handlers have their own equivalent in internal/api.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// We write the message as JSON; the body is intentionally minimal.
	body, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write(body)
}
