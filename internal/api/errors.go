package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/agentkms/agentkms/internal/backend"
)

// ── Error codes ───────────────────────────────────────────────────────────────

// Machine-readable error codes for the "code" field in error responses.
// These values are part of the public API contract; do not change them.
const (
	errCodeInvalidRequest       = "invalid_request"
	errCodeKeyNotFound          = "key_not_found"
	errCodePolicyDenied         = "policy_denied"
	errCodeAlgorithmMismatch    = "algorithm_mismatch"
	errCodeOperationNotSupported = "operation_not_supported"
	errCodeInternal             = "internal_error"
	errCodeNotImplemented       = "not_implemented"
)

// ── Response types ────────────────────────────────────────────────────────────

// errorResponse is the JSON body for all error responses.
//
// SECURITY: The "error" field must contain only a generic human-readable
// message chosen from a fixed set of strings.  It must NEVER contain:
//   - Raw backend error messages (which may include key IDs, internal paths).
//   - Stack traces or Go runtime details.
//   - Key material of any kind.
//
// The "code" field is machine-readable and stable across versions.
type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// writeError writes a JSON error response with the given HTTP status code.
//
// message must be a pre-approved, generic string (see the call sites for the
// full set).  It must NOT be derived from err.Error() or any backend-internal
// string.
//
// SECURITY: This function is the single gate through which all error responses
// leave the service.  Keep it minimal; any future extension that adds fields
// derived from internal state must be reviewed carefully.
func (s *Server) writeError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	// Ignore json.Encoder errors: if the response writer is broken we cannot
	// report the error to the client anyway.
	_ = json.NewEncoder(w).Encode(errorResponse{Error: message, Code: code})
}

// writeJSON writes a JSON-encoded value with the given HTTP status code.
// The caller is responsible for ensuring that v contains no key material.
func writeJSON(w http.ResponseWriter, statusCode int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// ── Backend error mapping ─────────────────────────────────────────────────────
//
// The three functions below translate backend sentinel errors into the HTTP
// layer equivalents.  They always return pre-defined strings — never
// err.Error() — so internal details cannot leak through error responses.

// statusFromBackendError maps a backend error to an HTTP status code.
func statusFromBackendError(err error) int {
	switch {
	case errors.Is(err, backend.ErrKeyNotFound):
		return http.StatusNotFound
	case errors.Is(err, backend.ErrAlgorithmMismatch):
		return http.StatusBadRequest
	case errors.Is(err, backend.ErrKeyTypeMismatch):
		return http.StatusBadRequest
	case errors.Is(err, backend.ErrInvalidInput):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// codeFromBackendError maps a backend error to a machine-readable error code.
func codeFromBackendError(err error) string {
	switch {
	case errors.Is(err, backend.ErrKeyNotFound):
		return errCodeKeyNotFound
	case errors.Is(err, backend.ErrAlgorithmMismatch):
		return errCodeAlgorithmMismatch
	case errors.Is(err, backend.ErrKeyTypeMismatch):
		return errCodeOperationNotSupported
	case errors.Is(err, backend.ErrInvalidInput):
		return errCodeInvalidRequest
	default:
		return errCodeInternal
	}
}

// messageFromBackendError maps a backend error to a safe, generic human
// message suitable for inclusion in an external error response.
//
// SECURITY: These strings are chosen to be informative without leaking any
// backend-internal detail.  The mapping is exhaustive over sentinel errors;
// any unrecognised error maps to the generic "internal error" message.
func messageFromBackendError(err error) string {
	switch {
	case errors.Is(err, backend.ErrKeyNotFound):
		return "key not found"
	case errors.Is(err, backend.ErrAlgorithmMismatch):
		return "algorithm does not match the key type"
	case errors.Is(err, backend.ErrKeyTypeMismatch):
		return "operation not supported for this key type"
	case errors.Is(err, backend.ErrInvalidInput):
		return "invalid input"
	default:
		return "internal error"
	}
}

// extractRemoteIP returns the client IP address from r.RemoteAddr, without
// the port component.  Used for audit event SourceIP fields.
//
// Uses net.SplitHostPort which handles IPv4 ("1.2.3.4:80"), IPv6
// ("[::1]:80"), and Unix sockets correctly.  Falls back to the raw
// RemoteAddr string if parsing fails (e.g. Unix socket paths).
func extractRemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Not a host:port pair (e.g. Unix socket path) — return as-is.
		return r.RemoteAddr
	}
	return host
}
