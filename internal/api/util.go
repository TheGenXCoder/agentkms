package api

import (
	"encoding/json"
	"net"
	"net/http"
)

// writeJSONError writes an HTTP error response with a JSON body.
//
// The response body is always {"error": "<msg>"} and the Content-Type is
// always application/json.
//
// SECURITY: msg must not contain key material, token content, stack traces,
// or internal error details that could help an attacker.  Pass a generic
// human-readable message; log the real error via the Auditor.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write(body)
}

// writeJSON encodes v as JSON and writes it to w with the given HTTP status.
// Sets Content-Type: application/json.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// sourceIP extracts the client's IP address from the request, stripping the
// port number.  If the RemoteAddr cannot be parsed, returns the raw string.
//
// NOTE: In production behind a load balancer or proxy, the real IP may be
// in X-Forwarded-For.  That header is intentionally NOT read here; in mTLS
// setups the RemoteAddr is always the direct peer.  If a proxy is added
// in front of AgentKMS, revisit this function and add appropriate trust logic.
func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// userAgent returns the User-Agent header value, trimmed to a safe maximum
// length to prevent log inflation.
func userAgent(r *http.Request) string {
	ua := r.UserAgent()
	const maxLen = 256
	if len(ua) > maxLen {
		return ua[:maxLen]
	}
	return ua
}
