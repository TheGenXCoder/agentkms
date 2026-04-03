package api

import (
	"encoding/json"
	"net/http"
)

// writeJSONError writes a simple {"error": "<msg>"} JSON response.
// Used by the auth handler and auth middleware.
//
// SECURITY: msg must not contain key material, tokens, or internal details.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write(body)
}

// sourceIP is an alias for extractRemoteIP. Used by auth.go.
func sourceIP(r *http.Request) string { return extractRemoteIP(r) }

// userAgent returns the User-Agent header trimmed to a safe maximum length.
func userAgent(r *http.Request) string {
	ua := r.UserAgent()
	const maxLen = 256
	if len(ua) > maxLen {
		return ua[:maxLen]
	}
	return ua
}
