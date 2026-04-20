package api

import "net/http"

// handleRevokeCredential is a stub for FO-B2: credential revocation.
// Returns 501 Not Implemented until the feature is built.
func (s *Server) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
