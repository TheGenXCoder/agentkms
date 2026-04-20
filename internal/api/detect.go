package api

import "net/http"

// OperationDetect is the audit operation for detection enrichment events.
const OperationDetect = "detect"

// handleDetectCredential handles POST /credentials/detect.
//
// Records a leak detection event on an existing credential's audit trail.
// Accepts a JSON body with credential_uuid, detected_at (RFC 3339),
// source (string), and an optional reason field.
//
// FO-C2: Detection enrichment API — stub returning 501.
func (s *Server) handleDetectCredential(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte(`{"error":"not implemented"}`))
}
