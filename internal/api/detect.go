package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
)

// OperationDetect is the audit operation for detection enrichment events.
const OperationDetect = "detect"

// detectRequest is the JSON body for POST /credentials/detect.
type detectRequest struct {
	CredentialUUID string `json:"credential_uuid"`
	DetectedAt     string `json:"detected_at"`
	Source         string `json:"source"`
	Reason         string `json:"reason"`
}

// handleDetectCredential handles POST /credentials/detect.
//
// Records a leak detection event on an existing credential's audit trail.
// Accepts a JSON body with credential_uuid, detected_at (RFC 3339),
// source (string), and an optional reason field.
//
// FO-C2: Detection enrichment API.
func (s *Server) handleDetectCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ── Audit scaffold ─────────────────────────────────────────────────────
	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = OperationDetect
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()

	id := identityFromContext(ctx)
	populateIdentityFields(&ev, id)

	// ── 1. Parse request body ──────────────────────────────────────────────
	var req detectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CredentialUUID == "" {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "credential_uuid is required")
		return
	}

	// ── 2. Validate UUID format ────────────────────────────────────────────
	if !uuidRFC4122.MatchString(req.CredentialUUID) {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid credential_uuid format")
		return
	}

	// ── 3. Validate detected_at ────────────────────────────────────────────
	if req.DetectedAt == "" {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "detected_at is required")
		return
	}
	if _, err := time.Parse(time.RFC3339, req.DetectedAt); err != nil {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "detected_at must be a valid RFC 3339 timestamp")
		return
	}

	// ── 4. Validate source ─────────────────────────────────────────────────
	if req.Source == "" {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "source is required")
		return
	}

	// ── 5. Check if credential exists ──────────────────────────────────────
	if _, ok := s.credentialUUIDs.Load(req.CredentialUUID); !ok {
		s.writeError(w, http.StatusNotFound, errCodeKeyNotFound, "credential not found")
		return
	}

	// ── 6. Emit audit event ────────────────────────────────────────────────
	ev.CredentialUUID = req.CredentialUUID
	ev.InvalidationReason = audit.ReasonRevokedLeak
	ev.Outcome = audit.OutcomeSuccess

	if logErr := s.auditLog(ctx, ev); logErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 7. Success response ────────────────────────────────────────────────
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "recorded"})
}
