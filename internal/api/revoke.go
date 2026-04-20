package api

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/agentkms/agentkms/internal/audit"
)

// uuidRFC4122 matches a valid RFC 4122 UUID: 8-4-4-4-12 lowercase hex with dashes.
var uuidRFC4122 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// revokeRequest is the JSON body for POST /credentials/revoke.
type revokeRequest struct {
	CredentialUUID string `json:"credential_uuid"`
}

// handleRevokeCredential handles POST /credentials/revoke.
//
// Request flow:
//  1. Parse and validate request body (credential_uuid required, RFC 4122 format).
//  2. Check if the credential UUID exists in the known credentials store.
//  3. Mark the credential as revoked (idempotent — already-revoked returns 200).
//  4. Emit audit event with Operation = OperationRevoke.
//  5. Return 200 OK on success.
//
// FO-B2.
func (s *Server) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ── Audit scaffold ─────────────────────────────────────────────────────
	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationRevoke
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()

	id := identityFromContext(ctx)
	populateIdentityFields(&ev, id)

	// ── 1. Parse request body ──────────────────────────────────────────────
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CredentialUUID == "" {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "credential_uuid is required")
		return
	}

	// ── 2. Validate UUID format ────────────────────────────────────────────
	if !uuidRFC4122.MatchString(req.CredentialUUID) {
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid credential_uuid format")
		return
	}

	// ── 3. Check if credential exists ──────────────────────────────────────
	if _, ok := s.credentialUUIDs.Load(req.CredentialUUID); !ok {
		s.writeError(w, http.StatusNotFound, errCodeKeyNotFound, "credential not found")
		return
	}

	// ── 4. Mark as revoked (idempotent) ────────────────────────────────────
	s.credentialUUIDs.Store(req.CredentialUUID, true) // true = revoked

	// ── 5. Emit audit event ────────────────────────────────────────────────
	ev.CredentialUUID = req.CredentialUUID
	ev.InvalidationReason = "revoked-user"
	ev.Outcome = audit.OutcomeSuccess

	if logErr := s.auditLog(ctx, ev); logErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 6. Success response ────────────────────────────────────────────────
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}
