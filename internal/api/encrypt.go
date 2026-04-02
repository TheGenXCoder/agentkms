package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/policy"
)

// ── Request / response types ──────────────────────────────────────────────────

type encryptRequest struct {
	// Plaintext is the data to encrypt, base64-encoded (standard encoding).
	Plaintext string `json:"plaintext"`
}

type encryptResponse struct {
	// Ciphertext is the encrypted payload, base64-encoded (standard encoding).
	// Treat as an opaque blob; pass it unmodified to /decrypt.
	Ciphertext string `json:"ciphertext"`

	// KeyVersion is the key version used for encryption.
	// Record alongside the ciphertext for operational tracking.
	KeyVersion int `json:"key_version"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// handleEncrypt implements POST /encrypt/{key-id...}
//
// Authentication: Bearer token (requireToken middleware).
// Policy:         must allow operation "encrypt" for this identity + key.
//
// Request body:
//
//	{"plaintext": "<base64-encoded bytes>"}
//
// Response body:
//
//	{"ciphertext": "<base64>", "key_version": 1}
func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyid")
	tok := tokenFromContext(r.Context())

	ev, err := audit.New()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ev.Operation = audit.OperationEncrypt
	ev.Environment = s.env
	ev.CallerID = tok.CallerID
	ev.TeamID = tok.TeamID
	ev.AgentSession = tok.SessionID
	ev.KeyID = keyID
	ev.SourceIP = sourceIP(r)
	ev.UserAgent = r.Header.Get("User-Agent")
	ev.Outcome = audit.OutcomeError

	defer func() { s.logAudit(r, ev) }()

	// ── 1. Decode request ─────────────────────────────────────────────────────
	var req encryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// ── 2. Decode plaintext ───────────────────────────────────────────────────
	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		writeError(w, http.StatusBadRequest, "plaintext must be valid base64")
		return
	}
	// SECURITY: Do NOT log plaintext or its length in audit events.
	// Instead, compute a hash of the plaintext for audit purposes.
	// This allows reconstructing the audit trail without exposing sensitive data.
	payloadHash := sha256.Sum256(plaintext)
	ev.PayloadHash = hex.EncodeToString(payloadHash[:])

	// ── 3. Policy check ───────────────────────────────────────────────────────
	dec := s.policy.Evaluate(policy.Request{
		CallerID:  tok.CallerID,
		TeamID:    tok.TeamID,
		Operation: policy.OperationEncrypt,
		KeyID:     keyID,
	})
	if !dec.Allowed {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = dec.DenyReason
		writeError(w, http.StatusForbidden, "operation denied by policy")
		return
	}

	// ── 4. Backend operation ──────────────────────────────────────────────────
	result, err := s.backend.Encrypt(r.Context(), keyID, plaintext)
	if err != nil {
		s.logger.Error("encrypt: backend error", "key_id", keyID, "error", err)
		if isKeyNotFound(err) {
			writeError(w, http.StatusNotFound, "key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "encrypt operation failed")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	ev.KeyVersion = result.KeyVersion

	// ── 5. Response ───────────────────────────────────────────────────────────
	// SECURITY: Return ciphertext only.  The plaintext input must not appear
	// in the response, audit event, or server log.
	writeJSON(w, encryptResponse{
		Ciphertext: base64.StdEncoding.EncodeToString(result.Ciphertext),
		KeyVersion: result.KeyVersion,
	})
}
