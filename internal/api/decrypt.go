package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
)

// ── Request / response types ──────────────────────────────────────────────────

type decryptRequest struct {
	// Ciphertext is the opaque blob returned by /encrypt, base64-encoded.
	Ciphertext string `json:"ciphertext"`
}

type decryptResponse struct {
	// Plaintext is the decrypted data, base64-encoded (standard encoding).
	// SECURITY: The caller must handle this value with appropriate care.
	// It must not be logged, stored in version control, or included in
	// error messages.
	Plaintext string `json:"plaintext"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// handleDecrypt implements POST /decrypt/{key-id...}
//
// Authentication: Bearer token (requireToken middleware).
// Policy:         must allow operation "decrypt" for this identity + key.
// Audit:          logged with sha256(ciphertext) as payload_hash — plaintext
//
//					is NEVER written to the audit log.
//
// Request body:
//
//	{"ciphertext": "<base64-encoded bytes>"}
//
// Response body:
//
//	{"plaintext": "<base64-encoded bytes>"}
//
// Error responses:
//   - 400 Bad Request:  malformed body or non-base64 ciphertext.
//   - 403 Forbidden:    policy denied the operation.
//   - 404 Not Found:    key does not exist in the backend.
//   - 500 Internal:     backend error or unexpected failure.
//
// SECURITY: The plaintext in the response is sensitive. Callers must not log
// it, persist it unencrypted, or include it in error messages or agent tool
// call results beyond what is strictly necessary.
func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyid")
	tok := tokenFromContext(r.Context())

	ev, err := audit.New()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ev.Operation = audit.OperationDecrypt
	ev.Environment = s.env
	ev.CallerID = tok.CallerID
	ev.TeamID = tok.TeamID
	ev.AgentSession = tok.SessionID
	ev.KeyID = keyID
	ev.SourceIP = sourceIP(r)
	ev.UserAgent = r.Header.Get("User-Agent")
	ev.Outcome = audit.OutcomeError // overwritten on success or denial

	defer func() { s.logAudit(r, ev) }()

	// ── 1. Decode request body ────────────────────────────────────────────────
	var req decryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// ── 2. Decode ciphertext ──────────────────────────────────────────────────
	if req.Ciphertext == "" {
		writeError(w, http.StatusBadRequest, "ciphertext must not be empty")
		return
	}
	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ciphertext must be valid base64")
		return
	}
	// SECURITY: Record a hash of the ciphertext in the audit event.
	// The plaintext — which is the sensitive value — must NEVER appear in the
	// audit log, regardless of the operation's outcome.
	ctHash := sha256.Sum256(ciphertext)
	ev.PayloadHash = "sha256:" + hex.EncodeToString(ctHash[:])

	// ── 3. Policy check ───────────────────────────────────────────────────────
	dec := s.policy.Evaluate(policy.Request{
		CallerID:  tok.CallerID,
		TeamID:    tok.TeamID,
		Operation: policy.OperationDecrypt,
		KeyID:     keyID,
	})
	if !dec.Allowed {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = dec.DenyReason
		writeError(w, http.StatusForbidden, "operation denied by policy")
		return
	}

	// ── 4. Backend operation ──────────────────────────────────────────────────
	result, err := s.backend.Decrypt(r.Context(), keyID, ciphertext)
	if err != nil {
		// Do NOT log err.Error() at the warn/error level without first ensuring
		// it contains no plaintext or key material (backend errors are expected
		// to be metadata-only by the Backend contract).
		s.logger.Error("decrypt: backend error", "key_id", keyID, "error", err)
		if isKeyNotFound(err) {
			writeError(w, http.StatusNotFound, "key not found")
			return
		}
		// ErrInvalidInput means the ciphertext was malformed — caller error, not server error.
		if errors.Is(err, backend.ErrInvalidInput) {
			writeError(w, http.StatusBadRequest, "malformed ciphertext")
			return
		}
		writeError(w, http.StatusInternalServerError, "decrypt operation failed")
		return
	}

	ev.Outcome = audit.OutcomeSuccess

	// ── 5. Response ───────────────────────────────────────────────────────────
	// SECURITY: Return plaintext base64-encoded.  Key material must not appear
	// in the response.  The plaintext is sensitive; the caller is responsible
	// for handling it appropriately and not persisting it unencrypted.
	writeJSON(w, decryptResponse{
		Plaintext: base64.StdEncoding.EncodeToString(result.Plaintext),
	})
}
