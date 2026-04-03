package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/agentkms/agentkms/internal/audit"
)

// ── Request / response types ──────────────────────────────────────────────────

// encryptRequest is the JSON body for POST /encrypt/{keyid...}.
type encryptRequest struct {
	// Plaintext is the base64 (standard encoding) representation of the
	// bytes to encrypt.  The caller must not send plaintext that should
	// not be held by AgentKMS even transiently; for large data, encrypt
	// a data-encryption key instead.
	Plaintext string `json:"plaintext"`
}

// encryptResponse is the JSON body for a successful POST /encrypt/{keyid...}.
//
// SECURITY: contains ONLY the base64-encoded ciphertext and the key version.
// The plaintext, the AES key, and any intermediate values are absent.
type encryptResponse struct {
	// Ciphertext is the base64 (standard encoding) representation of the
	// opaque ciphertext blob returned by the backend.  Pass it unmodified to
	// POST /decrypt/{keyid...} to recover the original plaintext.
	Ciphertext string `json:"ciphertext"`

	// KeyVersion is the version of the key used for encryption.  The key
	// version is also embedded in the ciphertext blob for self-contained
	// decryption; this field is informational and aids audit correlation.
	KeyVersion int `json:"key_version"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// handleEncrypt handles POST /encrypt/{keyid...}.
//
// Request flow:
//  1. Input validation (key ID format, plaintext is valid base64).
//  2. Policy evaluation.
//  3. Backend.Encrypt.
//  4. Audit log write (payload_hash = SHA-256 of plaintext — never plaintext).
//  5. Response — ciphertext (base64) and key_version only.
//
// Implements backlog C-02.
//
// Full integration blockers:
//   - TODO(A-04): Token validation middleware (auth stream).
//   - TODO(B-01): OpenBao backend injection (backend stream).
//   - TODO(P-03): Real policy engine evaluation (policy stream).
func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyID := r.PathValue("keyid")

	// ── Audit event scaffold ───────────────────────────────────────────────
	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationEncrypt
	ev.KeyID = keyID
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()

	id := identityFromContext(ctx)
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession

	// ── 1. Input validation ────────────────────────────────────────────────
	if !isValidKeyID(keyID) {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid key ID format"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid key ID")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req encryptRequest
	if err := dec.Decode(&req); err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "malformed request body"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "malformed request body")
		return
	}

	if req.Plaintext == "" {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "missing plaintext field"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "plaintext is required")
		return
	}

	plaintextBytes, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "plaintext is not valid base64"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest,
			"plaintext must be base64-encoded (standard encoding)")
		return
	}

	// Record the SHA-256 hash of the plaintext in the audit event — NEVER
	// the plaintext itself.  This lets auditors correlate operations on the
	// same data without the audit log becoming a plaintext store.
	h := sha256.Sum256(plaintextBytes)
	ev.PayloadHash = fmt.Sprintf("sha256:%x", h)

	// ── 2. Policy check ────────────────────────────────────────────────────
	// TODO(P-03): Wire real policy engine.
	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationEncrypt, keyID)
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateAnomalies(&ev, decision.Anomalies)
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	// ── 3. Backend call ────────────────────────────────────────────────────
	// TODO(B-01): OpenBao backend.
	result, bErr := s.backend.Encrypt(ctx, keyID, plaintextBytes)
	if bErr != nil {
		ev.Outcome = audit.OutcomeError
		populateAnomalies(&ev, decision.Anomalies)
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w,
			statusFromBackendError(bErr),
			codeFromBackendError(bErr),
			messageFromBackendError(bErr),
		)
		return
	}
	ev.KeyVersion = result.KeyVersion

	// ── 4. Audit ───────────────────────────────────────────────────────────
	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 5. Response ────────────────────────────────────────────────────────
	// SECURITY: response contains ONLY ciphertext (base64) and key version.
	// The plaintext bytes are absent from the response.
	writeJSON(w, http.StatusOK, encryptResponse{
		Ciphertext: base64.StdEncoding.EncodeToString(result.Ciphertext),
		KeyVersion: result.KeyVersion,
	})
}
