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

// decryptRequest is the JSON body for POST /decrypt/{keyid...}.
type decryptRequest struct {
	// Ciphertext is the base64 (standard encoding) representation of the
	// opaque ciphertext blob produced by POST /encrypt/{keyid...}.
	// Pass the Ciphertext field from the encrypt response unmodified.
	Ciphertext string `json:"ciphertext"`
}

// decryptResponse is the JSON body for a successful POST /decrypt/{keyid...}.
//
// SECURITY: contains ONLY the base64-encoded recovered plaintext.
// Key material, internal algorithm details, and key versions used during
// decryption are absent.
type decryptResponse struct {
	// Plaintext is the base64 (standard encoding) representation of the
	// decrypted bytes.
	Plaintext string `json:"plaintext"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// handleDecrypt handles POST /decrypt/{keyid...}.
//
// Request flow:
//  1. Input validation (key ID format, ciphertext is valid base64).
//  2. Policy evaluation.
//  3. Backend.Decrypt.
//  4. Audit log write (payload_hash = SHA-256 of ciphertext — neither
//     plaintext nor key material appears in the audit event).
//  5. Response — plaintext (base64) only.
//
// Implements backlog C-03.
//
// Full integration blockers:
//   - TODO(A-04): Token validation middleware (auth stream).
//   - TODO(B-01): OpenBao backend injection (backend stream).
//   - TODO(P-03): Real policy engine evaluation (policy stream).
func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyID := r.PathValue("keyid")

	// ── Audit event scaffold ───────────────────────────────────────────────
	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationDecrypt
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
	var req decryptRequest
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

	if req.Ciphertext == "" {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "missing ciphertext field"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "ciphertext is required")
		return
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "ciphertext is not valid base64"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest,
			"ciphertext must be base64-encoded (standard encoding)")
		return
	}

	// Audit the SHA-256 hash of the ciphertext — not the ciphertext itself
	// (which could be large) and not the resulting plaintext (which is
	// sensitive).  The hash allows correlation with the corresponding encrypt
	// event if needed.
	h := sha256.Sum256(ciphertextBytes)
	ev.PayloadHash = fmt.Sprintf("sha256:%x", h)

	// ── 2. Policy check ────────────────────────────────────────────────────
	// TODO(P-03): Wire real policy engine.
	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationDecrypt, keyID)
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
	result, bErr := s.backend.Decrypt(ctx, keyID, ciphertextBytes)
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

	// ── 4. Audit ───────────────────────────────────────────────────────────
	// SECURITY: The decrypted plaintext is NEVER written to the audit event.
	// The audit event records that a decrypt occurred (operation, key_id,
	// caller, outcome) — sufficient for compliance without storing the data.
	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 5. Response ────────────────────────────────────────────────────────
	// SECURITY: response contains ONLY the base64-encoded plaintext.
	// Key material and internal decryption details are absent.
	writeJSON(w, http.StatusOK, decryptResponse{
		Plaintext: base64.StdEncoding.EncodeToString(result.Plaintext),
	})
}
