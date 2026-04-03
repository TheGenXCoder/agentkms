package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
)

// ── Request / response types ──────────────────────────────────────────────────

// signRequest is the JSON body for POST /sign/{keyid...}.
type signRequest struct {
	// PayloadHash is the SHA-256 hash of the payload to sign, formatted as
	// "sha256:<64 hex characters>".  The raw payload must never be sent to
	// AgentKMS.
	PayloadHash string `json:"payload_hash"`

	// Algorithm is the signing algorithm to use.  Must match the algorithm
	// the key was created with.  Accepted values: "ES256", "RS256", "EdDSA".
	Algorithm string `json:"algorithm"`
}

// signResponse is the JSON body for a successful POST /sign/{keyid...}.
//
// SECURITY: contains ONLY the base64-encoded signature and the key version.
// The private key, raw payload hash bytes, and algorithm details beyond the
// requested value are deliberately absent.
type signResponse struct {
	// Signature is the base64 (standard encoding) representation of the
	// raw signature bytes returned by the backend.
	Signature string `json:"signature"`

	// KeyVersion is the version of the key used to produce the signature.
	// Callers must record this alongside the signature to support future key
	// rotation without breaking verification of historical signatures.
	KeyVersion int `json:"key_version"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// handleSign handles POST /sign/{keyid...}.
//
// Request flow:
//  1. Input validation (key ID format, payload_hash format, algorithm).
//  2. Policy evaluation — deny-by-default until P-03 is wired.
//  3. Backend.Sign — delegates to the injected Backend implementation.
//  4. Audit log write — every outcome is recorded before the response.
//  5. Response — signature (base64) and key_version only.
//
// Implements backlog C-01.
//
// Full integration blockers:
//   - TODO(A-04): Token validation middleware (auth stream).
//   - TODO(B-01): OpenBao backend injection (backend stream).
//   - TODO(P-03): Real policy engine evaluation (policy stream).
func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyID := r.PathValue("keyid")

	// ── Audit event scaffold ───────────────────────────────────────────────
	// Build the event up-front so every exit path can populate and emit it.
	// Fields are added incrementally as they become available.
	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationSign
	ev.KeyID = keyID
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()

	// Identity is injected by the auth middleware (TODO A-04 stub for now).
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
	var req signRequest
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

	hashBytes, err := parsePayloadHash(req.PayloadHash)
	if err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid payload_hash"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest,
			`invalid payload_hash: must be "sha256:<64 hex chars>"`)
		return
	}
	// Store the formatted hash string in the audit event — never the raw bytes.
	ev.PayloadHash = req.PayloadHash

	if !isValidSigningAlgorithm(req.Algorithm) {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid or unsupported algorithm"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest,
			"invalid algorithm: must be one of ES256, RS256, EdDSA")
		return
	}
	ev.Algorithm = req.Algorithm
	alg := backend.Algorithm(req.Algorithm)

	// ── 2. Policy check ────────────────────────────────────────────────────
	// TODO(P-03): Wire real policy engine once internal/policy/engine.go is
	// fully implemented (backlog P-01 to P-04).  The injected engine is
	// DenyAllEngine by default; operators must configure a permissive policy
	// for operations to succeed.
	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationSign, keyID)
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
		// DenyReason goes to the audit log ONLY — never to the HTTP response.
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
	// TODO(B-01): Ensure the injected backend is the OpenBao implementation
	// once internal/backend/openbao.go is ready (backlog B-01).
	result, bErr := s.backend.Sign(ctx, keyID, hashBytes, alg)
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
	// The sign operation completed successfully.  Audit before responding so
	// that a failed audit write surfaces as an error to the client (who can
	// retry) rather than silently producing an unaudited signature.
	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		// The backend signed successfully but we cannot record the event.
		// Return 500: client retries; the unaudited sign result is discarded.
		// TODO(T2): Make audit failure a configurable circuit-breaker.
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 5. Response ────────────────────────────────────────────────────────
	// SECURITY: response contains ONLY the base64-encoded signature and key
	// version.  The private key, raw hash bytes, and algorithm details are
	// absent.  The backend.SignResult struct has no key-material fields by
	// design (enforced by F-08 tests).
	writeJSON(w, http.StatusOK, signResponse{
		Signature:  base64.StdEncoding.EncodeToString(result.Signature),
		KeyVersion: result.KeyVersion,
	})
}
