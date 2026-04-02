package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
)

// ── Request / response types ──────────────────────────────────────────────────

type signRequest struct {
	// PayloadHash is the SHA-256 hash of the actual payload, formatted as
	// "sha256:<hex-encoded 32 bytes>".  The backend never receives the raw payload.
	PayloadHash string `json:"payload_hash"`

	// Algorithm identifies the signing algorithm.  Must match the key's
	// configured algorithm.  Valid values: "ES256", "RS256", "EdDSA".
	Algorithm string `json:"algorithm"`
}

type signResponse struct {
	// Signature is the raw signature bytes, base64-encoded (standard encoding).
	Signature string `json:"signature"`

	// KeyVersion is the version of the key that produced this signature.
	// Callers must record this alongside the signature to support future
	// key rotation without breaking verification of historical signatures.
	KeyVersion int `json:"key_version"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// handleSign implements POST /sign/{key-id...}
//
// Authentication: Bearer token (requireToken middleware).
// Policy:         must allow operation "sign" for this identity + key.
// Audit:          logged with payload_hash (never the payload), algorithm,
//
//	key_id, key_version, outcome.
//
// Request body:
//
//	{"payload_hash": "sha256:<hex>", "algorithm": "ES256"}
//
// Response body:
//
//	{"signature": "<base64>", "key_version": 3}
//
// Error responses:
//   - 400 Bad Request:  malformed body, invalid payload_hash, unknown algorithm.
//   - 403 Forbidden:    policy denied the operation.
//   - 404 Not Found:    key does not exist in the backend.
//   - 500 Internal:     backend error or unexpected failure.
func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyid")
	tok := tokenFromContext(r.Context())

	ev, err := audit.New()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ev.Operation = audit.OperationSign
	ev.Environment = s.env
	ev.CallerID = tok.CallerID
	ev.TeamID = tok.TeamID
	ev.AgentSession = tok.SessionID
	ev.KeyID = keyID
	ev.SourceIP = sourceIP(r)
	ev.UserAgent = r.Header.Get("User-Agent")
	ev.Outcome = audit.OutcomeError // overwritten below

	defer func() { s.logAudit(r, ev) }()

	// ── 1. Decode request body ────────────────────────────────────────────────
	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// ── 2. Validate and parse payload_hash ───────────────────────────────────
	payloadHash, err := parsePayloadHash(req.PayloadHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload_hash: "+err.Error())
		return
	}
	// Record the hash reference in the audit event — never the raw payload.
	ev.PayloadHash = req.PayloadHash

	// ── 3. Validate algorithm ─────────────────────────────────────────────────
	alg := backend.Algorithm(req.Algorithm)
	if !alg.IsSigningAlgorithm() {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("algorithm %q is not a signing algorithm", req.Algorithm))
		return
	}
	ev.Algorithm = req.Algorithm

	// ── 4. Policy check ───────────────────────────────────────────────────────
	dec := s.policy.Evaluate(policy.Request{
		CallerID:  tok.CallerID,
		TeamID:    tok.TeamID,
		Operation: policy.OperationSign,
		KeyID:     keyID,
	})
	if !dec.Allowed {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = dec.DenyReason
		writeError(w, http.StatusForbidden, "operation denied by policy")
		return
	}

	// ── 5. Backend operation ──────────────────────────────────────────────────
	result, err := s.backend.Sign(r.Context(), keyID, payloadHash, alg)
	if err != nil {
		s.logger.Error("sign: backend error",
			"key_id", keyID, "algorithm", req.Algorithm, "error", err)
		if isKeyNotFound(err) {
			writeError(w, http.StatusNotFound, "key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "sign operation failed")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	ev.KeyVersion = result.KeyVersion

	// ── 6. Response ───────────────────────────────────────────────────────────
	writeJSON(w, signResponse{
		Signature:  base64.StdEncoding.EncodeToString(result.Signature),
		KeyVersion: result.KeyVersion,
	})
}

// ── Shared input parsing helpers ──────────────────────────────────────────────

// parsePayloadHash validates and decodes a payload hash string.
// Expected format: "sha256:<64-character lowercase hex string>".
// Returns the 32 decoded bytes on success.
func parsePayloadHash(s string) ([]byte, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return nil, fmt.Errorf("must start with %q", prefix)
	}
	hexStr := s[len(prefix):]
	if len(hexStr) != 64 {
		return nil, fmt.Errorf("SHA-256 hex must be 64 characters, got %d", len(hexStr))
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("SHA-256 hash must be 32 bytes, got %d", len(decoded))
	}
	return decoded, nil
}

// isKeyNotFound reports whether err wraps backend.ErrKeyNotFound.
// Uses errors.Is to handle all error chain forms including errors.Join.
func isKeyNotFound(err error) bool {
	return errors.Is(err, backend.ErrKeyNotFound)
}
