package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
)

// ── Response types ────────────────────────────────────────────────────────────

// keyMetaResponse is the JSON representation of a KeyMeta value.
// It mirrors backend.KeyMeta but serialises timestamps as RFC 3339 strings
// and omits key material (which KeyMeta never contains by contract).
type keyMetaResponse struct {
	KeyID     string  `json:"key_id"`
	Algorithm string  `json:"algorithm"`
	Version   int     `json:"version"`
	TeamID    string  `json:"team_id"`
	CreatedAt string  `json:"created_at"` // RFC 3339
	RotatedAt *string `json:"rotated_at,omitempty"`
}

type listKeysResponse struct {
	Keys []*keyMetaResponse `json:"keys"`
}

// createKeyRequest is the body for POST /keys (dev-only endpoint).
type createKeyRequest struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	TeamID    string `json:"team_id"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// handleListKeys implements GET /keys.
//
// Authentication: Bearer token.
// Policy:         must allow operation "list_keys" for this identity.
// Query params:
//   - prefix: filter keys by ID prefix (optional)
//   - team:   filter keys by team ID (optional)
//
// Response: {"keys": [...keyMetaResponse]}
//
// SECURITY: Only metadata is returned.  Key material never appears in
// backend.KeyMeta or in keyMetaResponse.
func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromContext(r.Context())

	ev, err := audit.New()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ev.Operation = audit.OperationListKeys
	ev.Environment = s.env
	ev.CallerID = tok.CallerID
	ev.TeamID = tok.TeamID
	ev.AgentSession = tok.SessionID
	ev.SourceIP = sourceIP(r)
	ev.UserAgent = r.Header.Get("User-Agent")
	ev.Outcome = audit.OutcomeError

	defer func() { s.logAudit(r, ev) }()

	prefix := r.URL.Query().Get("prefix")
	teamFilter := r.URL.Query().Get("team")

	dec := s.policy.Evaluate(policy.Request{
		CallerID:  tok.CallerID,
		TeamID:    tok.TeamID,
		Operation: policy.OperationListKeys,
		KeyID:     prefix, // policy key prefix matches against the filter prefix
	})
	if !dec.Allowed {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = dec.DenyReason
		writeError(w, http.StatusForbidden, "operation denied by policy")
		return
	}

	metas, err := s.backend.ListKeys(r.Context(), backend.KeyScope{
		Prefix: prefix,
		TeamID: teamFilter,
	})
	if err != nil {
		s.logger.Error("list_keys: backend error", "error", err)
		writeError(w, http.StatusInternalServerError, "list keys failed")
		return
	}

	ev.Outcome = audit.OutcomeSuccess

	resp := &listKeysResponse{Keys: make([]*keyMetaResponse, 0, len(metas))}
	for _, m := range metas {
		resp.Keys = append(resp.Keys, toKeyMetaResponse(m))
	}
	writeJSON(w, resp)
}

// handleRotateKey implements POST /keys/rotate/{key-id...}.
//
// Authentication: Bearer token.
// Policy:         must allow operation "rotate_key" for this identity + key.
//
// Response: updated key metadata (new version number, rotated_at).
func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyid")
	tok := tokenFromContext(r.Context())

	ev, err := audit.New()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ev.Operation = audit.OperationRotateKey
	ev.Environment = s.env
	ev.CallerID = tok.CallerID
	ev.TeamID = tok.TeamID
	ev.AgentSession = tok.SessionID
	ev.KeyID = keyID
	ev.SourceIP = sourceIP(r)
	ev.UserAgent = r.Header.Get("User-Agent")
	ev.Outcome = audit.OutcomeError

	defer func() { s.logAudit(r, ev) }()

	dec := s.policy.Evaluate(policy.Request{
		CallerID:  tok.CallerID,
		TeamID:    tok.TeamID,
		Operation: policy.OperationRotateKey,
		KeyID:     keyID,
	})
	if !dec.Allowed {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = dec.DenyReason
		writeError(w, http.StatusForbidden, "operation denied by policy")
		return
	}

	meta, err := s.backend.RotateKey(r.Context(), keyID)
	if err != nil {
		s.logger.Error("rotate_key: backend error", "key_id", keyID, "error", err)
		if isKeyNotFound(err) {
			writeError(w, http.StatusNotFound, "key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "rotate key failed")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	ev.KeyVersion = meta.Version

	writeJSON(w, toKeyMetaResponse(meta))
}

// handleCreateKey implements POST /keys (dev only).
//
// This endpoint is only registered when Server.env == "dev".  In production,
// keys are created via the backend admin interface (OpenBao CLI, AWS KMS
// console, etc.) — not through the AgentKMS API.
//
// The handler type-asserts the backend to *backend.DevBackend to call
// CreateKey.  If the backend is not a DevBackend, it returns 501.
//
// Authentication: Bearer token.
// Policy:         must allow operation "key_create" for this identity.
//
// Request body:
//
//	{"key_id": "payments/signing-key", "algorithm": "ES256", "team_id": "dev-team"}
//
// Response: created key metadata.
func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromContext(r.Context())

	ev, err := audit.New()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ev.Operation = audit.OperationKeyCreate
	ev.Environment = s.env
	ev.CallerID = tok.CallerID
	ev.TeamID = tok.TeamID
	ev.AgentSession = tok.SessionID
	ev.SourceIP = sourceIP(r)
	ev.UserAgent = r.Header.Get("User-Agent")
	ev.Outcome = audit.OutcomeError

	defer func() { s.logAudit(r, ev) }()

	// Type-assert: only DevBackend supports CreateKey.
	devBackend, ok := s.backend.(*backend.DevBackend)
	if !ok {
		writeError(w, http.StatusNotImplemented, "key creation not supported by this backend")
		return
	}

	var req createKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.KeyID == "" {
		writeError(w, http.StatusBadRequest, "key_id must not be empty")
		return
	}
	alg := backend.Algorithm(req.Algorithm)
	if !alg.IsSigningAlgorithm() && !alg.IsEncryptionAlgorithm() {
		writeError(w, http.StatusBadRequest, "unsupported algorithm: "+req.Algorithm)
		return
	}

	teamID := req.TeamID
	if teamID == "" {
		teamID = tok.TeamID
	}

	ev.KeyID = req.KeyID

	dec := s.policy.Evaluate(policy.Request{
		CallerID:  tok.CallerID,
		TeamID:    tok.TeamID,
		Operation: policy.OperationKeyCreate,
		KeyID:     req.KeyID,
	})
	if !dec.Allowed {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = dec.DenyReason
		writeError(w, http.StatusForbidden, "operation denied by policy")
		return
	}

	if err := devBackend.CreateKey(req.KeyID, alg, teamID); err != nil {
		s.logger.Error("key_create: backend error", "key_id", req.KeyID, "error", err)
		if errors.Is(err, backend.ErrInvalidInput) {
			writeError(w, http.StatusBadRequest, "invalid key parameters")
			return
		}
		writeError(w, http.StatusConflict, "key already exists or creation failed")
		return
	}

	// Fetch the exact key metadata to return in the response.
	// Use prefix=req.KeyID but then match exactly — prefix matching would
	// return unrelated keys that share a common prefix (e.g. "payments/key"
	// and "payments/key-v2").
	metas, err := s.backend.ListKeys(r.Context(), backend.KeyScope{Prefix: req.KeyID})
	var created *backend.KeyMeta
	if err == nil {
		for _, m := range metas {
			if m.KeyID == req.KeyID {
				created = m
				break
			}
		}
	}
	if created == nil {
		// Key was created but metadata unavailable — still a success.
		ev.Outcome = audit.OutcomeSuccess
		w.WriteHeader(http.StatusCreated)
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	ev.KeyVersion = created.Version

	writeJSONStatus(w, http.StatusCreated, toKeyMetaResponse(created))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// toKeyMetaResponse converts a backend.KeyMeta to its JSON response form.
func toKeyMetaResponse(m *backend.KeyMeta) *keyMetaResponse {
	resp := &keyMetaResponse{
		KeyID:     m.KeyID,
		Algorithm: string(m.Algorithm),
		Version:   m.Version,
		TeamID:    m.TeamID,
		CreatedAt: m.CreatedAt.UTC().Format(time.RFC3339),
	}
	if m.RotatedAt != nil {
		s := m.RotatedAt.UTC().Format(time.RFC3339)
		resp.RotatedAt = &s
	}
	return resp
}
