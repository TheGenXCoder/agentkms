package api

import (
	"net/http"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
)

// ── Response types ────────────────────────────────────────────────────────────

// keyMetaResponse is the JSON representation of a single key's metadata.
//
// SECURITY: contains ONLY key metadata — identifier, algorithm, version
// numbers, and dates.  Key material (private key bytes, symmetric key bytes)
// is structurally absent: there is no field that could carry it.
type keyMetaResponse struct {
	KeyID     string  `json:"key_id"`
	Algorithm string  `json:"algorithm"`
	Version   int     `json:"version"`
	CreatedAt string  `json:"created_at"` // RFC 3339
	RotatedAt *string `json:"rotated_at,omitempty"`
	TeamID    string  `json:"team_id"`
}

// listKeysResponse is the JSON body for a successful GET /keys.
type listKeysResponse struct {
	Keys []keyMetaResponse `json:"keys"`
}

// ── List keys handler ─────────────────────────────────────────────────────────

// handleListKeys handles GET /keys.
//
// Query parameters (both optional):
//
//	prefix   — restrict to keys whose ID starts with this string.
//	team_id  — restrict to keys owned by this team.
//
// The response is key metadata only.  No key material is ever returned.
//
// Implements backlog C-04.
//
// Full integration blockers:
//   - TODO(A-04): Token validation middleware (auth stream).
//   - TODO(B-01): OpenBao backend injection (backend stream).
//   - TODO(P-03): Real policy engine evaluation (policy stream).
func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ── Audit event scaffold ───────────────────────────────────────────────
	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationListKeys
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()

	id := identityFromContext(ctx)
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession

	// ── 1. Query parameter parsing ─────────────────────────────────────────
	q := r.URL.Query()
	prefix := q.Get("prefix")
	teamID := q.Get("team_id")

	// Validate prefix if provided: same rules as a key ID prefix.
	// An empty prefix is valid (matches all keys).
	if prefix != "" && !isValidKeyIDPrefix(prefix) {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid prefix format"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid prefix format")
		return
	}

	// Validate team_id if provided.  Same character rules as a key ID segment:
	// lowercase alphanumeric, hyphens, underscores.  An empty team_id is valid
	// (matches all teams).
	if teamID != "" && !isValidTeamID(teamID) {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid team_id format"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid team_id format")
		return
	}

	// Use the prefix (or empty string if listing all) as the key scope in
	// the audit event and policy check.
	ev.KeyID = prefix

	// ── 2. Policy check ────────────────────────────────────────────────────
	// TODO(P-03): Wire real policy engine.
	// The keyID passed to Evaluate is the scope prefix; the engine enforces
	// whether this identity can list keys in that namespace.
	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationListKeys, prefix)
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
	scope := backend.KeyScope{
		Prefix: prefix,
		TeamID: teamID,
	}
	metas, bErr := s.backend.ListKeys(ctx, scope)
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
	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 5. Response ────────────────────────────────────────────────────────
	// Convert backend.KeyMeta to keyMetaResponse.  The conversion is explicit
	// rather than using reflection so that adding a key-material field to
	// KeyMeta in future would require a deliberate change here too.
	resp := listKeysResponse{
		Keys: make([]keyMetaResponse, 0, len(metas)),
	}
	for _, m := range metas {
		kmr := keyMetaResponse{
			KeyID:     m.KeyID,
			Algorithm: string(m.Algorithm),
			Version:   m.Version,
			CreatedAt: m.CreatedAt.Format(time.RFC3339),
			TeamID:    m.TeamID,
		}
		if m.RotatedAt != nil {
			s := m.RotatedAt.Format(time.RFC3339)
			kmr.RotatedAt = &s
		}
		resp.Keys = append(resp.Keys, kmr)
	}

	writeJSON(w, http.StatusOK, resp)
}

// ── Rotate key handler ────────────────────────────────────────────────────────

// rotateKeyResponse is the JSON body for a successful POST /rotate/{keyid...}.
//
// SECURITY: contains ONLY key metadata.  No key material is ever returned.
type rotateKeyResponse struct {
	KeyID     string  `json:"key_id"`
	Algorithm string  `json:"algorithm"`
	Version   int     `json:"version"`
	RotatedAt string  `json:"rotated_at"` // RFC 3339
	CreatedAt string  `json:"created_at"` // RFC 3339
	TeamID    string  `json:"team_id"`
}

// handleRotateKey handles POST /rotate/{keyid...}.
//
// Rotates the named key: generates a new key version and makes it active for
// all subsequent Sign and Encrypt operations.  Historical versions are
// retained so that data encrypted before rotation remains decryptable.
//
// Request flow:
//  1. Input validation (key ID format).
//  2. Policy evaluation — deny-by-default.
//  3. backend.RotateKey — generates new version, retains old.
//  4. Audit log write — before response.
//  5. Response — updated KeyMeta only (no key material).
//
// Implements backlog C-05.
func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyID := r.PathValue("keyid")

	// ── Audit event scaffold ───────────────────────────────────────────────
	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationRotateKey
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
	ev.KeyID = keyID

	// ── 2. Policy check ────────────────────────────────────────────────────
	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationRotateKey, keyID)
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
		ev.DenyReason = decision.DenyReason // audit only — never sent in response
		populateAnomalies(&ev, decision.Anomalies)
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	// ── 3. Backend call ────────────────────────────────────────────────────
	meta, bErr := s.backend.RotateKey(ctx, keyID)
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
	ev.KeyVersion = meta.Version

	// ── 4. Audit ───────────────────────────────────────────────────────────
	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 5. Response ────────────────────────────────────────────────────────
	// SECURITY: response contains ONLY key metadata — id, algorithm, version,
	// timestamps, team.  No key material.
	resp := rotateKeyResponse{
		KeyID:     meta.KeyID,
		Algorithm: string(meta.Algorithm),
		Version:   meta.Version,
		CreatedAt: meta.CreatedAt.Format(time.RFC3339),
		TeamID:    meta.TeamID,
	}
	if meta.RotatedAt != nil {
		resp.RotatedAt = meta.RotatedAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

// ── Validation helpers (keys-specific) ───────────────────────────────────────

// isValidKeyIDPrefix reports whether prefix is a valid key ID scope prefix.
//
// A prefix may be empty (matches all keys) or a valid partial or complete key
// ID path with an optional trailing slash.
//
// Examples of valid prefixes: "", "payments/", "payments/signing-key",
// "ml-team/".
// Examples of invalid prefixes: "../", "PAYMENTS/", "//bad".
func isValidKeyIDPrefix(prefix string) bool {
	if prefix == "" {
		return true
	}
	// Strip optional trailing slash before validating segments.
	trimmed := prefix
	if len(trimmed) > 0 && trimmed[len(trimmed)-1] == '/' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	if trimmed == "" {
		// A bare "/" is not a valid prefix.
		return false
	}
	return isValidKeyID(trimmed)
}
