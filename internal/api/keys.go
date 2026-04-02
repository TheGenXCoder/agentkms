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

// ── Rotate key stub ───────────────────────────────────────────────────────────

// handleRotateKeyStub handles POST /rotate/{keyid...}.
//
// ┌──────────────────────────────────────────────────────────────────────┐
// │  TODO(C-05, B-01) — Not implemented                                  │
// │                                                                      │
// │  Key rotation requires the OpenBao backend (backlog B-01) to be      │
// │  available so that RotateKey can be delegated to the Transit engine.  │
// │  Implement once B-01 is complete.                                    │
// │                                                                      │
// │  When implemented, the endpoint will:                                │
// │    1. Validate key ID and policy (same pattern as other handlers).   │
// │    2. Call backend.RotateKey(ctx, keyID).                            │
// │    3. Audit the rotation event.                                      │
// │    4. Return updated KeyMeta (no key material).                      │
// └──────────────────────────────────────────────────────────────────────┘
func (s *Server) handleRotateKeyStub(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyID := r.PathValue("keyid")

	// Audit every access to the rotate endpoint — even stub 501 responses.
	// An attacker probing rotation capabilities must be visible in the audit trail.
	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationRotateKey
	ev.KeyID = keyID
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()

	id := identityFromContext(ctx)
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession

	// Outcome is OutcomeError because the service failed to fulfil the request
	// (not implemented), not because the policy denied it.
	ev.Outcome = audit.OutcomeError
	ev.DenyReason = "key rotation not yet implemented (backlog C-05, B-01)"
	if logErr := s.auditLog(ctx, ev); logErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	s.writeError(w, http.StatusNotImplemented, errCodeNotImplemented,
		"key rotation is not yet implemented; see backlog C-05")
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
