package api

// registry.go — KPM Phase 1: registry endpoints for secret and metadata management.
//
// Storage layout (logical path prefixes in the shared EncryptedKV file):
//
//	kv/data/secrets/{path}      — secret value fields
//	kv/data/metadata/{path}     — metadata record (version, tags, etc.)
//	kv/data/secrets/{path}/v{N} — archived version N of the secret value
//
// SECURITY INVARIANTS:
//
//  1. Secret values are NEVER returned in metadata, list, or history responses.
//  2. List responses are built from metadata paths only — they cannot
//     accidentally reach the secrets namespace.
//  3. Any metadata field whose name contains "value" or "secret" is stripped
//     before the response is written (defense in depth against future bugs).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/credentials"
)

// ── Path helpers ──────────────────────────────────────────────────────────────

const (
	kvMount         = "kv"
	secretsPrefix   = "kv/data/secrets"
	metadataPrefix  = "kv/data/metadata"
	maxVersions     = 10 // v0.1 simplification: keep last 10 versions
)

func secretKVPath(userPath string) string {
	return secretsPrefix + "/" + strings.TrimPrefix(userPath, "/")
}

func metadataKVPath(userPath string) string {
	return metadataPrefix + "/" + strings.TrimPrefix(userPath, "/")
}

func versionKVPath(userPath string, version int) string {
	return secretsPrefix + "/" + strings.TrimPrefix(userPath, "/") + "/v" + strconv.Itoa(version)
}

// ── Request/Response types ────────────────────────────────────────────────────

type writeSecretRequest struct {
	// Flat fields: the entire JSON body is stored as the secret's field map.
	// We accept any key=value pairs — callers use whatever fields make sense.
	// Common patterns: {"value":"..."} or {"access_key_id":"...","secret_access_key":"..."}
}

type writeMetadataRequest struct {
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Type        string   `json:"type,omitempty"`
	Expires     string   `json:"expires,omitempty"`
}

type metadataResponse struct {
	Path        string   `json:"path"`
	Version     int      `json:"version"`
	Created     string   `json:"created,omitempty"`
	Updated     string   `json:"updated,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Type        string   `json:"type,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	Deleted     bool     `json:"deleted,omitempty"`
}

type historyResponse struct {
	Path     string        `json:"path"`
	Versions []versionInfo `json:"versions"`
}

type versionInfo struct {
	Version int    `json:"version"`
	Created string `json:"created,omitempty"`
}

// ── Internal metadata record ──────────────────────────────────────────────────

// metadataRecord is stored in KV as a flat map[string]string.
// We use string encoding for all fields to fit the EncryptedKV data model.
// Keys are prefixed with "meta_" to avoid collision with future secret fields.
//
// v0.1 simplification: versions stored as semicolon-separated string in metadata.
// Move to dedicated version index in v0.2.
type metadataRecord struct {
	Version         int
	Created         string
	Updated         string
	Description     string
	Tags            string // semicolon-separated
	Type            string
	Expires         string
	Deleted         string // "true" or ""
	VersionsHistory string // semicolon-separated list of "N:timestamp" pairs
}

func metadataFromMap(m map[string]string) metadataRecord {
	v, _ := strconv.Atoi(m["meta_version"])
	return metadataRecord{
		Version:         v,
		Created:         m["meta_created"],
		Updated:         m["meta_updated"],
		Description:     m["meta_description"],
		Tags:            m["meta_tags"],
		Type:            m["meta_type"],
		Expires:         m["meta_expires"],
		Deleted:         m["meta_deleted"],
		VersionsHistory: m["meta_versions_history"],
	}
}

func metadataToMap(r metadataRecord) map[string]string {
	return map[string]string{
		"meta_version":          strconv.Itoa(r.Version),
		"meta_created":          r.Created,
		"meta_updated":          r.Updated,
		"meta_description":      r.Description,
		"meta_tags":             r.Tags,
		"meta_type":             r.Type,
		"meta_expires":          r.Expires,
		"meta_deleted":          r.Deleted,
		"meta_versions_history": r.VersionsHistory,
	}
}

func metadataToResponse(userPath string, rec metadataRecord) metadataResponse {
	resp := metadataResponse{
		Path:        userPath,
		Version:     rec.Version,
		Created:     rec.Created,
		Updated:     rec.Updated,
		Description: rec.Description,
		Type:        rec.Type,
		Expires:     rec.Expires,
		Deleted:     rec.Deleted == "true",
	}
	if rec.Tags != "" {
		resp.Tags = strings.Split(rec.Tags, ";")
	}
	return resp
}

// stripSensitiveFields removes any fields whose name contains "value" or "secret"
// (case-insensitive) from a metadata map. Defense in depth.
func stripSensitiveFields(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "value") || strings.Contains(lower, "secret") {
			continue
		}
		out[k] = v
	}
	return out
}

// parseVersionsHistory parses the semicolon-separated "N:timestamp" history string.
func parseVersionsHistory(s string) []versionInfo {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ";")
	out := make([]versionInfo, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		idx := strings.Index(p, ":")
		if idx < 0 {
			continue
		}
		n, err := strconv.Atoi(p[:idx])
		if err != nil {
			continue
		}
		out = append(out, versionInfo{Version: n, Created: p[idx+1:]})
	}
	return out
}

// appendVersionHistory adds an entry and trims to maxVersions.
func appendVersionHistory(existing string, version int, ts string) string {
	entry := fmt.Sprintf("%d:%s", version, ts)
	if existing == "" {
		return entry
	}
	parts := strings.Split(existing, ";")
	parts = append(parts, entry)
	// v0.1 simplification: versions stored as semicolon-separated string in metadata.
	// Move to dedicated version index in v0.2.
	if len(parts) > maxVersions {
		parts = parts[len(parts)-maxVersions:]
	}
	return strings.Join(parts, ";")
}

// userPathFromKVPath strips the metadata or secrets prefix to recover the
// user-visible path (e.g. "cloudflare/dns-token").
func userPathFromKVPath(kvPath, prefix string) string {
	p := strings.TrimPrefix(kvPath, prefix+"/")
	return p
}

// ── POST /secrets/{path...} ───────────────────────────────────────────────────

// handleWriteSecret handles POST /secrets/{path...}.
//
// Reads a JSON body of arbitrary key=value pairs (the entire body is stored
// as the secret's field map). Creates or updates the secret at the given path.
// On update: archives the current version, increments the version counter,
// and retains at most maxVersions historical versions.
//
// SECURITY: secret values are NEVER included in the audit event.
func (s *Server) handleWriteSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userPath := r.PathValue("path")
	id := identityFromContext(ctx)

	// ── Audit scaffold ─────────────────────────────────────────────────────
	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationSecretWrite
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession

	// ── 1. Input validation ────────────────────────────────────────────────
	userPath = strings.Trim(userPath, "/")
	if userPath == "" {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid path: empty"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "path is required")
		return
	}
	ev.KeyID = "secrets/" + userPath

	// ── 2. Policy check ────────────────────────────────────────────────────
	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationSecretWrite, ev.KeyID)
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateAnomalies(&ev, decision.Anomalies)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	// ── 3. Check registry writer ───────────────────────────────────────────
	if s.registryWriter == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "registry not configured")
		return
	}

	// ── 4. Decode body — NEVER log the values ─────────────────────────────
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var fields map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid JSON body"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid JSON body")
		return
	}
	if len(fields) == 0 {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "empty secret body"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "secret body must not be empty")
		return
	}

	// Convert json.RawMessage values to strings (unquote string values).
	secretFields := make(map[string]string, len(fields))
	for k, raw := range fields {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			// Not a string — store the raw JSON representation.
			secretFields[k] = string(raw)
		} else {
			secretFields[k] = s
		}
	}

	// ── 5. Versioning ──────────────────────────────────────────────────────
	now := time.Now().UTC().Format(time.RFC3339)
	secretPath := secretKVPath(userPath)
	metaPath := metadataKVPath(userPath)

	existing, err := s.registryWriter.GetSecret(ctx, metaPath)
	var rec metadataRecord
	isNew := true
	if err == nil {
		// Secret exists — archive current version.
		isNew = false
		existing = stripSensitiveFields(existing)
		rec = metadataFromMap(existing)

		// Copy current value to versioned path before overwriting.
		currentVal, vErr := s.registryWriter.GetSecret(ctx, secretPath)
		if vErr == nil && len(currentVal) > 0 {
			newVersion := rec.Version + 1
			verPath := versionKVPath(userPath, rec.Version) // archive as old version
			if setErr := s.registryWriter.SetSecret(ctx, verPath, currentVal); setErr != nil {
				ev.Outcome = audit.OutcomeError
				_ = s.auditLog(ctx, ev)
				s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
				return
			}
			rec.VersionsHistory = appendVersionHistory(rec.VersionsHistory, rec.Version, rec.Updated)
			rec.Version = newVersion
		}
		rec.Updated = now
	} else {
		// New secret.
		rec.Version = 1
		rec.Created = now
		rec.Updated = now
	}

	// ── 6. Write secret value ──────────────────────────────────────────────
	if err := s.registryWriter.SetSecret(ctx, secretPath, secretFields); err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 7. Update metadata ─────────────────────────────────────────────────
	if isNew {
		rec.Type = "generic"
	}
	rec.Deleted = ""
	if err := s.registryWriter.SetSecret(ctx, metaPath, metadataToMap(rec)); err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 8. Audit success (NO secret values) ───────────────────────────────
	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 9. Response ────────────────────────────────────────────────────────
	status := http.StatusCreated
	if !isNew {
		status = http.StatusOK
	}
	writeJSON(w, status, metadataToResponse(userPath, rec))
}

// ── POST /metadata/{path...} ──────────────────────────────────────────────────

// handleWriteMetadata handles POST /metadata/{path...}.
//
// Updates metadata fields for an existing secret. The secret must already
// exist (metadata path must be present). Fields are merged — absent fields
// in the request body are left unchanged.
func (s *Server) handleWriteMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userPath := r.PathValue("path")
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationMetadataWrite
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession

	userPath = strings.Trim(userPath, "/")
	if userPath == "" {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid path: empty"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "path is required")
		return
	}
	ev.KeyID = "metadata/" + userPath

	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationMetadataWrite, ev.KeyID)
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateAnomalies(&ev, decision.Anomalies)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	if s.registryWriter == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "registry not configured")
		return
	}

	// Secret must already exist.
	metaPath := metadataKVPath(userPath)
	existing, err := s.registryWriter.GetSecret(ctx, metaPath)
	if err != nil {
		ev.Outcome = audit.OutcomeError
		if isNotFound(err) {
			ev.DenyReason = "secret not found"
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusNotFound, errCodeKeyNotFound, "secret not found — write the secret first")
			return
		}
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	existing = stripSensitiveFields(existing)
	rec := metadataFromMap(existing)

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req writeMetadataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid JSON body"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid JSON body")
		return
	}

	// Merge — only overwrite provided fields.
	if req.Description != "" {
		rec.Description = req.Description
	}
	if len(req.Tags) > 0 {
		rec.Tags = strings.Join(req.Tags, ";")
	}
	if req.Type != "" {
		rec.Type = req.Type
	}
	if req.Expires != "" {
		rec.Expires = req.Expires
	}
	rec.Updated = time.Now().UTC().Format(time.RFC3339)

	if err := s.registryWriter.SetSecret(ctx, metaPath, metadataToMap(rec)); err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, metadataToResponse(userPath, rec))
}

// ── GET /metadata ─────────────────────────────────────────────────────────────

// handleListMetadata handles GET /metadata.
//
// Lists all registry secrets (metadata only — NEVER values).
// Filters deleted secrets unless ?include_deleted=true.
//
// SECURITY: only paths under the metadata prefix are listed.
// The list is built from metadata paths — it physically cannot reach
// the secrets namespace. Fields containing "value" or "secret" are
// stripped from each record as defense in depth.
func (s *Server) handleListMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationMetadataList
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession

	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationMetadataList, "metadata/*")
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateAnomalies(&ev, decision.Anomalies)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	if s.registryWriter == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "registry not configured")
		return
	}

	includeDeleted := r.URL.Query().Get("include_deleted") == "true"

	allPaths, err := s.registryWriter.ListPaths(ctx)
	if err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	results := make([]metadataResponse, 0)
	for _, kvPath := range allPaths {
		// Only process metadata paths.
		if !strings.HasPrefix(kvPath, metadataPrefix+"/") {
			continue
		}
		userPath := userPathFromKVPath(kvPath, metadataPrefix)

		raw, err := s.registryWriter.GetSecret(ctx, kvPath)
		if err != nil {
			continue // skip unreadable entries
		}
		// Defense in depth: strip any field containing "value" or "secret".
		raw = stripSensitiveFields(raw)
		rec := metadataFromMap(raw)

		if rec.Deleted == "true" && !includeDeleted {
			continue
		}

		results = append(results, metadataToResponse(userPath, rec))
	}

	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"secrets": results})
}

// ── GET /metadata/{path...} ───────────────────────────────────────────────────

// handleGetMetadata handles GET /metadata/{path...}.
// Returns metadata for a single secret — NEVER includes values.
func (s *Server) handleGetMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userPath := r.PathValue("path")
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationMetadataList
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession

	userPath = strings.Trim(userPath, "/")
	if userPath == "" {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid path: empty"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "path is required")
		return
	}
	ev.KeyID = "metadata/" + userPath

	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationMetadataList, ev.KeyID)
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateAnomalies(&ev, decision.Anomalies)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	if s.registryWriter == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "registry not configured")
		return
	}

	metaPath := metadataKVPath(userPath)
	raw, err := s.registryWriter.GetSecret(ctx, metaPath)
	if err != nil {
		ev.Outcome = audit.OutcomeError
		if isNotFound(err) {
			ev.DenyReason = "not found"
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusNotFound, errCodeKeyNotFound, "secret not found")
			return
		}
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// Defense in depth: strip any field containing "value" or "secret".
	raw = stripSensitiveFields(raw)
	rec := metadataFromMap(raw)

	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, metadataToResponse(userPath, rec))
}

// ── DELETE /secrets/{path...} ─────────────────────────────────────────────────

// handleDeleteSecret handles DELETE /secrets/{path...}.
//
// Default: soft-delete — sets deleted=true in metadata, retains values.
// With ?purge=true: hard-delete — removes secret value, all versions, and metadata.
// Purge uses OperationSecretPurge (separate policy operation).
func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userPath := r.PathValue("path")
	id := identityFromContext(ctx)
	purge := r.URL.Query().Get("purge") == "true"

	// Select audit operation based on purge flag.
	auditOp := audit.OperationSecretDelete
	if purge {
		auditOp = audit.OperationSecretPurge
	}

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = auditOp
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession

	userPath = strings.Trim(userPath, "/")
	if userPath == "" {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid path: empty"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "path is required")
		return
	}
	ev.KeyID = "secrets/" + userPath

	decision, pErr := s.policy.Evaluate(ctx, id, auditOp, ev.KeyID)
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateAnomalies(&ev, decision.Anomalies)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	if s.registryWriter == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "registry not configured")
		return
	}

	metaPath := metadataKVPath(userPath)
	secretPath := secretKVPath(userPath)

	// Verify the secret exists.
	existing, err := s.registryWriter.GetSecret(ctx, metaPath)
	if err != nil {
		if isNotFound(err) {
			ev.Outcome = audit.OutcomeError
			ev.DenyReason = "not found"
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusNotFound, errCodeKeyNotFound, "secret not found")
			return
		}
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	if purge {
		// Hard delete: remove secret, all versions, and metadata.
		existing = stripSensitiveFields(existing)
		rec := metadataFromMap(existing)

		// Delete all archived versions.
		versions := parseVersionsHistory(rec.VersionsHistory)
		for _, vi := range versions {
			verPath := versionKVPath(userPath, vi.Version)
			_ = s.registryWriter.DeleteSecret(ctx, verPath) // best-effort
		}

		// Delete current secret value.
		if err := s.registryWriter.DeleteSecret(ctx, secretPath); err != nil && !isNotFound(err) {
			ev.Outcome = audit.OutcomeError
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}

		// Delete metadata.
		if err := s.registryWriter.DeleteSecret(ctx, metaPath); err != nil && !isNotFound(err) {
			ev.Outcome = audit.OutcomeError
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
	} else {
		// Soft delete: mark deleted in metadata.
		existing = stripSensitiveFields(existing)
		rec := metadataFromMap(existing)
		rec.Deleted = "true"
		rec.Updated = time.Now().UTC().Format(time.RFC3339)
		if err := s.registryWriter.SetSecret(ctx, metaPath, metadataToMap(rec)); err != nil {
			ev.Outcome = audit.OutcomeError
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
	}

	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── GET /secrets/{path...} (with ?action=history) ────────────────────────────

// handleGetSecretOrHistory handles GET /secrets/{path...}.
//
// With ?action=history: returns the version history for the secret — NEVER includes values.
// Otherwise: returns 405 Method Not Allowed (secrets are not readable via GET;
// use /credentials/generic/{path} for credential vending).
//
// Note: Go 1.22 ServeMux does not support a suffix after a {wildcard...} segment,
// so /secrets/{path...}/history cannot be registered as a separate route.
// We use ?action=history as the alternative.
func (s *Server) handleGetSecretOrHistory(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("action") == "history" {
		s.handleSecretHistory(w, r)
		return
	}
	// GET on secrets without action=history is not a supported operation.
	// Secrets are vended via /credentials/generic/{path}, not read directly.
	s.writeError(w, http.StatusMethodNotAllowed, errCodeInvalidRequest,
		"secrets are not directly readable; use /credentials/generic/{path} for vending or add ?action=history for version history")
}

// handleSecretHistory returns version history for a secret — NEVER values.
func (s *Server) handleSecretHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userPath := r.PathValue("path")
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationSecretHistory
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession

	userPath = strings.Trim(userPath, "/")
	if userPath == "" {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid path: empty"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "path is required")
		return
	}
	ev.KeyID = "secrets/" + userPath

	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationSecretHistory, ev.KeyID)
	if pErr != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	if !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = decision.DenyReason
		populateAnomalies(&ev, decision.Anomalies)
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "operation denied by policy")
		return
	}

	if s.registryWriter == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "registry not configured")
		return
	}

	metaPath := metadataKVPath(userPath)
	raw, err := s.registryWriter.GetSecret(ctx, metaPath)
	if err != nil {
		if isNotFound(err) {
			ev.Outcome = audit.OutcomeError
			ev.DenyReason = "not found"
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusNotFound, errCodeKeyNotFound, "secret not found")
			return
		}
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	raw = stripSensitiveFields(raw)
	rec := metadataFromMap(raw)

	versions := parseVersionsHistory(rec.VersionsHistory)
	// Include current version in history if it exists.
	if rec.Version > 0 {
		versions = append(versions, versionInfo{Version: rec.Version, Created: rec.Updated})
	}

	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, historyResponse{
		Path:     userPath,
		Versions: versions,
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// isNotFound reports whether err signals a missing key.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not found") ||
		strings.Contains(err.Error(), credentials.ErrCredentialNotFound.Error())
}
