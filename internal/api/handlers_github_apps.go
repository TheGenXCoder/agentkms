// handlers_github_apps.go — UX-B: GitHub App registration endpoints.
//
// Endpoints:
//
//	POST   /github-apps           — register (create or replace) a GitHub App
//	GET    /github-apps           — list all registered Apps (no private key)
//	GET    /github-apps/{name}    — inspect a single App (no private key)
//	DELETE /github-apps/{name}    — remove a GitHub App registration
//
// All endpoints:
//   - require an authenticated session (existing authMiddleware)
//   - emit an audit event via s.auditLog
//   - NEVER return private key bytes in any response body
//
// The private key is accepted only on POST and stored encrypted in the KV layer.
// Inspect and List return only AppID, InstallationID, and Name.

package api

import (
	"encoding/json"
	"net/http"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/githubapp"
)

// SetGithubAppStore wires in the GitHub App store after construction.
// Call this from cmd/server/main.go and cmd/dev/main.go once the KV backend is available.
// If not called, all /github-apps/* endpoints return 503 Service Unavailable.
func (s *Server) SetGithubAppStore(gs githubapp.Store) {
	s.githubAppStore = gs
}

// ── POST /github-apps ─────────────────────────────────────────────────────────

// registerGithubAppRequest is the JSON body accepted by POST /github-apps.
//
// SECURITY: private_key_pem is accepted here and stored encrypted in KV.
// It is NEVER echoed back in any response body.
type registerGithubAppRequest struct {
	Name           string `json:"name"`
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
	// PrivateKeyPEM is the RSA private key PEM for the GitHub App.
	// Required on registration. Never returned in GET responses.
	PrivateKeyPEM string `json:"private_key_pem"`
}

func (s *Server) handleRegisterGithubApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationGithubAppRegister
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	populateIdentityFields(&ev, id)

	if s.githubAppStore == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "github app store not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req registerGithubAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid JSON body"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "invalid JSON body")
		return
	}

	if req.Name == "" {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "name is required"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "name is required")
		return
	}
	if req.AppID == 0 {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "app_id is required"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "app_id is required")
		return
	}
	if req.InstallationID == 0 {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "installation_id is required"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "installation_id is required")
		return
	}
	if req.PrivateKeyPEM == "" {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "private_key_pem is required"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "private_key_pem is required")
		return
	}

	ev.KeyID = "github-apps/" + req.Name

	app := githubapp.GithubApp{
		Name:           req.Name,
		AppID:          req.AppID,
		InstallationID: req.InstallationID,
		PrivateKeyPEM:  []byte(req.PrivateKeyPEM),
	}

	if err := s.githubAppStore.Save(ctx, app); err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// Return only the summary — never the private key.
	writeJSON(w, http.StatusCreated, githubapp.Summary{
		Name:           app.Name,
		AppID:          app.AppID,
		InstallationID: app.InstallationID,
	})
}

// ── GET /github-apps ──────────────────────────────────────────────────────────

func (s *Server) handleListGithubApps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationGithubAppInspect
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.KeyID = "github-apps/*"
	populateIdentityFields(&ev, id)

	if s.githubAppStore == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "github app store not configured")
		return
	}

	summaries, err := s.githubAppStore.List(ctx)
	if err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	_ = s.auditLog(ctx, ev)

	if summaries == nil {
		summaries = []githubapp.Summary{}
	}
	writeJSON(w, http.StatusOK, summaries)
}

// ── GET /github-apps/{name} ───────────────────────────────────────────────────

func (s *Server) handleInspectGithubApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)
	name := r.PathValue("name")

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationGithubAppInspect
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.KeyID = "github-apps/" + name
	populateIdentityFields(&ev, id)

	if s.githubAppStore == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "github app store not configured")
		return
	}

	app, err := s.githubAppStore.Get(ctx, name)
	if err != nil {
		if err == githubapp.ErrNotFound {
			ev.Outcome = audit.OutcomeDenied
			ev.DenyReason = "not found"
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusNotFound, errCodeKeyNotFound, "github app not found")
			return
		}
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	_ = s.auditLog(ctx, ev)

	// Return only the summary — private key is NEVER returned to external callers.
	writeJSON(w, http.StatusOK, githubapp.Summary{
		Name:           app.Name,
		AppID:          app.AppID,
		InstallationID: app.InstallationID,
	})
}

// ── DELETE /github-apps/{name} ────────────────────────────────────────────────

func (s *Server) handleDeleteGithubApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFromContext(ctx)
	name := r.PathValue("name")

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationGithubAppDelete
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.KeyID = "github-apps/" + name
	populateIdentityFields(&ev, id)

	if s.githubAppStore == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "github app store not configured")
		return
	}

	if err := s.githubAppStore.Delete(ctx, name); err != nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	_ = s.auditLog(ctx, ev)
	w.WriteHeader(http.StatusNoContent)
}
