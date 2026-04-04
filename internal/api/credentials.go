package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/credentials"
)

// ── Response types ────────────────────────────────────────────────────────────

// credentialResponse is the JSON body for GET /credentials/llm/{provider}.
//
// SECURITY: APIKey is present because the caller needs it.  This is the
// ONLY place in the codebase where the LLM API key is included in a
// response.  The audit event for this response must NOT include the key.
type credentialResponse struct {
	// Provider is the LLM provider (e.g. "anthropic", "openai").
	Provider string `json:"provider"`

	// APIKey is the short-lived LLM API key.
	// SECURITY: the caller must treat this as sensitive material.
	// It must not be logged, stored on disk, or included in any further
	// audit event.  The Pi extension holds it in-memory only.
	APIKey string `json:"api_key"`

	// ExpiresAt is when this credential should be refreshed (RFC 3339).
	ExpiresAt string `json:"expires_at"`

	// TTLSeconds is the number of seconds until expiry.
	// The Pi extension refreshes when TTL < 10 minutes (600 seconds).
	TTLSeconds int `json:"ttl_seconds"`
}

type genericCredentialResponse struct {
	Path       string            `json:"path"`
	Secrets    map[string]string `json:"secrets"` // SECURITY: sensitive
	ExpiresAt  string            `json:"expires_at"`
	TTLSeconds int               `json:"ttl_seconds"`
}

// ── GET /credentials/llm/{provider} ──────────────────────────────────────────

// handleGetLLMCredential handles GET /credentials/llm/{provider}.
//
// Request flow:
//  1. Input validation (provider must be in supported set).
//  2. Policy check — caller must be allowed to vend credentials.
//  3. Fetch credential from KV store via Vender.
//  4. Audit log — records the vend event WITHOUT the API key.
//  5. Response — returns the API key with TTL.
//
// LV-01, LV-02, LV-03.
func (s *Server) handleGetLLMCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	provider := r.PathValue("provider")

	// ── Audit scaffold ─────────────────────────────────────────────────────
	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationCredentialVend
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.ComplianceTags = []string{"soc2", "pci-dss", "iso27001"}

	id := identityFromContext(ctx)
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession

	// ── 1. Input validation ────────────────────────────────────────────────
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid provider: empty"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "provider is required")
		return
	}
	if !credentials.SupportedProviders[provider] {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "unsupported provider"
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest,
			"unsupported provider — see /credentials/llm for supported list")
		return
	}
	// Store provider in audit event (safe — it's just the provider name, not the key).
	ev.KeyID = "llm/" + provider

	// ── Rate limit check (MEDIUM-05) ─────────────────────────────────────
	rateLimitKey := id.CallerID + ":" + provider
	if last, ok := s.credRateLimit.Load(rateLimitKey); ok {
		if time.Since(last.(time.Time)) < credRateLimitInterval {
			ev.Outcome = audit.OutcomeDenied
			ev.DenyReason = "rate limited: credential recently vended"
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusTooManyRequests, errCodeRateLimited,
				"credential recently vended — retry after TTL expires")
			return
		}
	}

	// ── 2. Policy check ────────────────────────────────────────────────────
	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationCredentialVend, ev.KeyID)
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

	// ── 3. Vend credential ─────────────────────────────────────────────────
	if s.vender == nil {
		ev.Outcome = audit.OutcomeError
		populateAnomalies(&ev, decision.Anomalies)
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal,
			"credential vending not configured")
		return
	}

	cred, vErr := s.vender.Vend(ctx, provider)
	if vErr != nil {
		ev.Outcome = audit.OutcomeError
		populateAnomalies(&ev, decision.Anomalies)
		if errors.Is(vErr, credentials.ErrCredentialNotFound) {
			ev.DenyReason = "credential not found for provider"
			if logErr := s.auditLog(ctx, ev); logErr != nil {
				s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
				return
			}
			s.writeError(w, http.StatusNotFound, errCodeKeyNotFound,
				"no credential configured for provider "+provider)
			return
		}
		if logErr := s.auditLog(ctx, ev); logErr != nil {
			s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
			return
		}
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 4. Audit (key MUST NOT appear here) ───────────────────────────────
	ev.Outcome = audit.OutcomeSuccess
	populateAnomalies(&ev, decision.Anomalies)
	// ev.KeyID is already set to "llm/{provider}" — safe to audit
	// The actual API key is deliberately absent from the audit event.
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		// Credential was vended but audit failed — return 500.
		// Compliance requires every vend to be audited.
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	// ── 5. Response ────────────────────────────────────────────────────────
	// Record successful vend time for rate limiting.
	s.credRateLimit.Store(rateLimitKey, time.Now())
	// SECURITY: this is the only response in the entire codebase that
	// contains a live API key.  The handler writes it directly here and
	// passes it nowhere else.  The key is NOT stored in the audit event.
	// Zero the key in memory immediately after writing the response.
	defer cred.Zero()
	writeJSON(w, http.StatusOK, credentialResponse{
		Provider:   cred.Provider,
		APIKey:     string(cred.APIKey),
		ExpiresAt:  cred.ExpiresAt.Format("2006-01-02T15:04:05Z"),
		TTLSeconds: cred.TTLSeconds,
	})
}

// ── POST /credentials/llm/{provider}/refresh ─────────────────────────────────

// handleRefreshLLMCredential handles POST /credentials/llm/{provider}/refresh.
//
// Functionally equivalent to GET /credentials/llm/{provider} — it re-vends
// a fresh credential for the same provider.  The Pi extension calls this
// when the credential is within 10 minutes of expiry.
//
// LV-04.
func (s *Server) handleRefreshLLMCredential(w http.ResponseWriter, r *http.Request) {
	// Refresh is identical to vend — delegate.
	s.handleGetLLMCredential(w, r)
}

// ── GET /credentials/llm ─────────────────────────────────────────────────────

// handleListLLMProviders handles GET /credentials/llm.
// Returns the list of supported provider names.  No credentials are returned.
func (s *Server) handleListLLMProviders(w http.ResponseWriter, r *http.Request) {
	providers := make([]string, 0, len(credentials.SupportedProviders))
	for p := range credentials.SupportedProviders {
		providers = append(providers, p)
	}
	writeJSON(w, http.StatusOK, map[string][]string{"providers": providers})
}

// ── GET /credentials/generic/{path} ──────────────────────────────────────────

func (s *Server) handleGetGenericCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := r.PathValue("path")
	id := identityFromContext(ctx)

	ev, evErr := audit.New()
	if evErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}
	ev.Operation = audit.OperationCredentialVend
	ev.Environment = s.env
	ev.SourceIP = extractRemoteIP(r)
	ev.UserAgent = r.UserAgent()
	ev.CallerID = id.CallerID
	ev.TeamID = id.TeamID
	ev.AgentSession = id.AgentSession

	if path == "" {
		ev.Outcome = audit.OutcomeDenied
		ev.DenyReason = "invalid path: empty"
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusBadRequest, errCodeInvalidRequest, "path is required")
		return
	}

	ev.KeyID = "generic/" + path
	rateLimitKey := id.CallerID + ":generic:" + path
	if last, ok := s.credRateLimit.Load(rateLimitKey); ok {
		if time.Since(last.(time.Time)) < credRateLimitInterval {
			ev.Outcome = audit.OutcomeDenied
			ev.DenyReason = "rate limited"
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusTooManyRequests, errCodeRateLimited, "retry after TTL expires")
			return
		}
	}

	decision, pErr := s.policy.Evaluate(ctx, id, audit.OperationCredentialVend, ev.KeyID)
	if pErr != nil || !decision.Allow {
		ev.Outcome = audit.OutcomeDenied
		if pErr == nil {
			ev.DenyReason = decision.DenyReason
		}
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusForbidden, errCodePolicyDenied, "denied")
		return
	}

	if s.vender == nil {
		ev.Outcome = audit.OutcomeError
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusServiceUnavailable, errCodeInternal, "vending not configured")
		return
	}

	cred, vErr := s.vender.VendGeneric(ctx, path)
	if vErr != nil {
		ev.Outcome = audit.OutcomeError
		if errors.Is(vErr, credentials.ErrCredentialNotFound) {
			ev.DenyReason = "not found"
			_ = s.auditLog(ctx, ev)
			s.writeError(w, http.StatusNotFound, errCodeKeyNotFound, "not found")
			return
		}
		_ = s.auditLog(ctx, ev)
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	ev.Outcome = audit.OutcomeSuccess
	if auditErr := s.auditLog(ctx, ev); auditErr != nil {
		s.writeError(w, http.StatusInternalServerError, errCodeInternal, "internal error")
		return
	}

	s.credRateLimit.Store(rateLimitKey, time.Now())
	defer cred.Zero()

	// Convert []byte map to string map for JSON response
	secretsMap := make(map[string]string, len(cred.Secrets))
	for k, v := range cred.Secrets {
		secretsMap[k] = string(v)
	}

	writeJSON(w, http.StatusOK, genericCredentialResponse{
		Path:       cred.Path,
		Secrets:    secretsMap,
		ExpiresAt:  cred.ExpiresAt.Format("2006-01-02T15:04:05Z"),
		TTLSeconds: cred.TTLSeconds,
	})
}
