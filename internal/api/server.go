// Package api implements the AgentKMS HTTP API handlers.
//
// Handlers: /sign, /encrypt, /decrypt, /keys, /credentials, /auth.
// Every handler must: validate the session token, evaluate policy,
// call the Backend interface (never a concrete backend directly),
// write an AuditEvent, and return only the minimal response.
//
// Backlog: C-01 to C-07.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/credentials/binding"
	"github.com/agentkms/agentkms/internal/plugin"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/internal/webhooks"
)

// Server holds the dependencies for all API handlers and owns the HTTP mux.
//
// All dependencies are injected at construction time via NewServer.  The zero
// value is invalid; always use NewServer.
//
// ┌──────────────────────────────────────────────────────────────────────────┐
// │  Dependency injection — integration status                               │
// │                                                                          │
// │  Backend  backend.Backend  ← injected by caller                         │
// │    TODO(B-01): Wire internal/backend/openbao.go once available.          │
// │    For T0/dev, inject *backend.DevBackend.                               │
// │                                                                          │
// │  Auditor  audit.Auditor    ← injected by caller                         │
// │    T0: *audit.FileAuditSink or *audit.MultiAuditor.                     │
// │                                                                          │
// │  Policy   policy.Engine    ← injected by caller                         │
// │    TODO(P-01,P-03): Wire real policy engine once P-03 is complete.       │
// │    Production must use a configured Engine, not DenyAllEngine.           │
// │    Never inject AllowAllEngine outside unit tests.                       │
// │                                                                          │
// │  Auth middleware is applied internally in registerRoutes.                │
// │    TODO(A-04): Wire real token middleware once A-04 is complete.         │
// └──────────────────────────────────────────────────────────────────────────┘
type Server struct {
	backend    backend.Backend
	auditor    audit.Auditor
	policy     policy.EngineI
	vender              *credentials.Vender    // nil until SetVender is called
	registryWriter      credentials.KVWriter   // nil until SetRegistryWriter is called
	bindingStore        binding.BindingStore   // nil until SetBindingStore is called
	destinationRegistry *plugin.Registry       // nil until SetDestinationRegistry is called
	alertOrchestrator   *webhooks.AlertOrchestrator // nil until SetAlertOrchestrator is called
	githubWebhookHandler *webhooks.GitHubWebhookHandler // nil until RegisterGitHubWebhookHandler is called
	authTokens *auth.TokenService

	// recoveryStore handles Layer 1 recovery codes.
	recoveryStore *auth.RecoveryStore

	// tokenService exposed for recovery bootstrap token issuance and WebAuthn.
	tokenService *auth.TokenService

	// webAuthn handles FIDO2/WebAuthn registration and authentication.
	webAuthn *auth.WebAuthnService

	// env identifies the deployment tier for audit events.
	env string

	mux *http.ServeMux

	// credentialUUIDs tracks known credential UUIDs and their revocation state.
	// Key: UUID string, Value: bool (true = revoked, false = active).
	// Pre-seeded in dev mode with well-known test UUIDs.
	credentialUUIDs sync.Map

	// credRateLimit tracks the last vend time per caller+provider.
	credRateLimit sync.Map

	// credRateLimitInterval is the minimum interval between credential vends
	// for the same caller+provider combination. Set to 0 to disable rate limiting.
	credRateLimitInterval time.Duration
}

// SetRecoveryStore wires in the recovery store after construction.
func (s *Server) SetRecoveryStore(rs *auth.RecoveryStore) {
	s.recoveryStore = rs
}

// SetVender wires in the credential vender after construction.
// Call this from cmd/server/main.go once the KV backend is available.
// If not called, /credentials/llm/* returns 503 Service Unavailable.
func (s *Server) SetVender(v *credentials.Vender) {
	s.vender = v
}

// SetRegistryWriter wires in the KV writer for registry endpoints after construction.
// Call this from cmd/dev/main.go after the EncryptedKV is created.
// If not called, registry write/delete endpoints return 503 Service Unavailable.
func (s *Server) SetRegistryWriter(w credentials.KVWriter) {
	s.registryWriter = w
}

// SetDestinationRegistry wires in the destination plugin registry after construction.
// Call this from cmd/server/main.go or cmd/dev/main.go once the plugin host has
// started destination plugins.
// If not called, the rotate endpoint will return "no deliverer" errors for every
// destination.
func (s *Server) SetDestinationRegistry(r *plugin.Registry) {
	s.destinationRegistry = r
}

// SetAlertOrchestrator wires an AlertOrchestrator into the Server so that the
// GitHub secret-scanning webhook handler can dispatch alerts through it.
// Must be called before Listen/Serve to take effect on incoming webhooks.
// If not called, the webhook endpoint still accepts requests but is a no-op
// (returns 200 OK without triggering any orchestration).
func (s *Server) SetAlertOrchestrator(orch *webhooks.AlertOrchestrator) {
	s.alertOrchestrator = orch
}

// SetRotationHook registers a RotationHook implementation with the underlying
// AlertOrchestrator. If the AlertOrchestrator has not been set (via
// SetAlertOrchestrator), this is a no-op with a warning log.
// Safe to call after Listen because the AlertOrchestrator's SetRotationHook
// uses a single-writer startup pattern (no concurrent webhook processing
// expected during startup).
func (s *Server) SetRotationHook(hook webhooks.RotationHook) {
	if s.alertOrchestrator == nil {
		slog.Warn("SetRotationHook called but AlertOrchestrator is nil; webhook-triggered rotation will not work")
		return
	}
	s.alertOrchestrator.SetRotationHook(hook)
}

// RegisterGitHubWebhookHandler registers the GitHub secret-scanning webhook handler
// on the server's internal mux. The handler is wired to the AlertOrchestrator if one
// has been set via SetAlertOrchestrator. Must be called before the server starts
// serving; calling it after Listen has no effect because the mux is already bound.
//
// The route registered is: POST /webhooks/github/secret-scanning
// This path matches the test expectations in github_orchestration_test.go and the T6
// runbook §4.2. The handler verifies HMAC-SHA256 (X-Hub-Signature-256 header) using
// webhookSecret before dispatching to the orchestrator.
func (s *Server) RegisterGitHubWebhookHandler(webhookSecret string) {
	h := webhooks.NewGitHubWebhookHandler(webhookSecret)
	if s.alertOrchestrator != nil {
		h.SetOrchestrator(s.alertOrchestrator)
	} else {
		slog.Warn("RegisterGitHubWebhookHandler called before SetAlertOrchestrator; webhook events will be accepted but no orchestration will run")
	}
	s.githubWebhookHandler = h
	// Register without the authMiddleware chain: GitHub webhooks are authenticated
	// by HMAC signature in the handler itself, not by session tokens.
	s.mux.Handle("POST /webhooks/github/secret-scanning", h)
}

// SetRateLimitInterval overrides the minimum interval between credential vends
// for the same caller+provider combination. Pass 0 to disable rate limiting.
func (s *Server) SetRateLimitInterval(d time.Duration) {
	s.credRateLimitInterval = d
}

// NewServer constructs a Server, registers all routes on an internal mux, and
// returns it ready to serve.
//
// All arguments are required and must not be nil.  env must be one of
// "production", "staging", or "dev".
//
// Panics immediately if any required argument is nil.  Fail-fast at
// construction is safer than a nil-pointer panic on the first request, which
// would be caught by recoveryMiddleware rather than surfacing at startup.
func NewServer(b backend.Backend, a audit.Auditor, p policy.EngineI, t *auth.TokenService, env string) *Server {
	if b == nil {
		panic("agentkms: NewServer requires a non-nil Backend")
	}
	if a == nil {
		panic("agentkms: NewServer requires a non-nil Auditor")
	}
	if p == nil {
		panic("agentkms: NewServer requires a non-nil policy EngineI")
	}
	if t == nil {
		panic("agentkms: NewServer requires a non-nil TokenService")
	}
	s := &Server{
		backend:               b,
		auditor:               a,
		policy:                p,
		authTokens:            t,
		tokenService:          t,
		env:                   env,
		mux:                   http.NewServeMux(),
		credRateLimitInterval: 60 * time.Second,
	}
	// Pre-seed known credential UUIDs in dev mode for testing.
	if env == "dev" {
		s.credentialUUIDs.Store("550e8400-e29b-41d4-a716-446655440000", false)
	}
	s.registerRoutes()
	return s
}

// ServeHTTP implements http.Handler.  All requests are dispatched through the
// internal mux, which applies the middleware chain to each route.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// auditLog writes ev to the audit sink using a context detached from the
// request context.  This ensures audit events are written even if the caller
// disconnects before the write completes (e.g., client timeout or TCP reset).
//
// SECURITY: every handler must call auditLog (not s.auditor.Log directly)
// to guarantee this invariant.  Bypassing auditLog creates a window where a
// client-disconnect causes a silent audit drop — violating SOC 2 CC7.2 and
// PCI-DSS Req 10.
func (s *Server) auditLog(ctx context.Context, ev audit.AuditEvent) error {
	s.RecordAuditEvent()
	return s.auditor.Log(context.WithoutCancel(ctx), ev)
}

// registerRoutes wires every API route to its handler, wrapped with the
// standard middleware chain: recoveryMiddleware → authMiddleware → handler.
//
// Route table (current stream: C-01 to C-05):
//
//	POST /sign/{keyid...}          C-01  Sign a payload hash
//	POST /encrypt/{keyid...}       C-02  Encrypt plaintext
//	POST /decrypt/{keyid...}       C-03  Decrypt ciphertext
//	GET  /keys                     C-04  List key metadata
//	POST /rotate/{keyid...}        C-05  Rotate a key (stub — 501)
//
// Note on /rotate routing:
//
//	The architecture spec defines the rotate endpoint as
//	POST /keys/{key-id}/rotate.  The standard net/http ServeMux (Go 1.22+)
//	requires {wildcard...} to be at the end of a pattern, so the suffix
//	"/rotate" cannot follow a multi-segment wildcard.  Using
//	POST /rotate/{keyid...} avoids the ambiguity.  The final URL shape will
//	be confirmed when C-05 is fully implemented (backlog C-05, B-01).
//
// Authentication endpoints (/auth/session, /auth/refresh, /auth/revoke) are
// owned by the auth stream (backlog A-06 to A-08) and are not registered here.
func (s *Server) registerRoutes() {
	// wrap applies the full middleware chain to a handler function.
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return s.metricsMiddleware(s.recoveryMiddleware(s.authMiddleware(h)))
	}

	s.mux.HandleFunc("GET /metrics", s.handleMetrics)
	s.mux.HandleFunc("POST /sign/{keyid...}", wrap(s.handleSign))
	s.mux.HandleFunc("POST /encrypt/{keyid...}", wrap(s.handleEncrypt))
	s.mux.HandleFunc("POST /decrypt/{keyid...}", wrap(s.handleDecrypt))
	s.mux.HandleFunc("GET /keys", wrap(s.handleListKeys))

	// C-05: fully implemented — delegates to backend.RotateKey.
	s.mux.HandleFunc("POST /rotate/{keyid...}", wrap(s.handleRotateKey))

	// LV-01: credential vending
	s.mux.HandleFunc("GET /credentials/llm", wrap(s.handleListLLMProviders))
	s.mux.HandleFunc("GET /credentials/llm/{provider}", wrap(s.handleGetLLMCredential))
	s.mux.HandleFunc("POST /credentials/llm/{provider}/refresh", wrap(s.handleRefreshLLMCredential))
	s.mux.HandleFunc("GET /credentials/generic/{path...}", wrap(s.handleGetGenericCredential))

	// Recovery endpoints — /auth/recovery/redeem is unauthenticated (caller is locked out)
	s.mux.HandleFunc("POST /auth/recovery/init", wrap(s.handleRecoveryInit))
	s.mux.HandleFunc("POST /auth/recovery/redeem", s.handleRecoveryRedeem) // no authMiddleware
	s.mux.HandleFunc("GET /auth/recovery/status", wrap(s.handleRecoveryStatus))

	// WebAuthn/FIDO2 endpoints
	s.mux.HandleFunc("POST /auth/webauthn/register/begin", wrap(s.handleWebAuthnRegisterBegin))
	s.mux.HandleFunc("POST /auth/webauthn/register/finish", wrap(s.handleWebAuthnRegisterFinish))
	s.mux.HandleFunc("POST /auth/webauthn/auth/begin", s.handleWebAuthnAuthBegin)   // unauthenticated
	s.mux.HandleFunc("POST /auth/webauthn/auth/finish", s.handleWebAuthnAuthFinish) // unauthenticated
	// AU-10: audit log export
	s.mux.HandleFunc("GET /audit/export", wrap(s.handleExportAuditLogs))

	// FX-05: automated SOC 2 evidence collection
	s.mux.HandleFunc("GET /compliance/soc2", wrap(s.handleSOC2ComplianceExport))

	// LV-06: credential use audit
	s.mux.HandleFunc("POST /audit/use", wrap(s.handleLogCredentialUse))

	// Registry endpoints — KPM Phase 1
	// Note: GET /secrets/{path...}/history conflicts with the wildcard multi-segment
	// pattern in Go 1.22 ServeMux (suffix after {path...} is not supported).
	// History is accessed via ?action=history on the GET /secrets/{path...} handler.
	s.mux.HandleFunc("POST /secrets/{path...}", wrap(s.handleWriteSecret))
	s.mux.HandleFunc("POST /metadata/{path...}", wrap(s.handleWriteMetadata))
	s.mux.HandleFunc("GET /metadata", wrap(s.handleListMetadata))
	s.mux.HandleFunc("GET /metadata/{path...}", wrap(s.handleGetMetadata))
	s.mux.HandleFunc("DELETE /secrets/{path...}", wrap(s.handleDeleteSecret))
	s.mux.HandleFunc("GET /secrets/{path...}", wrap(s.handleGetSecretOrHistory))

	// FO-B2: credential revocation
	s.mux.HandleFunc("POST /credentials/revoke", wrap(s.handleRevokeCredential))

	// FO-C2: detection enrichment
	s.mux.HandleFunc("POST /credentials/detect", wrap(s.handleDetectCredential))

	// T3: credential binding endpoints (OSS)
	s.mux.HandleFunc("POST /bindings", wrap(s.handleRegisterBinding))
	s.mux.HandleFunc("GET /bindings", wrap(s.handleListBindings))
	s.mux.HandleFunc("GET /bindings/{name}", wrap(s.handleGetBinding))
	s.mux.HandleFunc("DELETE /bindings/{name}", wrap(s.handleDeleteBinding))
	s.mux.HandleFunc("POST /bindings/{name}/rotate", wrap(s.handleRotateBinding))
}
