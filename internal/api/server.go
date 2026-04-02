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
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
)

// Server holds all dependencies for the AgentKMS HTTP API.
// It is constructed once at startup and is safe for concurrent use.
type Server struct {
	backend backend.Backend
	auditor audit.Auditor
	tokens  *auth.TokenStore
	policy  *policy.Engine
	env     string
	logger  *slog.Logger
}

// Config configures a Server.
type Config struct {
	// Backend performs all cryptographic operations.  Required.
	Backend backend.Backend

	// Auditor receives every audit event.  Required.
	Auditor audit.Auditor

	// Tokens manages session token issuance, validation, and revocation.  Required.
	Tokens *auth.TokenStore

	// Policy is the evaluated policy engine.  Required.
	Policy *policy.Engine

	// Environment is the deployment tier label written into audit events.
	// Defaults to "dev".
	Environment string

	// Logger is the structured logger for operational messages.
	// Defaults to slog.Default().
	Logger *slog.Logger
}

// NewServer creates a Server from cfg and returns it.
// Panics if any required field is nil.
func NewServer(cfg Config) *Server {
	if cfg.Backend == nil {
		panic("api: Config.Backend must not be nil")
	}
	if cfg.Auditor == nil {
		panic("api: Config.Auditor must not be nil")
	}
	if cfg.Tokens == nil {
		panic("api: Config.Tokens must not be nil")
	}
	if cfg.Policy == nil {
		panic("api: Config.Policy must not be nil")
	}

	env := cfg.Environment
	if env == "" {
		env = "dev"
	}
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}

	return &Server{
		backend: cfg.Backend,
		auditor: cfg.Auditor,
		tokens:  cfg.Tokens,
		policy:  cfg.Policy,
		env:     env,
		logger:  lg,
	}
}

// Handler builds and returns the http.Handler with all routes registered.
//
// Route summary:
//
//	POST /auth/session              — mTLS cert auth; issues session token
//	POST /auth/refresh              — token auth; issues new token
//	POST /auth/revoke               — token auth; revokes current token
//
//	POST /sign/{keyid...}           — token + policy; returns signature
//	POST /encrypt/{keyid...}        — token + policy; returns ciphertext
//	POST /decrypt/{keyid...}        — token + policy; returns plaintext
//
//	GET  /keys                      — token + policy; returns key metadata list
//	POST /keys/rotate/{keyid...}    — token + policy; rotates key
//	POST /keys                      — token + policy; creates key (dev only)
//
//	GET  /healthz                   — no auth; returns {"status":"ok"}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// ── Auth endpoints ────────────────────────────────────────────────────────
	// /auth/session: identity comes from the mTLS client cert — no token needed.
	mux.HandleFunc("POST /auth/session", s.handleAuthSession)

	// Remaining auth endpoints require a valid Bearer token.
	mux.Handle("POST /auth/refresh", s.requireToken(http.HandlerFunc(s.handleAuthRefresh)))
	mux.Handle("POST /auth/revoke", s.requireToken(http.HandlerFunc(s.handleAuthRevoke)))

	// ── Crypto operation endpoints ────────────────────────────────────────────
	// {keyid...} matches the rest of the path, enabling hierarchical key IDs
	// such as "payments/signing-key" → path "/sign/payments/signing-key".
	// Note: ServeMux wildcard names must be valid Go identifiers (no hyphens).
	mux.Handle("POST /sign/{keyid...}", s.requireToken(http.HandlerFunc(s.handleSign)))
	mux.Handle("POST /encrypt/{keyid...}", s.requireToken(http.HandlerFunc(s.handleEncrypt)))
	mux.Handle("POST /decrypt/{keyid...}", s.requireToken(http.HandlerFunc(s.handleDecrypt)))

	// ── Key management endpoints ──────────────────────────────────────────────
	// GET /keys must be registered before POST /keys to avoid ambiguity.
	mux.Handle("GET /keys", s.requireToken(http.HandlerFunc(s.handleListKeys)))
	mux.Handle("POST /keys/rotate/{keyid...}", s.requireToken(http.HandlerFunc(s.handleRotateKey)))

	// Key creation is available in dev mode only.  In production, keys are
	// created via the backend admin interface (OpenBao/KMS console).
	if s.env == "dev" {
		mux.Handle("POST /keys", s.requireToken(http.HandlerFunc(s.handleCreateKey)))
	}

	// ── Health check ──────────────────────────────────────────────────────────
	// No authentication — used by process supervisors (Kubernetes probes, load
	// balancers, monitoring) that are not part of the mTLS PKI.
	// Architecture §4.1: "/healthz — no auth; returns {\"status\":\"ok\"}".
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Wrap the mux with a global body size limit so no individual handler
	// needs to remember http.MaxBytesReader.  Bounds memory for all endpoints.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		mux.ServeHTTP(w, r)
	})
}

// ── Response helpers ──────────────────────────────────────────────────────────

// writeError writes a JSON error response.  The message is sent to the caller
// as-is; it must not contain key material, stack traces, or token values.
func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: msg})
}

// writeJSON writes a JSON success response with HTTP 200.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONStatus writes a JSON response with the given HTTP status code.
func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// sourceIP extracts the caller's IP address (without port) from r.RemoteAddr.
func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // fallback: return as-is
	}
	return host
}

// maxRequestBodyBytes is the ceiling for request bodies on all endpoints.
// Prevents a single authenticated caller from exhausting server memory by
// sending a large plaintext to /encrypt or a crafted body to any other endpoint.
// 1 MiB is generous for all legitimate AgentKMS payloads:
//   - /sign: payload_hash + algorithm  ≈ 200 bytes
//   - /encrypt: plaintext (base64)     ≤ 1 MiB
//   - /keys: key creation request      ≈ 200 bytes
//   - /auth/*: token string            ≈ 500 bytes
const maxRequestBodyBytes = 1 << 20 // 1 MiB

// auditWriteTimeout is the maximum time logAudit will wait for the audit sink.
// Must be long enough for fsync on a local file, short enough to not block
// request goroutines indefinitely.
const auditWriteTimeout = 5 * time.Second

// logAudit writes ev to the server's auditor.
//
// SECURITY: This method deliberately does NOT use the request context.
// r.Context() is cancelled when the client disconnects.  Using it would
// cause audit events to be silently lost for any operation where the client
// disconnected before the handler returned — an unacceptable audit gap for
// a compliance service.  Instead, logAudit uses a fresh background context
// with a fixed timeout, so audit writes are always attempted regardless of
// client connection state.
func (s *Server) logAudit(_ *http.Request, ev audit.AuditEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
	defer cancel()
	// Log writes and fsyncs the event (FileAuditSink.Log calls Sync internally).
	// A separate Flush() call is NOT made here — that would double-fsync every
	// event.  Flush is called once at graceful shutdown to drain any buffered
	// events and guarantee durability.
	if err := s.auditor.Log(ctx, ev); err != nil {
		s.logger.Warn("audit write failed",
			"event_id", ev.EventID,
			"operation", ev.Operation,
			"error", err.Error())
	}
}

// handleHealthz is a simple liveness endpoint.  It returns 200 with a static
// body.  No authentication is required.  It must not expose version details,
// internal state, or configuration.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}
