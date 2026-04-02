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
	"net/http"

	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
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
	backend backend.Backend
	auditor audit.Auditor
	policy  policy.Engine

	// env identifies the deployment tier for audit events.
	// Values: "production", "staging", "dev".
	env string

	mux *http.ServeMux
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
func NewServer(b backend.Backend, a audit.Auditor, p policy.Engine, env string) *Server {
	if b == nil {
		panic("agentkms: NewServer requires a non-nil Backend")
	}
	if a == nil {
		panic("agentkms: NewServer requires a non-nil Auditor")
	}
	if p == nil {
		panic("agentkms: NewServer requires a non-nil policy Engine")
	}
	s := &Server{
		backend: b,
		auditor: a,
		policy:  p,
		env:     env,
		mux:     http.NewServeMux(),
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
//   The architecture spec defines the rotate endpoint as
//   POST /keys/{key-id}/rotate.  The standard net/http ServeMux (Go 1.22+)
//   requires {wildcard...} to be at the end of a pattern, so the suffix
//   "/rotate" cannot follow a multi-segment wildcard.  Using
//   POST /rotate/{keyid...} avoids the ambiguity.  The final URL shape will
//   be confirmed when C-05 is fully implemented (backlog C-05, B-01).
//
// Authentication endpoints (/auth/session, /auth/refresh, /auth/revoke) are
// owned by the auth stream (backlog A-06 to A-08) and are not registered here.
func (s *Server) registerRoutes() {
	// wrap applies the full middleware chain to a handler function.
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return s.recoveryMiddleware(s.authMiddleware(h))
	}

	s.mux.HandleFunc("POST /sign/{keyid...}", wrap(s.handleSign))
	s.mux.HandleFunc("POST /encrypt/{keyid...}", wrap(s.handleEncrypt))
	s.mux.HandleFunc("POST /decrypt/{keyid...}", wrap(s.handleDecrypt))
	s.mux.HandleFunc("GET /keys", wrap(s.handleListKeys))

	// C-05 stub: returns 501 until B-01 (OpenBao backend) is wired.
	s.mux.HandleFunc("POST /rotate/{keyid...}", wrap(s.handleRotateKeyStub))
}
