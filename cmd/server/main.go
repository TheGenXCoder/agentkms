// Package main is the AgentKMS production server entrypoint.
//
// Wiring status (see docs/backlog.md for tracking):
//
//	API handlers    — [~] C-01 to C-04 implemented; C-05 stub (501)
//	Auth middleware — TODO(A-04): replace stub with real token validation
//	Backend         — TODO(B-01): wire OpenBao once internal/backend/openbao.go is ready
//	Policy engine   — TODO(P-03): wire real engine once P-01 to P-04 complete
//	Audit sink      — file sink available; ELK/Splunk in backlog AU-02 to AU-08
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("agentkms: %v", err)
	}
}

func run() error {
	// ── Audit sink ─────────────────────────────────────────────────────────
	// T0: local file sink.  T1+: swap for MultiAuditor with ELK/Splunk.
	auditLogPath := envOr("AGENTKMS_AUDIT_LOG", "/var/log/agentkms/audit.jsonl")
	fileSink, err := audit.NewFileAuditSink(auditLogPath)
	if err != nil {
		return fmt.Errorf("opening audit log %q: %w", auditLogPath, err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = fileSink.Flush(ctx)
		_ = fileSink.Close()
	}()
	auditor := audit.NewMultiAuditor(fileSink)

	// ── Backend ────────────────────────────────────────────────────────────
	// TODO(B-01): Replace DevBackend with the OpenBao backend once
	// internal/backend/openbao.go is implemented.  DevBackend is in-memory
	// only and loses all keys on process restart.
	//
	// Future wiring:
	//   bao, err := backend.NewOpenBaoBackend(openBaoConfig)
	//   if err != nil { return fmt.Errorf("openbao backend: %w", err) }
	//   activeBackend = bao
	log.Println("[WARN] using in-memory DevBackend — TODO(B-01): wire OpenBao backend")
	activeBackend := backend.NewDevBackend()

	// ── Policy engine ──────────────────────────────────────────────────────
	// TODO(P-03): Replace DenyAllEngine with the real policy engine once
	// internal/policy/engine.go (P-01 to P-04) is complete.
	//
	// DenyAllEngine is the correct safe default: nothing is permitted until
	// an operator configures explicit allow rules.
	log.Println("[WARN] using DenyAllEngine — TODO(P-03): wire real policy engine")
	policyEngine := policy.DenyAllEngine{}

	// ── HTTP server ─────────────────────────────────────────────────────────
	// TODO(A-01): Wrap with mTLS (pkg/tlsutil/server.go, backlog A-01).
	// The Server struct and API handlers are ready; the TLS layer wraps the
	// http.Server externally.
	srv := api.NewServer(activeBackend, auditor, policyEngine, envOr("AGENTKMS_ENV", "production"))

	addr := envOr("AGENTKMS_ADDR", ":8443")
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      srv,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("agentkms: listening on %s (env=%s)", addr, envOr("AGENTKMS_ENV", "production"))
		// TODO(A-01): Replace ListenAndServe with ListenAndServeTLS once
		// mTLS is wired.  All traffic must use TLS 1.3+ with client cert
		// verification.
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("agentkms: ListenAndServe: %v", err)
		}
	}()

	<-quit
	log.Println("agentkms: shutdown signal received")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Println("agentkms: shutdown complete")
	return nil
}

// envOr returns the value of the named environment variable, or fallback if
// the variable is unset or empty.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
