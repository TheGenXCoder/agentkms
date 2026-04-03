// Package main is the agentkms-dev local development server.
//
// agentkms-dev starts a local mTLS server that exposes the full AgentKMS API
// surface using the in-memory DevBackend.  No external dependencies (OpenBao,
// Vault, KMS) are required.
//
// Prerequisites: run `agentkms-dev enroll` first to generate the dev PKI in
// ~/.agentkms/dev/ (or the directory specified by --dir / AGENTKMS_DIR).
//
// Usage:
//
//	agentkms-dev [flags]
//	  --addr   string   Listen address (default: 127.0.0.1:8443)
//	  --dir    string   Cert directory (default: ~/.agentkms/dev)
//	  --audit  string   Audit log file path (default: <dir>/audit.ndjson)
//	  --env    string   Environment tag in audit events (default: "dev")
//
// D-01.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/pkg/tlsutil"
)

func main() {
	if err := run(); err != nil {
		slog.Error("agentkms-dev failed", "error", err.Error())
		os.Exit(1)
	}
}

func run() error {
	// ── Flags ─────────────────────────────────────────────────────────────
	var (
		addrFlag  string
		dirFlag   string
		auditFlag string
		envFlag   string
	)
	flag.StringVar(&addrFlag, "addr", "127.0.0.1:8443", "listen address (host:port)")
	flag.StringVar(&dirFlag, "dir", "", "cert directory (default: ~/.agentkms/dev)")
	flag.StringVar(&auditFlag, "audit", "", "audit log file (default: <dir>/audit.ndjson)")
	flag.StringVar(&envFlag, "env", "dev", "environment tag in audit events")
	flag.Parse()

	// ── Resolve directory ─────────────────────────────────────────────────
	dir, err := resolveDir(dirFlag)
	if err != nil {
		return err
	}

	// ── Set up structured logger ──────────────────────────────────────────
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	slog.Info("agentkms-dev starting",
		"addr", addrFlag,
		"cert_dir", dir,
		"environment", envFlag,
	)

	// ── Load TLS config ───────────────────────────────────────────────────
	caCertPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("reading CA cert from %s: %w\n"+
			"  → Did you run `agentkms-dev enroll` first?", dir, err)
	}
	serverCertPEM, err := os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		return fmt.Errorf("reading server cert from %s: %w", dir, err)
	}
	serverKeyPEM, err := os.ReadFile(filepath.Join(dir, "server.key"))
	if err != nil {
		return fmt.Errorf("reading server key from %s: %w", dir, err)
	}

	tlsCfg, err := tlsutil.LoadServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		return fmt.Errorf("building TLS config: %w", err)
	}
	slog.Info("mTLS configured", "min_tls_version", "TLS 1.3", "client_auth", "RequireAndVerify")

	// ── Set up audit sink ─────────────────────────────────────────────────
	auditPath := auditFlag
	if auditPath == "" {
		auditPath = filepath.Join(dir, "audit.ndjson")
	}
	fileSink, err := audit.NewFileAuditSink(auditPath)
	if err != nil {
		return fmt.Errorf("opening audit log %q: %w", auditPath, err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := fileSink.Flush(ctx); err != nil {
			slog.Error("audit flush on shutdown failed", "error", err.Error())
		}
		fileSink.Close()
	}()

	auditor := audit.NewMultiAuditor(fileSink)
	slog.Info("audit sink ready", "path", auditPath)

	// ── Set up token service ──────────────────────────────────────────────
	revocationList := auth.NewRevocationList()
	tokenSvc, err := auth.NewTokenService(revocationList)
	if err != nil {
		return fmt.Errorf("initialising token service: %w", err)
	}
	slog.Info("token service ready", "ttl", "15m")

	// ── Set up in-memory backend ──────────────────────────────────────────
	devBackend := backend.NewDevBackend()
	// Seed a demo signing key so the dev server has something to work with.
	if err := devBackend.CreateKey("dev/demo-signing-key", backend.AlgorithmES256, "dev"); err != nil {
		return fmt.Errorf("seeding demo key: %w", err)
	}
	slog.Info("dev backend ready (in-memory; keys lost on restart)")

	// ── Build auth handler ────────────────────────────────────────────────
	authHandler := api.NewAuthHandler(tokenSvc, auditor, envFlag)

	// ── Wire routes ───────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// POST /auth/session — mTLS only, no token required.
	mux.HandleFunc("POST /auth/session", authHandler.Session)

	// POST /auth/refresh — requires valid session token.
	mux.Handle("POST /auth/refresh",
		auth.RequireToken(tokenSvc)(http.HandlerFunc(authHandler.Refresh)))

	// POST /auth/revoke — requires valid session token.
	mux.Handle("POST /auth/revoke",
		auth.RequireToken(tokenSvc)(http.HandlerFunc(authHandler.Revoke)))

	// Health check — no auth (used by monitoring and load balancer probes).
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","service":"agentkms-dev"}`)
	})

	_ = devBackend // future handlers (C-01 to C-05) will use this

	// ── Start server ──────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:      addrFlag,
		Handler:   mux,
		TLSConfig: tlsCfg,

		// Timeouts defend against Slowloris and slow-read attacks.
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("agentkms-dev listening",
			"addr", "https://"+addrFlag,
			"endpoints", []string{
				"POST /auth/session",
				"POST /auth/refresh",
				"POST /auth/revoke",
				"GET  /healthz",
			},
		)
		// ListenAndServeTLS with empty cert/key paths: uses srv.TLSConfig.
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "error", err.Error())
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	slog.Info("shutdown complete")
	return nil
}

// resolveDir determines the cert directory, defaulting to ~/.agentkms/dev.
func resolveDir(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if env := os.Getenv("AGENTKMS_DIR"); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determining home directory (use --dir or AGENTKMS_DIR): %w", err)
	}
	return filepath.Join(home, ".agentkms", "dev"), nil
}
