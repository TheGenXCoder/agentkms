// Package main is the AgentKMS production server.
//
// Reads configuration from /etc/agentkms/config.yaml and a Vault Agent token
// from AGENTKMS_VAULT_TOKEN_PATH.  Connects to OpenBao via the configured
// address and serves the AgentKMS API on :8200.
//
// Deployment: Kubernetes, injected by Vault Agent init container.
// See deploy/helm/agentkms/ for the Helm chart.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/tlsutil"
)

const (
	defaultVaultPolicyPath = "" // empty = use local file only
)

const (
	defaultListenAddr  = ":8200"
	defaultConfigPath  = "/etc/agentkms/config.yaml"
	defaultTokenPath   = "/vault/secrets/token"
	defaultAuditLog    = "/tmp/audit.log"
	defaultEnvironment = "production"
	shutdownTimeout    = 30 * time.Second
	defaultELKAddr     = ""
)

func main() {
	// ── Flags ─────────────────────────────────────────────────────────────────
	addr       := flag.String("addr", envOr("AGENTKMS_ADDR", defaultListenAddr), "Listen address")
	configPath := flag.String("config", envOr("AGENTKMS_CONFIG", defaultConfigPath), "Config file path")
	tokenPath  := flag.String("token-path", envOr("AGENTKMS_VAULT_TOKEN_PATH", defaultTokenPath), "Vault token file path")
	vaultAddr  := flag.String("vault-addr", envOr("AGENTKMS_VAULT_ADDR", ""), "OpenBao/Vault address")
	policyFile  := flag.String("policy", envOr("AGENTKMS_POLICY", ""), "Policy YAML file (optional; empty = deny all)")
	vaultPolicyPath := flag.String("vault-policy-path", envOr("AGENTKMS_VAULT_POLICY_PATH", ""), "Vault KV path for policy (e.g. policy/production); overrides --policy")
	vaultPolicyReload := flag.Duration("vault-policy-reload", 60*time.Second, "How often to reload policy from Vault KV")
	auditLog   := flag.String("audit-log", envOr("AGENTKMS_AUDIT_LOG", defaultAuditLog), "Audit log file path")
	elkAddr    := flag.String("elk-addr", envOr("AGENTKMS_ELK_ADDR", defaultELKAddr), "Elasticsearch address (optional)")
	elkIndex   := flag.String("elk-index", envOr("AGENTKMS_ELK_INDEX", "agentkms-audit"), "Elasticsearch index")
	env        := flag.String("env", envOr("AGENTKMS_ENV", defaultEnvironment), "Deployment environment")
	tlsCert    := flag.String("tls-cert", envOr("AGENTKMS_TLS_CERT", ""), "Server TLS certificate path (required in production)")
	tlsKey     := flag.String("tls-key", envOr("AGENTKMS_TLS_KEY", ""), "Server TLS key path (required in production)")
	vaultCert  := flag.String("vault-tls-cert", envOr("AGENTKMS_VAULT_TLS_CERT", ""), "Client TLS cert for Vault/OpenBao")
	vaultKey   := flag.String("vault-tls-key", envOr("AGENTKMS_VAULT_TLS_KEY", ""), "Client TLS key for Vault/OpenBao")
	vaultCA    := flag.String("vault-tls-ca", envOr("AGENTKMS_VAULT_TLS_CA", ""), "CA certificate for Vault/OpenBao")
	flag.Parse()

	// ── Logger ─────────────────────────────────────────────────────────────────
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	if *env == "production" {
		if *tlsCert == "" || *tlsKey == "" {
			slog.Error("server TLS is required in production (--tls-cert, --tls-key)")
			os.Exit(1)
		}
	}

	slog.Info("agentkms starting",
		"addr", *addr,
		"env", *env,
		"vault_addr", *vaultAddr,
		"policy_file", *policyFile,
	)

	// ── Audit sink ─────────────────────────────────────────────────────────────
	fileSink, err := audit.NewFileAuditSink(*auditLog)
	if err != nil {
		slog.Error("failed to open audit log", "path", *auditLog, "error", err)
		os.Exit(1)
	}
	signer, err := audit.NewEventSigner()
	if err != nil {
		slog.Error("failed to create audit event signer", "error", err)
		os.Exit(1)
	}
	signingAuditor := audit.NewSigningAuditor(fileSink, signer)

	var auditorSinks []audit.Auditor
	auditorSinks = append(auditorSinks, signingAuditor)

	// Wire ELK sink if configured.
	if *elkAddr != "" {
		ctx := context.Background()
		elkSink, err := audit.NewELKAuditSink(ctx, audit.ELKConfig{
			Address:       *elkAddr,
			Index:         *elkIndex,
			BufferSize:    50,
			FlushInterval: 5 * time.Second,
		})
		if err != nil {
			slog.Error("failed to create ELK audit sink", "addr", *elkAddr, "error", err)
			os.Exit(1)
		}
		auditorSinks = append(auditorSinks, audit.NewSigningAuditor(elkSink, signer))
		slog.Info("ELK audit sink ready", "addr", *elkAddr, "index", *elkIndex)
	}

	auditor := audit.NewMultiAuditor(auditorSinks...)

	slog.Info("audit sink ready", "path", *auditLog)

	// ── Vault mTLS ─────────────────────────────────────────────────────────────
	var vaultTLS *tls.Config
	if *vaultCert != "" && *vaultKey != "" && *vaultCA != "" {
		vaultCABytes, err := os.ReadFile(*vaultCA)
		if err != nil {
			slog.Error("failed to read vault ca", "error", err)
			os.Exit(1)
		}
		vaultCertBytes, err := os.ReadFile(*vaultCert)
		if err != nil {
			slog.Error("failed to read vault cert", "error", err)
			os.Exit(1)
		}
		vaultKeyBytes, err := os.ReadFile(*vaultKey)
		if err != nil {
			slog.Error("failed to read vault key", "error", err)
			os.Exit(1)
		}
		vaultTLS, err = tlsutil.ClientTLSConfig(vaultCABytes, vaultCertBytes, vaultKeyBytes)
		if err != nil {
			slog.Error("failed to build vault tls config", "error", err)
			os.Exit(1)
		}
		slog.Info("vault client mtls configured")
	} else if *env == "production" && *vaultAddr != "" {
		slog.Warn("vault mtls not configured in production")
	}

	// ── Backend ────────────────────────────────────────────────────────────────
	var bknd backend.Backend

	// Read the Vault token once — used by backend, policy loader, and credential vender.
	var vaultToken string
	if *vaultAddr != "" {
		var err error
		vaultToken, err = readToken(*tokenPath)
		if err != nil {
			slog.Error("failed to read vault token", "path", *tokenPath, "error", err)
			os.Exit(1)
		}

		cfg := backend.OpenBaoConfig{
			Address:   *vaultAddr,
			Token:     vaultToken,
			TLSConfig: vaultTLS,
		}
		// Read mount paths from config if provided, otherwise use defaults.
		if mountTransit, mountKV := mountsFromConfig(*configPath); mountTransit != "" {
			cfg.MountPath = mountTransit
			_ = mountKV // KV mount used by LV stream (LV-01)
		}

		ob, err := backend.NewOpenBaoBackend(cfg)
		if err != nil {
			slog.Error("failed to create OpenBao backend", "error", err)
			os.Exit(1)
		}
		bknd = ob
		slog.Info("backend: OpenBao", "addr", *vaultAddr)
	} else {
		// No Vault address — fall back to dev backend for local testing.
		slog.Warn("AGENTKMS_VAULT_ADDR not set — using in-memory dev backend (not for production)")
		bknd = backend.NewDevBackend()
	}

	// ── Policy engine ──────────────────────────────────────────────────────────
	var eng policy.EngineI

	if *vaultPolicyPath != "" && *vaultAddr != "" {
		// Load policy from Vault KV (with optional local fallback).
		loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
			Address:           *vaultAddr,
			Token:             vaultToken,
			TLSConfig:         vaultTLS,
			PolicyPath:        *vaultPolicyPath,
			LocalFallbackPath: *policyFile,
			ReloadInterval:    *vaultPolicyReload,
		})
		if err := loader.Load(context.Background()); err != nil {
			slog.Error("failed to load policy from Vault KV", "path", *vaultPolicyPath, "error", err)
			os.Exit(1)
		}
		eng = loader.EngineI()
		slog.Info("policy loaded from Vault KV",
			"path", *vaultPolicyPath,
			"reload_interval", vaultPolicyReload.String())
	} else if *policyFile != "" {
		p, err := policy.LoadFromFile(*policyFile)
		if err != nil {
			slog.Error("failed to load policy", "path", *policyFile, "error", err)
			os.Exit(1)
		}
		eng = policy.AsEngineI(policy.New(*p))
		slog.Info("policy loaded from file", "path", *policyFile)
	} else {
		slog.Warn("no policy configured — all operations denied by default")
		eng = policy.DenyAllEngine{}
	}

	// ── HTTP server ────────────────────────────────────────────────────────────
	// ── Credential vender ─────────────────────────────────────────────────────
	apiServer := api.NewServer(bknd, auditor, eng, *env)
	if *vaultAddr != "" {
		kv := credentials.NewOpenBaoKV(*vaultAddr, vaultToken, vaultTLS)
		apiServer.SetVender(credentials.NewVender(kv, "kv"))
		slog.Info("credential vender ready")
	}

	mux := http.NewServeMux()
	mux.Handle("/", apiServer)
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/readyz", handleReadyz)

	httpServer := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		// TLS is configured by Vault Agent / cert-manager in production.
		// For T1 POC: plain HTTP inside the cluster (mTLS at ingress layer).
	}

	// ── Listener ───────────────────────────────────────────────────────────────
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("failed to bind", "addr", *addr, "error", err)
		os.Exit(1)
	}

	// ── Signal handling + graceful shutdown ────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	errCh := make(chan error, 1)
	go func() {
		if *tlsCert != "" && *tlsKey != "" {
			slog.Info("listening (TLS)", "addr", ln.Addr().String())
			if err := httpServer.ServeTLS(ln, *tlsCert, *tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("http server (tls): %w", err)
			}
		} else {
			slog.Warn("listening (PLAIN HTTP)", "addr", ln.Addr().String())
			if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("http server: %w", err)
			}
		}
	}()

	select {
	case sig := <-sigCh:
		slog.Info("received signal, shutting down", "signal", sig)
	case err := <-errCh:
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
	}

	// Flush audit buffer before exit.
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer flushCancel()
	if err := auditor.Flush(flushCtx); err != nil {
		slog.Error("audit flush failed on shutdown", "error", err)
	}

	slog.Info("shutdown complete")
}

// ── Health endpoints ──────────────────────────────────────────────────────────

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func handleReadyz(w http.ResponseWriter, _ *http.Request) {
	// TODO(T2): check backend connectivity, policy load status, token validity.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func readToken(path string) (string, error) {
	// Vault Agent writes the token to a file; re-read on every use for
	// token rotation support.  For the initial read at startup, this is fine.
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("reading token from %s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// mountsFromConfig reads transit and KV mount paths from the config file.
// Returns empty strings if the file cannot be parsed (caller uses defaults).
func mountsFromConfig(path string) (transitMount, kvMount string) {
	if path == "" {
		return "", ""
	}
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", ""
	}
	// Minimal YAML parsing — avoid importing yaml package in this binary's
	// hot path.  The full config reader is deferred to a follow-up (T2 config
	// management).  For now, extract the two paths with simple string search.
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "transit_mount:") {
			transitMount = strings.TrimSpace(strings.TrimPrefix(line, "transit_mount:"))
			transitMount = strings.Trim(transitMount, `"'`)
		}
		if strings.HasPrefix(line, "kv_mount:") {
			kvMount = strings.TrimSpace(strings.TrimPrefix(line, "kv_mount:"))
			kvMount = strings.Trim(kvMount, `"'`)
		}
	}
	return transitMount, kvMount
}
