// Package main is the agentkms-dev local development server.
//
// agentkms-dev is a single binary that implements the full production
// AgentKMS API surface using an in-memory backend and a local dev CA.
// It enforces the same mTLS + token lifecycle as production — no shortcuts.
//
// Subcommands:
//
//	agentkms-dev server   — start the local dev server
//	agentkms-dev enroll   — generate local dev CA, server cert, and client cert
//	agentkms-dev key      — key management (create, list)
//
// Backlog: D-01, D-02, D-03, D-04.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/tlsutil"
)

// defaultListenAddr is the default address for the local dev server.
// Bound to loopback only — the dev server must not be reachable from other hosts.
const defaultListenAddr = "127.0.0.1:8200"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "enroll":
		runEnroll(os.Args[2:])
	case "key":
		runKey(os.Args[2:])
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "agentkms-dev: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `agentkms-dev — AgentKMS local development server

Usage:
  agentkms-dev server   [--addr=127.0.0.1:8200]
  agentkms-dev enroll   [--caller-id=<user@dev>] [--team-id=<team>] [--force]
  agentkms-dev key create --name=<keyid> --algorithm=<ES256|AES256GCM|...>
  agentkms-dev key list  [--addr=127.0.0.1:8200]

SECURITY NOTE: The local dev server enforces the same mTLS + token lifecycle
as production. Dev credentials are only trusted by the local dev server and
cannot be used with staging or production instances.

Run 'agentkms-dev enroll' once before starting the server.`)
}

// ── Path helpers ──────────────────────────────────────────────────────────────

// devDir returns the directory where dev certificates are stored.
// Default: ~/.agentkms/dev
func devDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(home, ".agentkms", "dev")
}

// devFile returns the path of a file inside devDir().
func devFile(name string) string {
	return filepath.Join(devDir(), name)
}

// validateLoopbackAddr ensures addr resolves to a loopback interface.
// The dev server must never bind to external interfaces.
func validateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Attempt to resolve hostname (e.g. "localhost") to check if it's loopback.
		resolved, err := net.LookupHost(host)
		if err != nil || len(resolved) == 0 {
			return fmt.Errorf("listen address %q: cannot resolve host %q", addr, host)
		}
		// ALL resolved addresses must be loopback — not just the first one.
		for _, a := range resolved {
			resIP := net.ParseIP(a)
			if resIP == nil || !resIP.IsLoopback() {
				return fmt.Errorf("listen address %q: host %q resolves to non-loopback address %s; "+
					"the dev server must only bind to loopback interfaces", addr, host, a)
			}
		}
		// All addresses are loopback — set ip for the final check below.
		ip = net.ParseIP(resolved[0])
	}
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q must bind to a loopback interface (127.0.0.1 or ::1); "+
			"the dev server must not be reachable from external hosts", addr)
	}
	return nil
}

// devPolicyFile returns the path of the local dev policy file.
// Default: ~/.agentkms/dev-policy.yaml
func devPolicyFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(home, ".agentkms", "dev-policy.yaml")
}

// ── server subcommand ─────────────────────────────────────────────────────────

// runServer starts the local dev server.
//
// Prerequisites: 'agentkms-dev enroll' must have been run to create the
// certificates and default policy file.
//
// SECURITY: This function enforces the same mTLS + token lifecycle as the
// production server.  It is not a dev shortcut — it is the production
// code path running against a local in-memory backend.
func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", defaultListenAddr, "listen address (loopback only; must bind to 127.0.0.1 or ::1)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// SECURITY: Enforce loopback-only binding.  The dev server holds
	// real cryptographic keys and enforces real mTLS, but exposing it
	// to external interfaces increases the attack surface unnecessarily.
	if err := validateLoopbackAddr(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	lg := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// ── Load TLS material ─────────────────────────────────────────────────────
	caCertPEM, err := os.ReadFile(devFile("ca.crt"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read dev CA certificate: %v\n"+
			"Run 'agentkms-dev enroll' first.\n", err)
		os.Exit(1)
	}
	serverCertPEM, err := os.ReadFile(devFile("server.crt"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read server certificate: %v\n"+
			"Run 'agentkms-dev enroll' first.\n", err)
		os.Exit(1)
	}
	serverKeyPEM, err := os.ReadFile(devFile("server.key"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read server key: %v\n"+
			"Run 'agentkms-dev enroll' first.\n", err)
		os.Exit(1)
	}

	// SECURITY: TLS 1.3 minimum, RequireAndVerifyClientCert — no exceptions.
	tlsCfg, err := tlsutil.LoadServerTLSConfig(serverCertPEM, serverKeyPEM, caCertPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: build TLS config: %v\n", err)
		os.Exit(1)
	}

	// ── Load policy ───────────────────────────────────────────────────────────
	pf, err := policy.LoadFromFile(devPolicyFile())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load policy from %s: %v\n"+
			"Run 'agentkms-dev enroll' first.\n", devPolicyFile(), err)
		os.Exit(1)
	}

	// ── Build service components ──────────────────────────────────────────────
	devBe := backend.NewDevBackend()

	ts, err := auth.NewTokenStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create token store: %v\n", err)
		os.Exit(1)
	}

	// Audit log: append-only NDJSON file.  Mode 0600 — may contain IP
	// addresses and session identifiers.
	auditLogPath := devFile("audit.log")
	auditSink, err := audit.NewFileAuditSink(auditLogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create audit log at %s: %v\n", auditLogPath, err)
		os.Exit(1)
	}

	srv := api.NewServer(api.Config{
		Backend:     devBe,
		Auditor:     auditSink,
		Tokens:      ts,
		Policy:      policy.NewEngine(pf),
		Environment: "dev",
		Logger:      lg,
	})

	// ── Background goroutines ─────────────────────────────────────────────────

	// Token revocation list purge: removes expired entries to bound memory.
	var wg sync.WaitGroup
	purgeDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(auth.TokenTTL)
		defer ticker.Stop()
		for {
			select {
			case <-purgeDone:
				return
			case <-ticker.C:
				ts.PurgeExpired()
			}
		}
	}()

	// ── Start mTLS listener ───────────────────────────────────────────────────
	ln, err := tls.Listen("tcp", *addr, tlsCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: listen on %s: %v\n", *addr, err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Handler:      srv.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	lg.Info("agentkms-dev server started",
		"addr", ln.Addr().String(),
		"tls", "mTLS TLS 1.3",
		"backend", "in-memory",
		"policy", devPolicyFile(),
		"audit_log", auditLogPath,
	)

	// ── Signal handling and graceful shutdown ─────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpSrv.Serve(ln)
	}()

	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			lg.Error("server terminated unexpectedly", "error", err)
			os.Exit(1)
		}
	case sig := <-sigCh:
		lg.Info("shutdown signal received", "signal", sig.String())
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			lg.Warn("graceful shutdown did not complete cleanly", "error", err)
		}
	}

	// Stop background goroutines.
	close(purgeDone)
	wg.Wait()

	// Flush and close the audit log before exiting so no events are lost.
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer flushCancel()
	if err := auditSink.Flush(flushCtx); err != nil {
		lg.Warn("audit flush on shutdown", "error", err)
	}
	if err := auditSink.Close(); err != nil {
		lg.Warn("audit close on shutdown", "error", err)
	}

	lg.Info("agentkms-dev server stopped")
}

// ── enroll subcommand ─────────────────────────────────────────────────────────

// runEnroll generates the local dev CA, server certificate, and client
// certificate, then writes a default policy file.
//
// File layout written:
//
//	~/.agentkms/dev/ca.crt     — dev CA certificate (0644)
//	~/.agentkms/dev/ca.key     — dev CA private key  (0400 — most restrictive)
//	~/.agentkms/dev/server.crt — server certificate  (0644)
//	~/.agentkms/dev/server.key — server private key  (0600)
//	~/.agentkms/dev/client.crt — developer cert      (0644)
//	~/.agentkms/dev/client.key — developer private key (0600)
//	~/.agentkms/dev-policy.yaml — default policy      (0600)
//
// SECURITY: Private key files are written with restrictive permissions.
// The CA key is 0400 (read-only for the owner) because it is the most
// sensitive file — it can issue new identities.
func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	callerID := fs.String("caller-id", "", "developer identity (CN) for client cert, e.g. alice@dev")
	teamID   := fs.String("team-id", "dev-team", "team identifier (O) for client cert")
	force    := fs.Bool("force", false, "overwrite existing certificates and policy")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Default caller-id: $USER@dev
	if *callerID == "" {
		username := os.Getenv("USER")
		if username == "" {
			username = "developer"
		}
		*callerID = username + "@dev"
	}

	// Ensure ~/.agentkms/dev/ exists with restricted permissions.
	dir := devDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "error: create dev directory %q: %v\n", dir, err)
		os.Exit(1)
	}

	// ── CA generation (or reuse) ──────────────────────────────────────────────
	caCertPath := devFile("ca.crt")
	caKeyPath  := devFile("ca.key")

	var caCertPEM, caKeyPEM []byte

	if !*force {
		if existingCert, err := os.ReadFile(caCertPath); err == nil {
			existingKey, err2 := os.ReadFile(caKeyPath)
			if err2 == nil {
				caCertPEM = existingCert
				caKeyPEM  = existingKey
				fmt.Println("Reusing existing dev CA (use --force to regenerate).")
			}
		}
	}

	if caCertPEM == nil {
		var err error
		caCertPEM, caKeyPEM, err = tlsutil.GenerateDevCA()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: generate dev CA: %v\n", err)
			os.Exit(1)
		}
		// CA cert: 0644 (readable by tools that need to trust it)
		if err := writeFileSecret(caCertPath, caCertPEM, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error: write CA certificate: %v\n", err)
			os.Exit(1)
		}
		// CA key: 0400 (read-only for owner) — never transmit this file
		if err := writeFileSecret(caKeyPath, caKeyPEM, 0400); err != nil {
			fmt.Fprintf(os.Stderr, "error: write CA key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated dev CA:          %s\n", caCertPath)
		// SECURITY: Do NOT print the CA key path with any content hint.
	}

	// ── Server certificate ────────────────────────────────────────────────────
	serverCertPEM, serverKeyPEM, err := tlsutil.IssueServerCert(caCertPEM, caKeyPEM, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: issue server certificate: %v\n", err)
		os.Exit(1)
	}
	if err := writeFileSecret(devFile("server.crt"), serverCertPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write server certificate: %v\n", err)
		os.Exit(1)
	}
	if err := writeFileSecret(devFile("server.key"), serverKeyPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error: write server key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Generated server certificate: %s\n", devFile("server.crt"))

	// ── Client certificate ────────────────────────────────────────────────────
	// The SPIFFE URI encodes the developer's identity in a machine-verifiable form.
	spiffeURI := fmt.Sprintf("spiffe://agentkms.local/dev/developer/%s", *callerID)
	clientCertPEM, clientKeyPEM, err := tlsutil.IssueClientCert(
		caCertPEM, caKeyPEM,
		*callerID, *teamID, "developer",
		spiffeURI,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: issue client certificate: %v\n", err)
		os.Exit(1)
	}
	if err := writeFileSecret(devFile("client.crt"), clientCertPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write client certificate: %v\n", err)
		os.Exit(1)
	}
	if err := writeFileSecret(devFile("client.key"), clientKeyPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error: write client key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Generated client certificate: %s (identity: %s)\n",
		devFile("client.crt"), *callerID)

	// ── Default policy ────────────────────────────────────────────────────────
	pfPath := devPolicyFile()
	if _, err := os.Stat(pfPath); err == nil && !*force {
		fmt.Printf("Policy file already exists (%s); not overwriting (use --force).\n", pfPath)
	} else {
		pf := policy.DefaultDevPolicy(*callerID, *teamID)
		policyData, err := policy.MarshalYAML(pf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: marshal default policy: %v\n", err)
			os.Exit(1)
		}
		if err := writeFileSecret(pfPath, policyData, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error: write policy file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Written default policy:      %s\n", pfPath)
	}

	fmt.Printf(`
Enrollment complete.

  Identity:  %s
  Team:      %s
  Cert dir:  %s/

Next steps:
  1. agentkms-dev server            # start the local dev server
  2. agentkms-dev key create --name=personal/my-key --algorithm=ES256
  3. agentkms-dev key list
`, *callerID, *teamID, dir)
}

// ── key subcommand ────────────────────────────────────────────────────────────

func runKey(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentkms-dev key <create|list>")
		os.Exit(1)
	}
	switch args[0] {
	case "create":
		runKeyCreate(args[1:])
	case "list":
		runKeyList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "agentkms-dev key: unknown subcommand %q\n", args[0])
		os.Exit(1)
	}
}

func runKeyCreate(args []string) {
	fs := flag.NewFlagSet("key create", flag.ExitOnError)
	keyName   := fs.String("name", "", "key identifier, e.g. personal/my-signing-key (required)")
	algorithm := fs.String("algorithm", "ES256", "algorithm: ES256 | EdDSA | RS256 | AES256GCM | RSA_OAEP_SHA256")
	addr      := fs.String("addr", defaultListenAddr, "dev server address")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *keyName == "" {
		fmt.Fprintln(os.Stderr, "error: --name is required")
		os.Exit(1)
	}

	c, token, err := newDevClient(*addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error connecting to dev server: %v\n"+
			"Is 'agentkms-dev server' running?\n", err)
		os.Exit(1)
	}
	defer c.revokeSession(token)

	reqBody, _ := json.Marshal(map[string]string{
		"key_id":    *keyName,
		"algorithm": *algorithm,
	})
	respBody, err := c.post("/keys", token, reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: key create: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(prettyJSON(respBody))
}

func runKeyList(args []string) {
	fs := flag.NewFlagSet("key list", flag.ExitOnError)
	addr := fs.String("addr", defaultListenAddr, "dev server address")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	c, token, err := newDevClient(*addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error connecting to dev server: %v\n"+
			"Is 'agentkms-dev server' running?\n", err)
		os.Exit(1)
	}
	defer c.revokeSession(token)

	respBody, err := c.get("/keys", token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: key list: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(prettyJSON(respBody))
}

// ── mTLS HTTP client ──────────────────────────────────────────────────────────

// devHTTPClient is a thin mTLS HTTP client for the local dev server.
// It holds an authenticated session (Bearer token) and provides helpers for
// GET and POST requests.
type devHTTPClient struct {
	hc      *http.Client
	baseURL string
}

// newDevClient builds a devHTTPClient for the given server address, connects
// using the developer's mTLS certificate, and authenticates via /auth/session.
// Returns the client and the Bearer token for use in subsequent requests.
//
// The caller must call revokeSession(token) when done to clean up the
// server-side session.
func newDevClient(addr string) (*devHTTPClient, string, error) {
	caCertPEM, err := os.ReadFile(devFile("ca.crt"))
	if err != nil {
		return nil, "", fmt.Errorf("read CA cert: %w — run 'agentkms-dev enroll' first", err)
	}
	clientCertPEM, err := os.ReadFile(devFile("client.crt"))
	if err != nil {
		return nil, "", fmt.Errorf("read client cert: %w", err)
	}
	clientKeyPEM, err := os.ReadFile(devFile("client.key"))
	if err != nil {
		return nil, "", fmt.Errorf("read client key: %w", err)
	}

	tlsCfg, err := tlsutil.LoadClientTLSConfig(clientCertPEM, clientKeyPEM, caCertPEM)
	if err != nil {
		return nil, "", fmt.Errorf("build TLS config: %w", err)
	}

	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		Timeout: 30 * time.Second,
	}

	baseURL := "https://" + addr
	c := &devHTTPClient{hc: hc, baseURL: baseURL}

	// Authenticate: mTLS cert → session token (15min TTL).
	sessResp, err := hc.Post(baseURL+"/auth/session", "application/json", nil)
	if err != nil {
		return nil, "", fmt.Errorf("POST /auth/session: %w", err)
	}
	defer sessResp.Body.Close()

	if sessResp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(sessResp.Body, 512))
		return nil, "", fmt.Errorf("/auth/session: HTTP %d: %s",
			sessResp.StatusCode, strings.TrimSpace(string(errBody)))
	}

	var sr struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(sessResp.Body).Decode(&sr); err != nil {
		return nil, "", fmt.Errorf("decode session response: %w", err)
	}
	if sr.Token == "" {
		return nil, "", fmt.Errorf("/auth/session: empty token in response")
	}

	return c, sr.Token, nil
}

func (c *devHTTPClient) get(path, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (c *devHTTPClient) post(path, token string, body []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", c.baseURL+path,
		strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

// revokeSession calls POST /auth/revoke to invalidate the session token
// server-side.  Best-effort: errors are silently ignored (the token will
// expire naturally within 15 minutes regardless).
func (c *devHTTPClient) revokeSession(token string) {
	if token == "" {
		return
	}
	req, err := http.NewRequest("POST", c.baseURL+"/auth/revoke", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.hc.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// ── File helpers ──────────────────────────────────────────────────────────────

// writeFileSecret atomically writes data to path with the given permissions.
// It uses a temp file + rename to avoid partial writes.
//
// SECURITY: perm should be 0600 for private keys, 0644 for certificates,
// and 0400 for the CA private key (which is the most sensitive file).
func writeFileSecret(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".agentkms-write-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()

	// Ensure the temp file is removed if we don't succeed in renaming it.
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write to temp file: %w", err)
	}
	// Sync before rename so data is durable.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	// Set permissions before rename — chmod after rename has a TOCTOU window.
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	success = true
	return nil
}

// prettyJSON pretty-prints a JSON byte slice.  Returns the original input as
// a string on any parsing error.
func prettyJSON(b []byte) string {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(b)
	}
	return string(out)
}
