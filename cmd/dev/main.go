// Package main is the agentkms-dev local development server.
//
// Subcommands:
//
//	agentkms-dev enroll   Generate the dev PKI (CA + server cert + client cert)
//	                      in ~/.agentkms/dev/. Run once before first `serve`.
//
//	agentkms-dev serve    Start the local mTLS server (default when no subcommand given).
//	agentkms-dev          Alias for serve.
//
// Serve flags:
//
//	--addr          string  Listen address (default: 127.0.0.1:8443)
//	--dir           string  Cert directory (default: ~/.agentkms/dev)
//	--secrets-file  string  JSON secrets file to seed KV store (default: <dir>/secrets.json)
//	--audit         string  Audit log file (default: <dir>/audit.ndjson)
//	--env           string  Environment tag in audit events (default: "dev")
//
// Enroll flags:
//
//	--dir           string  Output directory for certs (default: ~/.agentkms/dev)
//	--client-cn     string  Common Name for client cert (default: "forge-gateway")
//	--force                 Overwrite existing certs
//
// D-01.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/credentials/binding"
	"github.com/agentkms/agentkms/internal/plugin"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/internal/revocation"
	"github.com/agentkms/agentkms/internal/webhooks"
	"github.com/agentkms/agentkms/pkg/tlsutil"
)

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "enroll":
			if err := runEnroll(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "agentkms-dev enroll: %v\n", err)
				os.Exit(1)
			}
			return
		case "serve":
			if err := runServe(os.Args[2:]); err != nil {
				slog.Error("agentkms-dev serve failed", "error", err.Error())
				os.Exit(1)
			}
			return
		case "secrets":
			if err := runSecrets(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "agentkms-dev secrets: %v\n", err)
				os.Exit(1)
			}
			return
		case "--help", "-h", "help":
			printUsage()
			return
		}
	}
	// Default: serve
	if err := runServe(os.Args[1:]); err != nil {
		slog.Error("agentkms-dev failed", "error", err.Error())
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`agentkms-dev — local development server for AgentKMS

Usage:
  agentkms-dev enroll  [--dir <dir>] [--client-cn <cn>] [--force]
  agentkms-dev secrets set <path> <key>=<value> [<key>=<value>...]
  agentkms-dev secrets list
  agentkms-dev secrets delete <path>
  agentkms-dev serve   [--addr <addr>] [--dir <dir>]
  agentkms-dev         (same as serve)

First run:
  agentkms-dev enroll                                    # generates PKI
  agentkms-dev secrets set generic/forge/telegram token=<bot_token>
  agentkms-dev secrets set llm/anthropic api_key=<key>
  agentkms-dev                                           # start server

Secrets are stored in the macOS Keychain — never in plaintext on disk.

`)
}

// ── Enroll ─────────────────────────────────────────────────────────────────────

func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	dirFlag := fs.String("dir", "", "output directory (default: ~/.agentkms/dev)")
	clientCN := fs.String("client-cn", "forge-gateway", "Common Name for the client cert")
	force := fs.Bool("force", false, "overwrite existing certificates")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir, err := resolveDir(*dirFlag)
	if err != nil {
		return err
	}

	caPath := filepath.Join(dir, "ca.crt")
	if !*force {
		if _, err := os.Stat(caPath); err == nil {
			return fmt.Errorf(
				"certificates already exist in %s\n"+
					"  Use --force to overwrite, or delete the directory manually.\n"+
					"  ⚠  If you regenerate certs, existing clients must re-enroll.",
				dir,
			)
		}
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating cert directory: %w", err)
	}

	fmt.Printf("Generating dev PKI in %s ...\n\n", dir)

	// ── 1. CA key + self-signed cert ───────────────────────────────────────
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "agentkms-dev-ca", Organization: []string{"AgentKMS Dev"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("parsing CA cert: %w", err)
	}

	if err := writeCert(filepath.Join(dir, "ca.crt"), caCertDER); err != nil {
		return err
	}
	fmt.Printf("  ✓ CA cert:          %s\n", filepath.Join(dir, "ca.crt"))

	// ── 2. Server key + cert ───────────────────────────────────────────────
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating server key: %w", err)
	}

	serverSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: "agentkms-dev", Organization: []string{"AgentKMS Dev"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating server cert: %w", err)
	}

	if err := writeCert(filepath.Join(dir, "server.crt"), serverCertDER); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, "server.key"), serverKey); err != nil {
		return err
	}
	fmt.Printf("  ✓ Server cert:       %s\n", filepath.Join(dir, "server.crt"))
	fmt.Printf("  ✓ Server key:        %s\n", filepath.Join(dir, "server.key"))

	// ── 3. Client key + cert ───────────────────────────────────────────────
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating client key: %w", err)
	}

	clientSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	clientTemplate := &x509.Certificate{
		SerialNumber: clientSerial,
		Subject: pkix.Name{
			CommonName:   *clientCN,
			Organization: []string{"AgentKMS Dev"},
			// OU encodes team and caller identity for the auth middleware.
			OrganizationalUnit: []string{"team:forge", "caller:" + *clientCN},
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        mustParseURIs([]string{"spiffe://agentkms.dev/team/forge/identity/" + *clientCN}),
	}
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating client cert: %w", err)
	}

	clientDir := filepath.Join(dir, "clients", *clientCN)
	if err := os.MkdirAll(clientDir, 0700); err != nil {
		return fmt.Errorf("creating client cert directory: %w", err)
	}
	if err := writeCert(filepath.Join(clientDir, "client.crt"), clientCertDER); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(clientDir, "client.key"), clientKey); err != nil {
		return err
	}
	// Also write CA cert into the client dir for convenience.
	if err := writeCert(filepath.Join(clientDir, "ca.crt"), caCertDER); err != nil {
		return err
	}
	fmt.Printf("  ✓ Client cert:       %s\n", filepath.Join(clientDir, "client.crt"))
	fmt.Printf("  ✓ Client key:        %s\n", filepath.Join(clientDir, "client.key"))
	fmt.Printf("  ✓ Client CA copy:    %s\n", filepath.Join(clientDir, "ca.crt"))

	fmt.Printf(`
Done. Next steps:

  1. Store your secrets in the macOS Keychain (encrypted, never plaintext on disk):
       agentkms-dev secrets set generic/forge/telegram token=<your_bot_token>
       agentkms-dev secrets set llm/anthropic api_key=<your_anthropic_key>

  2. Start the dev server:
       agentkms-dev serve

  3. Point the Forge gateway at the client certs:
       AGENTKMS_CERT_DIR=%s
`, clientDir)

	return nil
}

// ── Secrets ───────────────────────────────────────────────────────────────────

// runSecrets handles the `agentkms-dev secrets` subcommand.
// Secrets are stored in the macOS Keychain — never in plaintext files.
//
// Usage:
//
//	agentkms-dev secrets set generic/forge/telegram token=<value>
//	agentkms-dev secrets set llm/anthropic api_key=<value>
//	agentkms-dev secrets list
//	agentkms-dev secrets delete generic/forge/telegram
func runSecrets(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required: set, list, delete")
	}
	switch args[0] {
	case "set":
		return runSecretsSet(args[1:])
	case "list":
		return runSecretsList()
	case "delete":
		return runSecretsDelete(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q — use set, list, or delete", args[0])
	}
}

func encryptedKVFromDir(dirFlag string) (*credentials.EncryptedKV, string, error) {
	dir, err := resolveDir(dirFlag)
	if err != nil {
		return nil, "", err
	}
	secretsEncPath := filepath.Join(dir, "secrets.enc")
	serverKeyPath := filepath.Join(dir, "server.key")
	return credentials.NewEncryptedKV(secretsEncPath, serverKeyPath), dir, nil
}

func runSecretsSet(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: agentkms-dev secrets set <path> <key>=<value> [<key>=<value>...]\n" +
			"  e.g. agentkms-dev secrets set generic/forge/telegram token=7xxx:AAA...")
	}

	userPath := args[0]
	kvPath := "kv/data/" + strings.TrimPrefix(userPath, "/")

	fields := make(map[string]string)
	for _, pair := range args[1:] {
		idx := strings.IndexByte(pair, '=')
		if idx < 0 {
			return fmt.Errorf("invalid key=value pair %q (missing '=')", pair)
		}
		fields[pair[:idx]] = pair[idx+1:]
	}

	kv, dir, err := encryptedKVFromDir("")
	if err != nil {
		return err
	}

	if err := kv.Set(kvPath, fields); err != nil {
		return err
	}

	fmt.Printf("✓ Secret stored (AES-256-GCM encrypted)\n")
	fmt.Printf("  File:   %s\n", filepath.Join(dir, "secrets.enc"))
	fmt.Printf("  Path:   %s\n", kvPath)
	for k := range fields {
		fmt.Printf("  Field:  %s=<hidden>\n", k)
	}
	fmt.Printf("  Access: GET /credentials/%s\n", userPath)
	return nil
}

func runSecretsList() error {
	kv, _, err := encryptedKVFromDir("")
	if err != nil {
		return err
	}
	paths, err := kv.Paths()
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		fmt.Println("No secrets stored yet. Use: agentkms-dev secrets set <path> <key>=<value>")
		return nil
	}
	fmt.Println("Stored secrets (paths only — values are encrypted):")
	for _, p := range paths {
		fmt.Printf("  %s\n", p)
	}
	return nil
}

func runSecretsDelete(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: agentkms-dev secrets delete <path>")
	}
	kvPath := "kv/data/" + strings.TrimPrefix(args[0], "/")
	kv, _, err := encryptedKVFromDir("")
	if err != nil {
		return err
	}
	if err := kv.Delete(kvPath); err != nil {
		return err
	}
	fmt.Printf("✓ Deleted %s\n", kvPath)
	return nil
}

// ── Serve ──────────────────────────────────────────────────────────────────────

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addrFlag := fs.String("addr", "127.0.0.1:8443", "listen address (host:port)")
	dirFlag := fs.String("dir", "", "cert directory (default: ~/.agentkms/dev)")
	auditFlag := fs.String("audit", "", "audit log file (default: <dir>/audit.ndjson)")
	envFlag := fs.String("env", "dev", "environment tag in audit events")
	rateLimitFlag := fs.Int("rate-limit", 60, "credential vend rate limit in seconds (0 to disable)")
	pluginDirFlag := fs.String("plugin-dir", "", "plugin directory (default: AGENTKMS_PLUGIN_DIR or ~/.agentkms/plugins)")
	webhookSecretFlag := fs.String("webhook-secret", envOrDev("AGENTKMS_WEBHOOK_SECRET", ""), "HMAC secret for GitHub secret-scanning webhooks (enables /webhooks/github/secret-scanning)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir, err := resolveDir(*dirFlag)
	if err != nil {
		return err
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	slog.Info("agentkms-dev starting", "addr", *addrFlag, "cert_dir", dir, "env", *envFlag)

	// ── TLS ────────────────────────────────────────────────────────────────
	caCertPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("reading ca.crt from %s: %w\n  → Run `agentkms-dev enroll` first", dir, err)
	}
	serverCertPEM, err := os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		return fmt.Errorf("reading server.crt: %w", err)
	}
	serverKeyPEM, err := os.ReadFile(filepath.Join(dir, "server.key"))
	if err != nil {
		return fmt.Errorf("reading server.key: %w", err)
	}

	tlsCfg, err := tlsutil.LoadServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		return fmt.Errorf("building TLS config: %w", err)
	}
	slog.Info("mTLS ready", "min_tls", "1.3", "client_auth", "RequireAndVerify")

	// ── Audit ──────────────────────────────────────────────────────────────
	auditPath := *auditFlag
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
		_ = fileSink.Flush(ctx)
		fileSink.Close()
	}()
	auditor := audit.NewMultiAuditor(fileSink)
	slog.Info("audit sink ready", "path", auditPath)

	// ── Auth ───────────────────────────────────────────────────────────────
	revocationList := auth.NewRevocationList()
	tokenSvc, err := auth.NewTokenService(revocationList)
	if err != nil {
		return fmt.Errorf("initialising token service: %w", err)
	}
	slog.Info("token service ready", "ttl", "15m")

	// ── KV store: AES-256-GCM encrypted file ───────────────────────────
	// Secrets are AES-256-GCM encrypted using a key derived from server.key.
	// secrets.enc is useless without server.key (which is mode 0600).
	// Works in any terminal context — no Keychain session required.
	secretsEncPath := filepath.Join(dir, "secrets.enc")
	serverKeyPath := filepath.Join(dir, "server.key")
	kv := credentials.NewEncryptedKV(secretsEncPath, serverKeyPath)
	slog.Info("KV backend: AES-256-GCM encrypted file",
		"path", secretsEncPath,
		"key", serverKeyPath,
		"hint", "add secrets with: agentkms-dev secrets set generic/forge/telegram token=<value>")

	vender := credentials.NewVender(kv, "kv")

	// ── Crypto backend ────────────────────────────────────────────────────
	devBackend := backend.NewDevBackend()
	if err := devBackend.CreateKey("dev/demo-signing-key", backend.AlgorithmES256, "dev"); err != nil {
		return fmt.Errorf("seeding demo key: %w", err)
	}
	slog.Info("dev crypto backend ready (in-memory; keys lost on restart)")

	// ── Policy (dev: allow all) ────────────────────────────────────────────
	eng := policy.New(policy.Policy{
		Version: "1.0",
		Rules: []policy.Rule{
			{
				ID:          "dev-allow-all",
				Description: "Allow all operations in dev",
				Effect:      policy.EffectAllow,
				Match: policy.Match{
					Identity: policy.IdentityMatch{
						Roles: []string{"developer", "service", "agent"},
					},
				},
			},
		},
	})

	// ── Handlers ──────────────────────────────────────────────────────────
	// authHandler owns all /auth/* routes.
	authHandler := api.NewAuthHandler(tokenSvc, auditor, policy.AsEngineI(eng), *envFlag)

	// apiServer owns all other routes (crypto ops, credential vending).
	// It registers its own internal routes in NewServer; we call SetVender
	// to wire in credential vending before any requests arrive.
	apiServer := api.NewServer(devBackend, auditor, policy.AsEngineI(eng), tokenSvc, *envFlag)
	apiServer.SetVender(vender)
	apiServer.SetRegistryWriter(kv)
	apiServer.SetBindingStore(binding.NewKVBindingStore(kv))
	apiServer.SetRateLimitInterval(time.Duration(*rateLimitFlag) * time.Second)

	// ── AlertOrchestrator (OSS webhook orchestration) ─────────────────────
	// Construct the AlertOrchestrator unconditionally. In dev mode we use
	// ConsoleNotifier (writes structured lines to stderr) and NoopRevoker
	// (no live provider credentials in dev). The orchestrator is wired to
	// apiServer and optionally extended with a RotationHook from the Pro
	// orchestrator plugin (below).
	alertOrch := webhooks.NewAlertOrchestrator(
		webhooks.NewDevAuditStore(), // dev-only in-memory AuditStore
		revocation.NewNoopRevoker(), // no live provider in dev
		auditor,
		webhooks.NewConsoleNotifier(),
	)
	apiServer.SetAlertOrchestrator(alertOrch)

	// Register the GitHub secret-scanning webhook endpoint if a secret is configured.
	// In dev mode the secret can be set via --webhook-secret or AGENTKMS_WEBHOOK_SECRET.
	// Without a secret the endpoint is not registered (operator must opt in).
	if *webhookSecretFlag != "" {
		apiServer.RegisterGitHubWebhookHandler(*webhookSecretFlag)
		slog.Info("[webhook] GitHub secret-scanning handler registered",
			"route", "POST /webhooks/github/secret-scanning")
	} else {
		slog.Info("[webhook] GitHub secret-scanning handler not registered (set --webhook-secret or AGENTKMS_WEBHOOK_SECRET to enable)")
	}

	// ── Orchestrator plugin (optional Pro feature) ────────────────────────
	// Resolve the plugin directory: flag → env → default.
	// Must run after apiServer + AlertOrchestrator are wired so the rotation
	// hook can be registered directly on the already-constructed apiServer.
	pluginDir := *pluginDirFlag
	if pluginDir == "" {
		if v := os.Getenv("AGENTKMS_PLUGIN_DIR"); v != "" {
			pluginDir = v
		} else {
			home, err := os.UserHomeDir()
			if err == nil {
				pluginDir = filepath.Join(home, ".agentkms", "plugins")
			}
		}
	}

	if pluginDir != "" {
		if _, statErr := os.Stat(pluginDir); statErr == nil {
			slog.Info("[plugin] discovering plugins", "dir", pluginDir)
			// Construct a shared registry so the same instance backs both the
			// plugin host (for adapter registration during Start*) and the api
			// server (for binding-rotate destination lookup).
			pluginRegistry := plugin.NewRegistry()
			apiServer.SetDestinationRegistry(pluginRegistry)
			pluginHost, hostErr := plugin.NewHostWithRegistry(pluginDir, pluginRegistry)
			if hostErr != nil {
				slog.Warn("[plugin] orchestrator plugin discovery failed", "error", hostErr)
			} else {
				discovered, discErr := pluginHost.Discover()
				if discErr != nil {
					slog.Warn("[plugin] orchestrator plugin discovery failed", "error", discErr)
				} else {
					// Pre-register HostServiceDeps once; orchestrator dispatch needs it.
					deps := &plugin.HostServiceDeps{
						Store:   binding.NewKVBindingStore(kv),
						Auditor: auditor,
						KV:      kv,
					}
					pluginHost.SetHostServiceDeps(deps)

					orchestratorFound := false
					for _, meta := range discovered {
						switch meta.Name {
						case "orchestrator":
							orchestratorFound = true
							slog.Info("[plugin] found: orchestrator", "path", meta.Path)
							orch, initErr := pluginHost.StartOrchestrator(meta.Name)
							if initErr != nil {
								slog.Error("[plugin] orchestrator plugin Init failed", "error", initErr)
							} else {
								slog.Info("[plugin] orchestrator plugin loaded", "path", meta.Path)
								rotationHook := pluginHost.RotationHookFor(orch)
								apiServer.SetRotationHook(rotationHook)
								slog.Info("[plugin] orchestrator registered as RotationHook")
							}
						case "gh-secret":
							slog.Info("[plugin] found: destination gh-secret", "path", meta.Path)
							if err := pluginHost.StartDestination(meta.Name); err != nil {
								slog.Error("[plugin] destination plugin Init failed", "name", meta.Name, "error", err)
							} else {
								slog.Info("[plugin] destination plugin loaded", "name", meta.Name, "path", meta.Path)
							}
						default:
							// Treat any other plugin as a CredentialVender provider plugin.
							// Host.Start() is for ScopeValidator plugins only — it dispenses
							// "scope_validator" and calls ScopeValidatorService.Kind(), which
							// fails for CredentialVender plugins with "unknown service
							// ScopeValidatorService". Host.StartProvider() dispenses
							// "credential_vender" and calls CredentialVenderService.Kind().
							slog.Info("[plugin] found: provider (credential_vender)", "name", meta.Name, "path", meta.Path)
							if err := pluginHost.StartProvider(meta.Name); err != nil {
								slog.Error("[plugin] provider plugin Init failed", "name", meta.Name, "error", err)
							} else {
								slog.Info("[plugin] provider plugin loaded", "name", meta.Name, "path", meta.Path)
							}
						}
					}
					if !orchestratorFound {
						slog.Info("[plugin] no orchestrator plugin found — running OSS-only rotation path")
					}
				}
			}
		} else {
			slog.Info("[plugin] no orchestrator plugin found — running OSS-only rotation path",
				"reason", "plugin dir not present", "dir", pluginDir)
		}
	} else {
		slog.Info("[plugin] no orchestrator plugin found — running OSS-only rotation path",
			"reason", "no plugin dir configured")
	}

	// ── Routes ────────────────────────────────────────────────────────────
	// Top-level mux: auth routes go to authHandler; everything else to apiServer.
	mux := http.NewServeMux()

	// Auth — mTLS only for session issuance; token required for refresh/revoke.
	mux.HandleFunc("POST /auth/session", authHandler.Session)
	mux.Handle("POST /auth/refresh",
		auth.RequireToken(tokenSvc)(http.HandlerFunc(authHandler.Refresh)))
	mux.Handle("POST /auth/revoke",
		auth.RequireToken(tokenSvc)(http.HandlerFunc(authHandler.Revoke)))
	mux.Handle("POST /auth/delegate",
		auth.RequireToken(tokenSvc)(http.HandlerFunc(authHandler.Delegate)))
	mux.Handle("POST /auth/certificate/revoke",
		auth.RequireToken(tokenSvc)(http.HandlerFunc(authHandler.RevokeCertificate)))
	mux.HandleFunc("GET /auth/certificate/crl", authHandler.CRL)

	// Health — no auth.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","service":"agentkms-dev"}`)
	})

	// Everything else (crypto ops + credential vending) → apiServer.
	// apiServer has its own internal mux with all routes already registered.
	mux.Handle("/", apiServer)

	// ── Server ─────────────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:              *addrFlag,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("agentkms-dev listening",
			"addr", "https://"+*addrFlag,
			"kv_backend", "encrypted-file",
		)
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

// ── PKI helpers ───────────────────────────────────────────────────────────────

func writeCert(path string, derBytes []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	derBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshalling key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})
}

func mustParseURIs(uris []string) []*url.URL {
	out := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			panic(fmt.Sprintf("invalid SPIFFE URI %q: %v", u, err))
		}
		out = append(out, parsed)
	}
	return out
}

// ── Shared ────────────────────────────────────────────────────────────────────

func resolveDir(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if env := os.Getenv("AGENTKMS_DIR"); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory (use --dir or AGENTKMS_DIR): %w", err)
	}
	return filepath.Join(home, ".agentkms", "dev"), nil
}

// envOrDev returns the environment variable value or the fallback.
// Avoids shadowing the envOr helper in cmd/server/main.go.
func envOrDev(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
