package devserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/credentials/binding"
	"github.com/agentkms/agentkms/internal/githubapp"
	"github.com/agentkms/agentkms/internal/plugin"
	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/internal/revocation"
	"github.com/agentkms/agentkms/internal/webhooks"
	"github.com/agentkms/agentkms/pkg/tlsutil"
)

// RunServe starts the local mTLS AgentKMS server (dev / bare-metal prod).
func RunServe(args []string) error {
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

	// VerifyClientCertIfGiven (not RequireAndVerify) so first-contact
	// enrollment works: `kpm login <invitecode>` has no client cert yet and
	// needs /.well-known/agentkms-ca + POST /auth/cert/issue (bootstrap-token
	// authorized). Presented certs are still verified; /auth/session still
	// requires a verified peer cert.
	tlsCfg, err := tlsutil.LoadServerTLSConfigOptionalClient(caCertPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		return fmt.Errorf("building TLS config: %w", err)
	}
	slog.Info("mTLS ready", "min_tls", "1.3", "client_auth", "VerifyIfGiven (enrollment-compatible)")

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
	apiServer.SetGithubAppStore(githubapp.NewKVStore(kv))
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
						Store:          binding.NewKVBindingStore(kv),
						Auditor:        auditor,
						KV:             kv,
						GithubAppStore: githubapp.NewKVStore(kv),
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

	if err := WireEnrollment(mux, dir, authHandler, tokenSvc); err != nil {
		return fmt.Errorf("enrollment routes: %w", err)
	}

	// Health — no auth.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","service":"agentkms-dev"}`)
	})

	// ── Dev-only legacy enrollment state ──────────────────────────────────
	// POST /admin/invites is now served by WireEnrollment (authenticated,
	// returns kpmi1_ codes). The in-memory structures below back only the
	// deprecated legacy POST /enroll path; devInvites stays empty so legacy
	// inv_ invite tokens are always rejected.

	type inviteRecord struct {
		Username  string
		ExpiresAt time.Time
		Used      bool
		CreatedAt time.Time
	}
	devInvites := map[string]*inviteRecord{}

	type deviceInfo struct {
		DeviceID string    `json:"device_id"`
		Hostname string    `json:"hostname"`
		Enrolled time.Time `json:"enrolled_at"`
		CertCN   string    `json:"cert_cn"`
	}
	devEnrolled := map[string][]deviceInfo{} // username -> list of devices

	// Admin: get basic info + enrolled devices for a user (for audit / "getuserinfo").
	mux.HandleFunc("GET /admin/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		username := strings.TrimPrefix(r.URL.Path, "/admin/users/")
		if username == "" {
			http.Error(w, `{"error":"username required, e.g. /admin/users/rajesh"}`, http.StatusBadRequest)
			return
		}
		devs := devEnrolled[username]
		json.NewEncoder(w).Encode(map[string]any{
			"username": username,
			"devices":  devs,
		})
	})

	// Enroll — bootstrap for new devices/machines (kpm enroll).
	// Supports two modes:
	//   1. Old/shared: explicit "user" + optional enrollment_token (shared secret via AGENTKMS_ENROLL_TOKEN or enroll.secret)
	//   2. New preferred (clean invites): "invite_token" created by kpm admin inviteuser.
	// When an invite_token is used the server resolves the username from the invite record
	// (one-time use) and the caller does not need to know or send the username.
	mux.HandleFunc("POST /enroll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Resolve the PKI dir once (supports --dir on serve, AGENTKMS_DIR, and default ~/.agentkms/dev).
		enrollDir := *dirFlag
		if enrollDir == "" {
			enrollDir = os.Getenv("AGENTKMS_DIR")
		}
		if enrollDir == "" {
			if home, err := os.UserHomeDir(); err == nil {
				enrollDir = filepath.Join(home, ".agentkms", "dev")
			}
		}

		// Parse body. Support both the legacy fields and the new invite flow.
		var req struct {
			User            string `json:"user"`
			DeviceID        string `json:"device_id"`
			Hostname        string `json:"hostname"`
			EnrollmentToken string `json:"enrollment_token"` // legacy shared secret
			InviteToken     string `json:"invite_token"`     // preferred: one-time from kpm admin inviteuser
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.DeviceID == "" {
			req.DeviceID = "device-" + fmt.Sprintf("%d", time.Now().UnixNano())
		}
		if req.Hostname == "" {
			req.Hostname, _ = os.Hostname()
		}

		allowedUser := req.User
		usedInvite := false

		// Preferred path: one-time invite token (created via `kpm admin inviteuser <name>`).
		if req.InviteToken != "" {
			if rec, ok := devInvites[req.InviteToken]; ok && !rec.Used && time.Now().Before(rec.ExpiresAt) {
				allowedUser = rec.Username
				rec.Used = true
				usedInvite = true
				slog.Info("enroll accepted via invite_token", "username", allowedUser, "invite", req.InviteToken)
			} else {
				slog.Warn("enroll rejected bad/used/expired invite_token", "invite", req.InviteToken)
				http.Error(w, "invalid, expired, or already-used invite token", http.StatusForbidden)
				return
			}
		}

		// Legacy / open-dev path (shared secret or completely open).
		if !usedInvite {
			if allowedUser == "" {
				allowedUser = "unknown-user"
			}
			devEnrollSecret := os.Getenv("AGENTKMS_ENROLL_TOKEN")
			if devEnrollSecret == "" {
				secretBytes, _ := os.ReadFile(filepath.Join(enrollDir, "enroll.secret"))
				devEnrollSecret = strings.TrimSpace(string(secretBytes))
			}
			sentToken := req.EnrollmentToken
			if sentToken == "" {
				sentToken = r.Header.Get("X-Enrollment-Token")
			}
			if devEnrollSecret != "" {
				if sentToken == "" || sentToken != devEnrollSecret {
					slog.Warn("enroll rejected: invalid or missing enrollment token",
						"requested_user", req.User, "has_token", sentToken != "")
					http.Error(w, "invalid or missing enrollment token (this server requires a token for enrollment)", http.StatusForbidden)
					return
				}
				slog.Info("enroll with valid (legacy) enrollment token", "user", allowedUser)
			} else {
				slog.Info("enroll (open dev, no token required)", "user", allowedUser)
			}
		}

		// Record the device for this user (used by /admin/users/...)
		devEnrolled[allowedUser] = append(devEnrolled[allowedUser], deviceInfo{
			DeviceID: req.DeviceID,
			Hostname: req.Hostname,
			Enrolled: time.Now(),
			CertCN:   allowedUser + "-" + req.DeviceID,
		})

		caPEM, caErr := os.ReadFile(filepath.Join(enrollDir, "ca.crt"))
		caKeyPEM, _ := os.ReadFile(filepath.Join(enrollDir, "ca.key"))
		if caErr != nil {
			http.Error(w, "no PKI yet — run 'agentkms-dev enroll' first on the server", 500)
			return
		}

		// Parse CA
		caBlock, _ := pem.Decode(caPEM)
		caCert, _ := x509.ParseCertificate(caBlock.Bytes)
		caKeyBlock, _ := pem.Decode(caKeyPEM)
		caKey, _ := x509.ParseECPrivateKey(caKeyBlock.Bytes)

		// Generate fresh client key + cert for this user+device.
		// CN and OU encode user and device for auth/policies and forensics tracking.
		// "user:xxx" (from the --user given to kpm enroll, or validated via token) is the
		// stable identity that gives access to "your" secrets across all your devices.
		clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		clientSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		clientCN := allowedUser + "-" + req.DeviceID
		clientTemplate := &x509.Certificate{
			SerialNumber: clientSerial,
			Subject: pkix.Name{
				CommonName:         clientCN,
				Organization:       []string{"AgentKMS"},
				OrganizationalUnit: []string{"user:" + allowedUser, "device:" + req.DeviceID, "hostname:" + req.Hostname},
			},
			NotBefore:   time.Now().Add(-time.Minute),
			NotAfter:    time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		clientCertDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)

		clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
		clientKeyDER, _ := x509.MarshalECPrivateKey(clientKey)
		clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

		// Write for server-side reference/audit (one dir per device for easy revocation/forensics).
		clientDir := filepath.Join(enrollDir, "clients", clientCN)
		os.MkdirAll(clientDir, 0700)
		_ = os.WriteFile(filepath.Join(clientDir, "ca.crt"), caPEM, 0644)
		_ = os.WriteFile(filepath.Join(clientDir, "client.crt"), clientCertPEM, 0644)
		_ = os.WriteFile(filepath.Join(clientDir, "client.key"), clientKeyPEM, 0600)

		fmt.Fprintf(w, `{"ca":%q,"client_cert":%q,"client_key":%q}`, string(caPEM), string(clientCertPEM), string(clientKeyPEM))
		slog.Info("enroll: built and pushed client cert for user+device", "user", allowedUser, "device_id", req.DeviceID, "hostname", req.Hostname, "cn", clientCN)
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
