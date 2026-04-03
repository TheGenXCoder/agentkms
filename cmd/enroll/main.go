// Package main is the agentkms production enrollment CLI — A-09/A-11.
//
// Enrollment flow:
//
//  1. Parse flags: --team, --caller-id, --vault-addr, --pki-mount, --role
//  2. Obtain a bootstrap token (one of):
//     a. --bootstrap-token flag (operator-issued, single-use)
//     b. --oidc-issuer flag: start OIDC flow → exchange code for identity →
//        call AgentKMS /auth/bootstrap to get a short-lived enroll token
//  3. Call PKIClient.IssueCert with the bootstrap token
//  4. Write cert + key to ~/.agentkms/client.{crt,key}
//     Key file mode 0600; never logged
//  5. Write CA cert to ~/.agentkms/ca.crt
//  6. Print summary (serial, expiry, paths) — no key material in stdout
//
// For local dev enrollment, use: agentkms-dev enroll
// This CLI handles production enrollment only.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agentkms/agentkms/internal/auth"
)

// httpClient is a shared HTTP client with a 30-second timeout.
// Used for OIDC discovery, token exchange, and AgentKMS bootstrap.
// SECURITY: replaces http.DefaultClient which has no timeout.
var httpClient = &http.Client{Timeout: 30 * time.Second}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "agentkms enroll: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)

	var (
		teamID         = fs.String("team", "", "Team identifier (required)")
		callerID       = fs.String("caller-id", "", "Caller identity (e.g. user@team); defaults to $USER@team")
		vaultAddr      = fs.String("vault-addr", envOr("AGENTKMS_VAULT_ADDR", ""), "OpenBao/Vault address (required)")
		pkiMount       = fs.String("pki-mount", "pki", "PKI secrets engine mount path")
		role           = fs.String("role", "agentkms", "PKI role for cert issuance")
		bootstrapToken = fs.String("bootstrap-token", envOr("AGENTKMS_BOOTSTRAP_TOKEN", ""), "Single-use bootstrap token (operator-issued)")
		oidcIssuer     = fs.String("oidc-issuer", envOr("AGENTKMS_OIDC_ISSUER", ""), "OIDC issuer URL (for browser-based enrollment)")
		oidcClientID   = fs.String("oidc-client-id", envOr("AGENTKMS_OIDC_CLIENT_ID", "agentkms-enroll"), "OIDC client ID")
		ttl            = fs.String("ttl", "720h", "Certificate TTL (default 30 days)")
		outputDir      = fs.String("output-dir", defaultOutputDir(), "Directory to write cert, key, and CA cert")
		force          = fs.Bool("force", false, "Overwrite existing certificates")
	)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `agentkms enroll — Issue a developer certificate from AgentKMS PKI

Usage:
  agentkms enroll --team=<team> --vault-addr=<url> [--bootstrap-token=<tok>]
  agentkms enroll --team=<team> --vault-addr=<url> --oidc-issuer=<url>

Authentication:
  --bootstrap-token  Single-use token provided by your platform admin.
  --oidc-issuer      Opens a browser for SSO login; requires OIDC to be
                     configured on the AgentKMS server.

Examples:
  # With a bootstrap token (admin provides this out-of-band):
  agentkms enroll \
    --team=platform-team \
    --vault-addr=https://openbao.internal:8200 \
    --bootstrap-token=hvs.BOOTSTRAP_TOKEN

  # With OIDC/SSO:
  agentkms enroll \
    --team=platform-team \
    --vault-addr=https://openbao.internal:8200 \
    --oidc-issuer=https://sso.internal

`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	// ── Validate required flags ────────────────────────────────────────────────
	if *teamID == "" {
		return fmt.Errorf("--team is required")
	}
	if *vaultAddr == "" {
		return fmt.Errorf("--vault-addr is required (or set AGENTKMS_VAULT_ADDR)")
	}
	if *bootstrapToken == "" && *oidcIssuer == "" {
		return fmt.Errorf("one of --bootstrap-token or --oidc-issuer is required")
	}

	// Set caller ID from $USER if not provided.
	if *callerID == "" {
		user := os.Getenv("USER")
		if user == "" {
			user = os.Getenv("USERNAME") // Windows
		}
		if user == "" {
			return fmt.Errorf("--caller-id is required (could not detect from $USER)")
		}
		*callerID = user + "@" + *teamID
	}

	// ── Check for existing certs ───────────────────────────────────────────────
	certPath := filepath.Join(*outputDir, "client.crt")
	if !*force {
		if _, err := os.Stat(certPath); err == nil {
			return fmt.Errorf("certificate already exists at %s; use --force to overwrite", certPath)
		}
	}

	// ── Obtain bootstrap token ─────────────────────────────────────────────────
	token := *bootstrapToken
	if token == "" {
		fmt.Fprintf(os.Stderr, "Starting OIDC enrollment via %s...\n", *oidcIssuer)
		var err error
		token, err = obtainOIDCBootstrapToken(*oidcIssuer, *oidcClientID, *vaultAddr)
		if err != nil {
			return fmt.Errorf("OIDC enrollment: %w", err)
		}
	}

	// ── Issue certificate ──────────────────────────────────────────────────────
	pkiClient := auth.NewPKIClient(auth.PKIConfig{
		Address:        *vaultAddr,
		BootstrapToken: token,
		PKIMount:       *pkiMount,
		Role:           *role,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spiffeID := fmt.Sprintf("spiffe://agentkms.org/team/%s/identity/%s", *teamID, *callerID)

	fmt.Fprintf(os.Stderr, "Requesting certificate for %s (team: %s)...\n", *callerID, *teamID)
	bundle, err := pkiClient.IssueCert(ctx, *callerID, *teamID, spiffeID, *ttl)
	if err != nil {
		if errors.Is(err, auth.ErrPKIIssueFailed) {
			return fmt.Errorf("PKI rejected certificate request: %w", err)
		}
		return fmt.Errorf("cert issuance failed: %w", err)
	}

	// ── Write files ────────────────────────────────────────────────────────────
	if err := os.MkdirAll(*outputDir, 0700); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	keyPath := filepath.Join(*outputDir, "client.key")
	caPath := filepath.Join(*outputDir, "ca.crt")

	// Write private key first (most sensitive — fail early if we can't write).
	// SECURITY: mode 0600 — only owner can read.
	// SECURITY: the key string is written directly; it is NOT logged.
	if err := os.WriteFile(keyPath, []byte(bundle.PrivateKeyPEM), 0600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	if err := os.WriteFile(certPath, []byte(bundle.CertificatePEM), 0644); err != nil {
		os.Remove(keyPath) //nolint:errcheck // best-effort cleanup
		return fmt.Errorf("writing certificate: %w", err)
	}

	if bundle.CAPEM != "" {
		if err := os.WriteFile(caPath, []byte(bundle.CAPEM), 0644); err != nil {
			return fmt.Errorf("writing CA cert: %w", err)
		}
	}

	// ── Summary (no key material) ──────────────────────────────────────────────
	fmt.Printf("\n✓ Enrollment complete\n\n")
	fmt.Printf("  Identity:    %s\n", *callerID)
	fmt.Printf("  Team:        %s\n", *teamID)
	fmt.Printf("  Serial:      %s\n", bundle.SerialNumber)
	fmt.Printf("  Expires:     %s\n", bundle.ExpiresAt.Format("2006-01-02 15:04 UTC"))
	fmt.Printf("\n  Certificate: %s\n", certPath)
	fmt.Printf("  Private key: %s\n", keyPath)
	fmt.Printf("  CA cert:     %s\n", caPath)
	fmt.Printf("\nPi will auto-discover these paths. Run 'pi' to start.\n\n")

	return nil
}

// ── OIDC enrollment flow ──────────────────────────────────────────────────────

// obtainOIDCBootstrapToken performs the OIDC authorization code flow and
// exchanges the resulting identity for a bootstrap enrollment token.
//
// Flow:
//  1. Fetch OIDC discovery document to get authorization_endpoint + token_endpoint
//  2. Start a local HTTP listener on a random port for the callback
//  3. Build authorization URL with state + PKCE
//  4. Open browser
//  5. Receive authorization code from callback
//  6. Exchange code for ID token
//  7. POST ID token to AgentKMS /auth/bootstrap → receive enrollment token
//
// SECURITY: the ID token and enrollment token are held in memory only.
// They are not logged or written to disk.
func obtainOIDCBootstrapToken(issuer, clientID, agentKMSAddr string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// ── 1. OIDC discovery ──────────────────────────────────────────────────────
	disc, err := fetchOIDCDiscovery(ctx, issuer)
	if err != nil {
		return "", fmt.Errorf("OIDC discovery: %w", err)
	}

	// ── 2. Local callback listener ─────────────────────────────────────────────
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("starting callback listener: %w", err)
	}
	defer ln.Close()

	callbackURL := fmt.Sprintf("http://%s/callback", ln.Addr())

	// ── 3. Build authorization URL + PKCE ─────────────────────────────────────
	state, err := randomHex(16)
	if err != nil {
		return "", err
	}
	codeVerifier, err := randomHex(32)
	if err != nil {
		return "", err
	}
	// PKCE S256: code_challenge = base64url(sha256(code_verifier))
	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	authURL := disc.AuthorizationEndpoint +
		"?response_type=code" +
		"&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(callbackURL) +
		"&scope=openid+email+profile" +
		"&state=" + state +
		"&code_challenge=" + codeChallenge +
		"&code_challenge_method=S256"

	// ── 4. Open browser ────────────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "\nOpening browser for SSO login...\n")
	fmt.Fprintf(os.Stderr, "If it doesn't open automatically, visit:\n  %s\n\n", authURL)
	openBrowser(authURL)

	// ── 5. Receive authorization code ─────────────────────────────────────────
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	srv := &http.Server{ReadTimeout: 5 * time.Minute}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if got := q.Get("state"); got != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			errCh <- fmt.Errorf("OIDC state mismatch")
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			errCh <- fmt.Errorf("OIDC: no code in callback")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h1>✓ Enrollment in progress</h1><p>You can close this tab.</p></body></html>")
		codeCh <- code
	})

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	var code string
	select {
	case code = <-codeCh:
		srv.Shutdown(context.Background()) //nolint:errcheck
	case err := <-errCh:
		srv.Shutdown(context.Background()) //nolint:errcheck
		return "", err
	case <-ctx.Done():
		srv.Shutdown(context.Background()) //nolint:errcheck
		return "", fmt.Errorf("OIDC: timed out waiting for browser callback")
	}

	// ── 6. Exchange code for ID token ──────────────────────────────────────────
	idToken, err := exchangeCodeForIDToken(ctx, disc.TokenEndpoint, clientID, code, codeVerifier, callbackURL)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}

	// ── 7. Exchange ID token for AgentKMS enrollment token ─────────────────────
	enrollToken, err := agentKMSBootstrap(ctx, agentKMSAddr, idToken)
	if err != nil {
		return "", fmt.Errorf("AgentKMS bootstrap: %w", err)
	}
	return enrollToken, nil
}

// oidcDiscovery holds the fields we need from the OIDC discovery document.
type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func fetchOIDCDiscovery(ctx context.Context, issuer string) (*oidcDiscovery, error) {
	well := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, well, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", well, err)
	}
	defer resp.Body.Close()
	var d oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("parse discovery: %w", err)
	}
	return &d, nil
}

func exchangeCodeForIDToken(ctx context.Context, tokenEndpoint, clientID, code, verifier, redirectURI string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", tokenEndpoint, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode != http.StatusOK {
		// Do not include body in error — it may contain a partial token.
		return "", fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if result.IDToken == "" {
		return "", fmt.Errorf("no id_token in token response")
	}
	return result.IDToken, nil
}

// agentKMSBootstrap exchanges an OIDC ID token for a short-lived AgentKMS
// enrollment token via POST /auth/bootstrap.
//
// This endpoint does not exist yet (tracked in backlog as part of A-11 full
// implementation). For now, returns an error with a helpful message.
func agentKMSBootstrap(ctx context.Context, agentKMSAddr, idToken string) (string, error) {
	enrollURL := strings.TrimRight(agentKMSAddr, "/") + "/auth/bootstrap"
	body := fmt.Sprintf(`{"id_token":%q}`, idToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL,
		strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", enrollURL, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("/auth/bootstrap not yet implemented on this server " +
			"(backlog A-11 T1 — use --bootstrap-token for now)")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bootstrap endpoint returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		EnrollToken string `json:"enroll_token"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse bootstrap response: %w", err)
	}
	if result.EnrollToken == "" {
		return "", fmt.Errorf("no enroll_token in bootstrap response")
	}
	// SECURITY: token returned to caller in memory only; never logged.
	return result.EnrollToken, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func defaultOutputDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".agentkms"
	}
	return filepath.Join(home, ".agentkms")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "linux":
		cmd, args = "xdg-open", []string{url}
	case "windows":
		cmd, args = "cmd", []string{"/c", "start", url}
	default:
		return // unsupported; user must open manually
	}
	exec.Command(cmd, args...).Start() //nolint:errcheck
}
