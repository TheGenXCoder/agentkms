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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/devserver"
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
		case "enroll-token":
			if err := runEnrollToken(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "agentkms-dev enroll-token: %v\n", err)
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
  agentkms-dev enroll-token generate [--dir <dir>] [--write]
  agentkms-dev secrets set <path> <key>=<value> [<key>=<value>...]
  agentkms-dev secrets list
  agentkms-dev secrets delete <path>
  agentkms-dev serve   [--addr <addr>] [--dir <dir>]
  agentkms-dev         (same as serve)

Enrollment tokens (for invited kpm enroll + per-user separation):
  agentkms-dev enroll-token generate --write
  # (prints a token and writes it to the enroll.secret file for the dir)
  # Give the token value securely to the invitee (e.g. Rajesh). They do:
  #   kpm enroll <server> --user rajesh --token <value>
  # Use the *same* --user string on all of *one person's* machines to keep them
  # in the same userspace/secret set. Different --user values are isolated by
  # the cert identity the server embeds.

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
	clientCN := fs.String("client-cn", "forge-gateway", "Common Name for the client cert (also used as device segment in the SPIFFE URI)")
	clientUser := fs.String("client-user", "", "logical user segment for the SPIFFE URI (default: empty — emits a legacy device-only URI)")
	tenant := fs.String("tenant", "forge", "tenant segment for the SPIFFE URI")
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
	if err := writeKey(filepath.Join(dir, "ca.key"), caKey); err != nil {
		return err
	}
	fmt.Printf("  ✓ CA cert:          %s\n", filepath.Join(dir, "ca.crt"))
	fmt.Printf("  ✓ CA key:           %s\n", filepath.Join(dir, "ca.key"))

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
		URIs:        mustParseURIs([]string{buildSPIFFEURI(*tenant, *clientUser, *clientCN)}),
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

  1. Store your secrets in the encrypted dev store (never plaintext on disk):
       agentkms-dev secrets set generic/forge/telegram token=<your_bot_token>
       agentkms-dev secrets set llm/anthropic api_key=<your_anthropic_key>

  2. Start the dev server:
       agentkms-dev serve

  3. Point the Forge gateway at the client certs:
       AGENTKMS_CERT_DIR=%s
`, clientDir)

	return nil
}

// ── Enroll token (for kpm invited enrollment) ──────────────────────────────────

// runEnrollToken implements `agentkms-dev enroll-token generate`.
// This is the admin command to create the value you give to someone (Rajesh)
// or to yourself for a new machine (Arch box) so they can run `kpm enroll`
// against this server and get a cert embedding a specific "user:NAME".
//
// The token is just a shared secret for this server instance (simple but effective
// for dev / small teams). For production you would typically issue short-lived
// per-user tokens that are validated + consumed server-side.
func runEnrollToken(args []string) error {
	fs := flag.NewFlagSet("enroll-token", flag.ExitOnError)
	dirFlag := fs.String("dir", "", "PKI directory (default: ~/.agentkms/dev)")
	write := fs.Bool("write", false, "write the token to <dir>/enroll.secret (mode 0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir, err := resolveDir(*dirFlag)
	if err != nil {
		return err
	}

	// Generate a strong random token (base64, ~32 bytes raw).
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("generating random token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	fmt.Printf("Enrollment token (give this to the invitee, or use for your own machines):\n\n")
	fmt.Printf("  %s\n\n", token)
	fmt.Printf("Client usage:\n")
	fmt.Printf("  kpm enroll <server-url> --user <name> --token %s\n\n", token)
	fmt.Printf("  (Use the same <name> on all devices belonging to one person so they share one userspace.)\n")

	if *write {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("creating dir: %w", err)
		}
		secretPath := filepath.Join(dir, "enroll.secret")
		if err := os.WriteFile(secretPath, []byte(token+"\n"), 0600); err != nil {
			return fmt.Errorf("writing %s: %w", secretPath, err)
		}
		fmt.Printf("✓ Wrote %s (0600). Server will read it on next start (or restart serve).\n", secretPath)
		fmt.Printf("  (Or set AGENTKMS_ENROLL_TOKEN in the environment of the server process.)\n")
	} else {
		fmt.Printf("Tip: re-run with --write to persist it as %s/enroll.secret\n", dir)
	}

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
	return devserver.RunServe(args)
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

// buildSPIFFEURI emits the multi-principal SPIFFE convention introduced in
// Phase 1 of the zero-trust identity rollout:
//
//	spiffe://agentkms.dev/tenant/<t>/user/<u>/device/<d>   (when user != "")
//	spiffe://agentkms.dev/tenant/<t>/device/<d>            (legacy fallback)
//
// The legacy fallback is preserved so existing dev workflows that didn't
// previously have a user concept keep producing a working cert; the server
// recognises it and emits a one-time warning per (UserID,DeviceID) pair.
func buildSPIFFEURI(tenant, user, device string) string {
	if user == "" {
		return fmt.Sprintf("spiffe://agentkms.dev/tenant/%s/device/%s", tenant, device)
	}
	return fmt.Sprintf("spiffe://agentkms.dev/tenant/%s/user/%s/device/%s", tenant, user, device)
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
