// Package main implements the agentkms-dev enroll CLI.
//
// enroll generates a local dev PKI (CA + developer cert + server cert) and
// writes the files to ~/.agentkms/dev/.  The same CA is used by the dev server
// and the Pi extension client to establish mTLS.
//
// Usage:
//
//	agentkms-dev enroll [flags]
//	  --name  string   Developer identity name (default: OS username)
//	  --team  string   Team name (default: "dev")
//	  --dir   string   Output directory (default: ~/.agentkms/dev)
//	  --force          Overwrite existing certificates without prompting
//
// Files written (all in --dir):
//
//	ca.crt        — Dev CA certificate (PEM, safe to share)
//	ca.key        — Dev CA private key  (PEM, mode 0600, KEEP SECRET)
//	client.crt    — Developer certificate (PEM)
//	client.key    — Developer private key  (PEM, mode 0600)
//	server.crt    — Local dev server certificate (PEM)
//	server.key    — Local dev server private key  (PEM, mode 0600)
//	config.json   — Dev server config (URL, team, identity)
//
// SECURITY NOTE: ca.key and client.key are private keys.  They are written
// with mode 0600.  Never commit them to version control, log them, or include
// them in error messages.
//
// A-09.
package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/agentkms/agentkms/pkg/tlsutil"
)

const (
	// defaultListenAddr is the address the dev server listens on.
	defaultListenAddr = "127.0.0.1:8443"

	// caValidity is how long the dev CA certificate is valid.
	// 365 days is sufficient for local dev; production PKI is managed
	// by the backend (OpenBao PKI engine).
	caValidity = 365 * 24 * time.Hour

	// certValidity is how long leaf certificates (developer, server) are valid.
	// 90 days; re-run enroll to renew.
	certValidity = 90 * 24 * time.Hour
)

// devConfig is written to config.json in the output directory.
// The Pi extension and dev server read this file to discover service URLs
// and the developer identity.
type devConfig struct {
	// ServerURL is the mTLS base URL of the local dev server.
	ServerURL string `json:"server_url"`

	// TeamID is the team identifier used for this dev identity.
	TeamID string `json:"team_id"`

	// CallerID is the developer's identity (encoded in the client cert CN).
	CallerID string `json:"caller_id"`

	// CACertPath is the path to the dev CA certificate.
	CACertPath string `json:"ca_cert_path"`

	// ClientCertPath is the path to the developer certificate.
	ClientCertPath string `json:"client_cert_path"`

	// ClientKeyPath is the path to the developer private key.
	// SECURITY: this path is stored here for convenience; the file itself
	// must remain 0600.
	ClientKeyPath string `json:"client_key_path"`

	// EnrolledAt is the UTC timestamp of the enrollment.
	EnrolledAt string `json:"enrolled_at"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "enroll: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// ── Flags ─────────────────────────────────────────────────────────────
	var (
		nameFlag  string
		teamFlag  string
		dirFlag   string
		forceFlag bool
	)

	flag.StringVar(&nameFlag, "name", "", "developer identity name (default: OS username)")
	flag.StringVar(&teamFlag, "team", "dev", "team name")
	flag.StringVar(&dirFlag, "dir", "", "output directory (default: ~/.agentkms/dev)")
	flag.BoolVar(&forceFlag, "force", false, "overwrite existing certificates")
	flag.Parse()

	// ── Resolve defaults ──────────────────────────────────────────────────
	name, err := resolveName(nameFlag)
	if err != nil {
		return err
	}

	dir, err := resolveDir(dirFlag)
	if err != nil {
		return err
	}

	callerID := name + "@" + teamFlag

	// ── Check for existing certs ──────────────────────────────────────────
	caCertPath := filepath.Join(dir, "ca.crt")
	if _, err := os.Stat(caCertPath); err == nil && !forceFlag {
		return fmt.Errorf(
			"certificates already exist in %s\n"+
				"Run with --force to overwrite, or delete the directory manually.\n"+
				"WARNING: overwriting rotates the CA — existing sessions will break.",
			dir,
		)
	}

	// ── Create output directory ───────────────────────────────────────────
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating output directory %q: %w", dir, err)
	}

	fmt.Printf("AgentKMS Dev Enrollment\n")
	fmt.Printf("  Identity : %s\n", callerID)
	fmt.Printf("  Team     : %s\n", teamFlag)
	fmt.Printf("  Directory: %s\n\n", dir)

	// ── Generate dev CA ───────────────────────────────────────────────────
	fmt.Printf("Generating dev CA...")
	ca, err := tlsutil.GenerateSelfSignedCA(tlsutil.CAOptions{
		CN:       "AgentKMS Dev CA",
		Org:      "agentkms-dev",
		Validity: caValidity,
	})
	if err != nil {
		return fmt.Errorf("generating dev CA: %w", err)
	}
	fmt.Println(" done")

	// ── Generate developer (client) certificate ───────────────────────────
	fmt.Printf("Generating developer certificate (%s)...", callerID)
	spiffeID := fmt.Sprintf("spiffe://agentkms.org/team/%s/identity/%s", teamFlag, name)
	clientCert, err := tlsutil.GenerateLeafCert(ca, tlsutil.LeafOptions{
		CN:           callerID,
		Org:          teamFlag,
		OrgUnit:      "developer",
		SPIFFEID:     spiffeID,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Validity:     certValidity,
	})
	if err != nil {
		return fmt.Errorf("generating developer certificate: %w", err)
	}
	fmt.Println(" done")

	// ── Generate server certificate for the local dev server ──────────────
	fmt.Printf("Generating dev server certificate (localhost)...")
	serverCert, err := tlsutil.GenerateLeafCert(ca, tlsutil.LeafOptions{
		CN:      "agentkms-dev-server",
		Org:     "agentkms-dev",
		OrgUnit: "service",
		DNSNames: []string{
			"localhost",
			"agentkms-dev.local",
		},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		},
		ExtKeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth, // also usable as client in service-to-service
		},
		Validity: certValidity,
	})
	if err != nil {
		return fmt.Errorf("generating server certificate: %w", err)
	}
	fmt.Println(" done")

	// ── Write files ───────────────────────────────────────────────────────
	files := []struct {
		name    string
		data    []byte
		mode    os.FileMode
		private bool
	}{
		// CA certificate: public — readable by anyone.
		{"ca.crt", ca.CertPEM, 0644, false},
		// CA private key: SECRET — only the owner must read this.
		// SECURITY: mode 0600; never logged, never in API responses.
		{"ca.key", ca.KeyPEM, 0600, true},
		// Developer cert: public.
		{"client.crt", clientCert.CertPEM, 0644, false},
		// Developer private key: SECRET.
		{"client.key", clientCert.KeyPEM, 0600, true},
		// Server cert: public.
		{"server.crt", serverCert.CertPEM, 0644, false},
		// Server private key: SECRET.
		{"server.key", serverCert.KeyPEM, 0600, true},
	}

	fmt.Println()
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		label := "writing"
		if f.private {
			label = "writing (private)"
		}
		fmt.Printf("  %-30s %s\n", label, path)
		if err := writeFile(path, f.data, f.mode); err != nil {
			return fmt.Errorf("writing %s: %w", f.name, err)
		}
	}

	// ── Write config.json ─────────────────────────────────────────────────
	cfg := devConfig{
		ServerURL:      "https://" + defaultListenAddr,
		TeamID:         teamFlag,
		CallerID:       callerID,
		CACertPath:     filepath.Join(dir, "ca.crt"),
		ClientCertPath: filepath.Join(dir, "client.crt"),
		ClientKeyPath:  filepath.Join(dir, "client.key"),
		EnrolledAt:     time.Now().UTC().Format(time.RFC3339),
	}
	cfgBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	fmt.Printf("  %-30s %s\n", "writing config", cfgPath)
	if err := writeFile(cfgPath, append(cfgBytes, '\n'), 0644); err != nil {
		return fmt.Errorf("writing config.json: %w", err)
	}

	// ── Success ───────────────────────────────────────────────────────────
	fmt.Printf("\nEnrollment complete.\n\n")
	fmt.Printf("Next steps:\n")
	fmt.Printf("  1. Start the dev server:\n")
	fmt.Printf("       agentkms-dev server\n\n")
	fmt.Printf("  2. The Pi extension will auto-discover certs from %s\n", dir)
	fmt.Printf("     Or set AGENTKMS_DIR=%s to use a custom path.\n\n", dir)
	fmt.Printf("  3. In Pi, you should see:\n")
	fmt.Printf("       AgentKMS: authenticated ✓  (identity: %s)\n\n", callerID)
	fmt.Printf("REMINDER: %s/ca.key and %s/client.key are private keys.\n", dir, dir)
	fmt.Printf("  Keep them out of version control and backups.\n")

	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// resolveName determines the developer identity name from the flag or OS user.
func resolveName(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("determining OS username (use --name to override): %w", err)
	}
	if u.Username == "" {
		return "", fmt.Errorf("OS username is empty; use --name to set developer identity")
	}
	return u.Username, nil
}

// resolveDir determines the output directory from the flag or the default
// (~/.agentkms/dev).
func resolveDir(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determining home directory (use --dir to override): %w", err)
	}
	return filepath.Join(home, ".agentkms", "dev"), nil
}

// writeFile writes data to path with the given permissions.
// If the file exists, it is overwritten.
//
// SECURITY: private key files (*.key) must be written with mode 0600.
// This is enforced at the call site — callers must pass the correct mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	// Write to a temp file first, then rename atomically.
	// This prevents partial writes from leaving a corrupt file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("writing temp file %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp) // best effort cleanup
		return fmt.Errorf("renaming %q to %q: %w", tmp, path, err)
	}
	return nil
}
