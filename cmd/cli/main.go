package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/agentkms/agentkms/internal/plugin"
	"github.com/agentkms/agentkms/pkg/tlsutil"
)

type credentialResponse struct {
	Secrets map[string]string `json:"secrets"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "plugin" {
		os.Exit(runPluginCommand(os.Args[2:]))
	}

	runCredentialCommand()
}

// ── Credential vend command (original behavior) ────────────────────────────────

func runCredentialCommand() {
	serverAddr := flag.String("server", "https://127.0.0.1:8443", "AgentKMS server address")
	dir := flag.String("dir", filepath.Join(os.Getenv("HOME"), ".agentkms", "dev"), "Directory containing mTLS certs")
	path := flag.String("path", "", "Path to generic credential (e.g. github/token)")
	flag.Parse()

	if *path == "" {
		fmt.Fprintln(os.Stderr, "Usage: agentkms run -path <path> -- <cmd> [args...]")
		os.Exit(1)
	}
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentkms run -path <path> -- <cmd> [args...]")
		os.Exit(1)
	}

	caPath := filepath.Join(*dir, "ca.crt")
	certPath := filepath.Join(*dir, "client.crt")
	keyPath := filepath.Join(*dir, "client.key")

	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read CA: %v\n", err)
		os.Exit(1)
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read client cert: %v\n", err)
		os.Exit(1)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read client key: %v\n", err)
		os.Exit(1)
	}

	tlsCfg, err := tlsutil.ClientTLSConfig(caBytes, certBytes, keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build TLS config: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, *serverAddr+"/credentials/generic/"+*path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build request: %v\n", err)
		os.Exit(1)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch credentials: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "server returned error status: %d\n", resp.StatusCode)
		os.Exit(1)
	}

	var credResp credentialResponse
	if err := json.NewDecoder(resp.Body).Decode(&credResp); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode response: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = os.Environ()
	for k, v := range credResp.Secrets {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			os.Exit(exitError.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "failed to run command: %v\n", err)
		os.Exit(1)
	}
}

// ── Plugin subcommands ─────────────────────────────────────────────────────────

const pluginUsage = `Usage: agentkms plugin <subcommand> [options]

Subcommands:
  install [--trust-key <key-file>] <binary-path>   Install a plugin binary
  list                                              List installed plugins
  remove <name>                                     Remove an installed plugin

Environment:
  AGENTKMS_PLUGIN_DIR   Plugin directory (default: ~/.agentkms/plugins/)
`

// runPluginCommand dispatches plugin subcommands and returns an exit code.
func runPluginCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, pluginUsage)
		return 1
	}

	pluginDir := defaultPluginDir()
	if v := os.Getenv("AGENTKMS_PLUGIN_DIR"); v != "" {
		pluginDir = v
	}
	// Ensure the plugin directory exists.
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create plugin dir %q: %v\n", pluginDir, err)
		return 1
	}

	switch args[0] {
	case "install":
		return pluginInstall(pluginDir, args[1:])
	case "list":
		return pluginList(pluginDir)
	case "remove":
		return pluginRemove(pluginDir, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown plugin subcommand %q\n\n%s", args[0], pluginUsage)
		return 1
	}
}

// pluginInstall copies a plugin binary into the plugin directory, optionally
// verifying its Ed25519 signature.
//
//	akms plugin install [--trust-key <key-file>] <binary-path>
func pluginInstall(pluginDir string, args []string) int {
	fs := flag.NewFlagSet("plugin install", flag.ContinueOnError)
	trustKey := fs.String("trust-key", "", "Path to Ed25519 public key file for signature verification")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() == 0 {
		fmt.Fprint(os.Stderr, "Usage: agentkms plugin install [--trust-key <key-file>] <binary-path>\n")
		return 1
	}
	sourcePath := fs.Arg(0)

	// Optional signature verification before copying.
	var verifier *plugin.Verifier
	if *trustKey != "" {
		pubKey, err := os.ReadFile(*trustKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read trust key %q: %v\n", *trustKey, err)
			return 1
		}
		v, err := plugin.NewVerifier(pubKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid trust key: %v\n", err)
			return 1
		}
		verifier = v
	}

	if verifier != nil {
		sigPath := sourcePath + ".sig"
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read .sig sidecar %q: %v\n", sigPath, err)
			return 1
		}
		if err := verifier.Verify(sourcePath, sig); err != nil {
			fmt.Fprintf(os.Stderr, "signature verification failed: %v\n", err)
			return 1
		}
	}

	reg := plugin.NewRegistry()
	mgr := plugin.NewManager(pluginDir, reg)

	meta, err := mgr.Install(sourcePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
		return 1
	}

	// Copy the .sig sidecar if present.
	if verifier != nil {
		sigSrc := sourcePath + ".sig"
		sigDst := meta.Path + ".sig"
		if err := copyFile(sigSrc, sigDst); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to copy .sig sidecar: %v\n", err)
		}
	}

	fmt.Printf("Installed plugin %s to %s\n", meta.Name, meta.Path)
	return 0
}

// pluginList prints all installed plugins with their signing status.
//
//	akms plugin list
func pluginList(pluginDir string) int {
	reg := plugin.NewRegistry()
	mgr := plugin.NewManager(pluginDir, reg)

	plugins, err := mgr.Installed()
	if err != nil {
		fmt.Fprintf(os.Stderr, "list failed: %v\n", err)
		return 1
	}

	if len(plugins) == 0 {
		fmt.Println("No plugins installed.")
		return 0
	}

	fmt.Printf("%-30s %-10s %s\n", "NAME", "SIGNING", "PATH")
	for _, p := range plugins {
		sigStatus := signingStatus(p.Path)
		fmt.Printf("%-30s %-10s %s\n", p.Name, sigStatus, p.Path)
	}
	return 0
}

// pluginRemove removes an installed plugin binary (and its .sig sidecar).
//
//	akms plugin remove <name>
func pluginRemove(pluginDir string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentkms plugin remove <name>")
		return 1
	}
	name := args[0]

	reg := plugin.NewRegistry()
	mgr := plugin.NewManager(pluginDir, reg)

	// Remove .sig sidecar first (best-effort).
	_ = os.Remove(filepath.Join(pluginDir, "agentkms-plugin-"+name+".sig"))

	if err := mgr.Remove(name); err != nil {
		fmt.Fprintf(os.Stderr, "remove failed: %v\n", err)
		return 1
	}

	fmt.Printf("Removed plugin %s\n", name)
	return 0
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func defaultPluginDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".agentkms/plugins"
	}
	return filepath.Join(home, ".agentkms", "plugins")
}

// signingStatus returns a human-readable signing status for a plugin binary.
// It reads the .sig sidecar without a public key (so it can only report
// "signed" meaning a .sig file exists, or "unsigned" meaning it does not).
func signingStatus(binaryPath string) string {
	sigPath := binaryPath + ".sig"
	if _, err := os.Stat(sigPath); err == nil {
		return "signed"
	}
	return "unsigned"
}

// copyFile copies src to dst, preserving permissions.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
