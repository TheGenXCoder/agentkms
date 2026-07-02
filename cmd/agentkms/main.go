// Unified AgentKMS CLI (UX consolidation D1).
//
//	agentkms init --dev | --prod --host <fqdn>
//	agentkms invite <user>
//	agentkms serve
//	agentkms run -path <path> -- <cmd>
//	agentkms plugin ...
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentkms/agentkms/internal/auth"
	"github.com/agentkms/agentkms/internal/bootstrap"
	"github.com/agentkms/agentkms/internal/devserver"
	"github.com/agentkms/agentkms/internal/invite"
	"github.com/agentkms/agentkms/internal/pki"
	"github.com/agentkms/agentkms/internal/state"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "init":
		os.Exit(runInit(args))
	case "invite":
		os.Exit(runInvite(args))
	case "serve":
		if err := runServe(args); err != nil {
			fmt.Fprintf(os.Stderr, "agentkms serve: %v\n", err)
			os.Exit(1)
		}
	case "run":
		os.Exit(runCredential(args))
	case "plugin":
		os.Exit(runPlugin(args))
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`agentkms — unified AgentKMS CLI

Commands:
  agentkms init --dev [--force]
  agentkms init --prod --host <fqdn> [--admin-user <name>] [--force]
  agentkms invite <user>
  agentkms serve [--addr <host:port>] [--dir <path>]
  agentkms run -path <path> -- <cmd> [args...]
  agentkms plugin install|list|remove ...

Golden path:
  agentkms init --prod --host agentkms.example.com
  agentkms invite alice
  # on client: kpm login <invite-code>
  agentkms serve

`)
}

func runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dev := fs.Bool("dev", false, "local loopback-only dev mode")
	prod := fs.Bool("prod", false, "bare-metal prod mode with hostname-bound PKI")
	host := fs.String("host", "", "FQDN for prod mode (required with --prod)")
	adminUser := fs.String("admin-user", "admin", "first admin user for prod init invite")
	force := fs.Bool("force", false, "overwrite existing PKI")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *dev == *prod {
		fmt.Fprintln(os.Stderr, "error: specify exactly one of --dev or --prod")
		return 1
	}

	ctx := context.Background()

	if *dev {
		dir, err := state.DevDataDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		layout, err := pki.InitDev(dir, *force)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		cfg := &state.Config{
			Mode:        state.ModeDev,
			DataDir:     layout.Dir,
			ListenAddr:  "127.0.0.1:8443",
			TrustDomain: "catalyst9.local",
		}
		if err := state.Save(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "error: save state: %v\n", err)
			return 1
		}
		fmt.Printf("Dev AgentKMS initialized at %s\n", layout.Dir)
		fmt.Println("Next: agentkms serve")
		return 0
	}

	hostVal := strings.TrimSpace(*host)
	if hostVal == "" {
		fmt.Fprintln(os.Stderr, "error: --host is required for --prod")
		return 1
	}
	dir, err := state.ProdDataDir(hostVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	layout, err := pki.InitProd(dir, hostVal, *force)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fp, err := pki.Fingerprint(layout.CACertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: CA fingerprint: %v\n", err)
		return 1
	}
	store, err := bootstrap.NewFileStore(filepath.Join(dir, "bootstrap-tokens"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: bootstrap store: %v\n", err)
		return 1
	}
	rawToken, err := store.Create(ctx, auth.BootstrapRecord{
		UserID:            strings.TrimSpace(*adminUser),
		DeviceNamePattern: "*",
		ExpiresAt:         time.Now().UTC().Add(24 * time.Hour),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create invite token: %v\n", err)
		return 1
	}
	serverURL := fmt.Sprintf("https://%s:8443", hostVal)
	code, err := invite.Encode(invite.Payload{
		Version:       1,
		ServerURL:     serverURL,
		CAFingerprint: fp,
		Token:         rawToken,
		UserID:        strings.TrimSpace(*adminUser),
		ExpiresAt:     time.Now().Add(24 * time.Hour).Unix(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: encode invite: %v\n", err)
		return 1
	}
	listen := net.JoinHostPort(hostVal, "8443")
	cfg := &state.Config{
		Mode:        state.ModeProd,
		Host:        hostVal,
		DataDir:     layout.Dir,
		ListenAddr:  listen,
		TrustDomain: "catalyst9.local",
	}
	if err := state.Save(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: save state: %v\n", err)
		return 1
	}
	fmt.Printf("Prod AgentKMS initialized at %s\n", layout.Dir)
	fmt.Printf("CA fingerprint (SHA-256): %s\n", fp)
	fmt.Printf("Admin invite (valid 24h):\n  %s\n", code)
	fmt.Println("Next: agentkms serve")
	return 0
}

func runInvite(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentkms invite <user>")
		return 1
	}
	st, err := state.Load()
	if err != nil || st == nil {
		fmt.Fprintln(os.Stderr, "error: run agentkms init first")
		return 1
	}
	fp, err := pki.Fingerprint(filepath.Join(st.DataDir, "ca.crt"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	store, err := bootstrap.NewFileStore(filepath.Join(st.DataDir, "bootstrap-tokens"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	rawToken, err := store.Create(context.Background(), auth.BootstrapRecord{
		UserID:            args[0],
		DeviceNamePattern: "*",
		ExpiresAt:         time.Now().UTC().Add(24 * time.Hour),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	serverURL := st.ListenAddr
	if !strings.HasPrefix(serverURL, "https://") {
		if st.Mode == state.ModeDev {
			serverURL = "https://" + serverURL
		} else {
			serverURL = "https://" + serverURL
		}
	}
	code, err := invite.Encode(invite.Payload{
		Version:       1,
		ServerURL:     serverURL,
		CAFingerprint: fp,
		Token:         rawToken,
		UserID:        args[0],
		ExpiresAt:     time.Now().Add(24 * time.Hour).Unix(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("Invite for %s (valid 24h):\n  %s\n", args[0], code)
	return 0
}

func runServe(args []string) error {
	st, _ := state.Load()
	prepended := args
	if st != nil {
		hasDir, hasAddr := false, false
		for i, a := range args {
			if a == "--dir" && i+1 < len(args) {
				hasDir = true
			}
			if a == "--addr" {
				hasAddr = true
			}
		}
		if !hasDir {
			prepended = append([]string{"--dir", st.DataDir}, prepended...)
		}
		if !hasAddr && st.ListenAddr != "" {
			prepended = append([]string{"--addr", st.ListenAddr}, prepended...)
		}
		if st.Mode == state.ModeDev {
			addr := st.ListenAddr
			if !hasAddr {
				for i, a := range prepended {
					if a == "--addr" && i+1 < len(prepended) {
						addr = prepended[i+1]
					}
				}
			}
			if err := devserver.EnforceDevBind(addr); err != nil {
				return err
			}
		}
	}
	return devserver.RunServe(prepended)
}

// runCredential and runPlugin delegate to the existing cmd/cli implementation
// by re-execing the same binary with forwarded args (keeps one build target).
func runCredential(args []string) int {
	fmt.Fprintln(os.Stderr, "agentkms run: use kpm run for credential injection")
	fmt.Fprintln(os.Stderr, "  kpm run --from template -- your-command")
	return 1
}

func runPlugin(args []string) int {
	fmt.Fprintln(os.Stderr, "agentkms plugin: not yet merged into unified binary — use agentkms-mcp / kpm")
	return 1
}
