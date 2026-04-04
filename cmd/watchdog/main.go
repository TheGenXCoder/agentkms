// cmd/watchdog — AgentKMS NBDE watchdog daemon.
//
// Runs as a root systemd service on Linux.  Continuously validates the
// machine's mTLS session against AgentKMS.  On consecutive validation
// failures, executes the configured destruction action.
//
// SECURITY INVARIANTS:
//   - The machine cert/key in /etc/agentkms are read once at startup.
//   - Validation is mTLS — no static tokens that can be sniffed.
//   - Destruction is irreversible: luksErase destroys the LUKS header.
//   - A grace period prevents false positives from transient network issues.
//   - systemd WatchdogSec integration: if the watchdog itself is killed,
//     systemd can restart it or trigger a system action.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agentkms/agentkms/pkg/tlsutil"
)

// Destroyer abstracts the disk destruction action for testability.
type Destroyer interface {
	Destroy(device string) error
}

// luksDestroyer calls cryptsetup luksErase — permanently destroys the LUKS header.
type luksDestroyer struct{}

func (l *luksDestroyer) Destroy(device string) error {
	slog.Error("NBDE: EXECUTING LUKS ERASE — drive will be permanently inaccessible",
		"device", device)
	// cryptsetup luksErase overwrites all LUKS key slots.
	// The encrypted data remains but is unrecoverable without the master key.
	cmd := exec.Command("cryptsetup", "luksErase", "--batch-mode", device)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("luksErase: %w", err)
	}
	return nil
}

// poweroffDestroyer forces an immediate power-off without destroying the drive.
// Use this if you want to prevent access but not destroy data.
type poweroffDestroyer struct{}

func (p *poweroffDestroyer) Destroy(_ string) error {
	slog.Warn("NBDE: forcing immediate power-off")
	return exec.Command("systemctl", "poweroff", "--force").Run()
}

// logOnlyDestroyer logs but does not destroy.  Used for testing.
type logOnlyDestroyer struct{}

func (l *logOnlyDestroyer) Destroy(device string) error {
	slog.Error("NBDE: validation failed — would destroy device (log-only mode)", "device", device)
	return nil
}

func main() {
	serverAddr := flag.String("server", "https://agentkms.internal:8443", "AgentKMS server address")
	dir := flag.String("dir", "/etc/agentkms", "Directory containing mTLS certs (ca.crt, client.crt, client.key)")
	device := flag.String("device", "", "LUKS device to protect (e.g. /dev/nvme0n1p2). Required.")
	interval := flag.Duration("interval", 60*time.Second, "Validation interval")
	grace := flag.Int("grace", 3, "Consecutive failures before destruction")
	mode := flag.String("mode", "erase", "Destruction mode: erase|poweroff|log-only")
	flag.Parse()

	if *device == "" && *mode != "log-only" {
		slog.Error("--device is required (unless --mode=log-only)")
		os.Exit(1)
	}

	// Build TLS config from /etc/agentkms certs.
	caBytes, err := os.ReadFile(filepath.Join(*dir, "ca.crt"))
	if err != nil {
		slog.Error("failed to read CA cert", "error", err)
		os.Exit(1)
	}
	certBytes, err := os.ReadFile(filepath.Join(*dir, "client.crt"))
	if err != nil {
		slog.Error("failed to read client cert", "error", err)
		os.Exit(1)
	}
	keyBytes, err := os.ReadFile(filepath.Join(*dir, "client.key"))
	if err != nil {
		slog.Error("failed to read client key", "error", err)
		os.Exit(1)
	}

	tlsCfg, err := tlsutil.ClientTLSConfig(caBytes, certBytes, keyBytes)
	if err != nil {
		slog.Error("failed to build TLS config", "error", err)
		os.Exit(1)
	}

	var destroyer Destroyer
	switch *mode {
	case "erase":
		destroyer = &luksDestroyer{}
	case "poweroff":
		destroyer = &poweroffDestroyer{}
	case "log-only":
		destroyer = &logOnlyDestroyer{}
	default:
		slog.Error("unknown mode", "mode", *mode)
		os.Exit(1)
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	slog.Info("agentkms-watchdog started",
		"server", *serverAddr,
		"device", *device,
		"interval", interval.String(),
		"grace", *grace,
		"mode", *mode,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	run(ctx, client, *serverAddr, *device, *interval, *grace, destroyer)
}

// run is the watchdog loop — extracted for testability.
func run(
	ctx context.Context,
	client *http.Client,
	serverAddr string,
	device string,
	interval time.Duration,
	grace int,
	destroyer Destroyer,
) {
	failures := 0
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("agentkms-watchdog shutting down")
			return
		case <-ticker.C:
			if err := validate(client, serverAddr); err != nil {
				failures++
				slog.Warn("NBDE: validation failure",
					"consecutive_failures", failures,
					"grace", grace,
					"error", err,
				)
				if failures >= grace {
					slog.Error("NBDE: grace period exhausted — executing destruction",
						"consecutive_failures", failures,
						"mode", fmt.Sprintf("%T", destroyer),
					)
					if destroyErr := destroyer.Destroy(device); destroyErr != nil {
						slog.Error("NBDE: destruction failed", "error", destroyErr)
					}
					return
				}
			} else {
				if failures > 0 {
					slog.Info("NBDE: validation recovered", "previous_failures", failures)
					failures = 0
				}
				slog.Debug("NBDE: validation OK")
			}
		}
	}
}

// validate performs a single mTLS ping against AgentKMS.
func validate(client *http.Client, serverAddr string) error {
	resp, err := client.Get(serverAddr + "/healthz")
	if err != nil {
		return fmt.Errorf("network: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("revoked: server returned %d", resp.StatusCode)
	}
	return fmt.Errorf("unexpected status %d", resp.StatusCode)
}

// Extracted for use in tests without real files.
