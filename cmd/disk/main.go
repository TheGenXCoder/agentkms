// cmd/disk — AgentKMS NBDE disk unlock command for use in the initramfs.
//
// This binary is embedded into the mkinitcpio initramfs image.
// On boot, before the root filesystem is mounted, it:
//   1. Establishes networking (handled by the initramfs hook).
//   2. Loads the machine's mTLS client certificate from /etc/agentkms.
//   3. Fetches the LUKS master key from AgentKMS via GET /credentials/generic/disk/{machine-id}.
//   4. Pipes the key directly into cryptsetup luksOpen.
//   5. Zeros the key from memory.
//
// Usage in mkinitcpio runtime hook:
//
//	/usr/bin/agentkms-disk unlock \
//	  --server https://kms.yourdomain.com \
//	  --machine-id arch-laptop-01 \
//	  --device /dev/nvme0n1p2
//
// If the key fetch fails, the hook falls back to asking for a passphrase
// (via a LUKS recovery slot that should always exist).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/agentkms/agentkms/pkg/tlsutil"
)

func main() {
	serverAddr := flag.String("server", "https://agentkms.internal:8443", "AgentKMS server address")
	dir := flag.String("dir", "/etc/agentkms", "Directory containing mTLS certs")
	machineID := flag.String("machine-id", "", "Machine identifier (used as kv path: disk/{machine-id})")
	device := flag.String("device", "", "LUKS device to unlock (e.g. /dev/nvme0n1p2)")
	outputKey := flag.Bool("output-key", false, "Print the raw key to stdout instead of running cryptsetup")
	mapperName := flag.String("mapper", "root", "cryptsetup mapper name (default: root)")
	flag.Parse()

	if *machineID == "" || *device == "" {
		fmt.Fprintln(os.Stderr, "Usage: agentkms-disk --machine-id <id> --device <dev>")
		os.Exit(1)
	}

	caBytes, err := os.ReadFile(filepath.Join(*dir, "ca.crt"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentkms-disk: read ca: %v\n", err)
		os.Exit(1)
	}
	certBytes, err := os.ReadFile(filepath.Join(*dir, "client.crt"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentkms-disk: read cert: %v\n", err)
		os.Exit(1)
	}
	keyBytes, err := os.ReadFile(filepath.Join(*dir, "client.key"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentkms-disk: read key: %v\n", err)
		os.Exit(1)
	}

	tlsCfg, err := tlsutil.ClientTLSConfig(caBytes, certBytes, keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentkms-disk: tls config: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	luksKey, err := fetchLUKSKey(client, *serverAddr, *machineID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentkms-disk: fetch key: %v\n", err)
		os.Exit(1) // initramfs will fall back to passphrase prompt
	}
	defer zeroBytes(luksKey)

	if *outputKey {
		os.Stdout.Write(luksKey)
		return
	}

	// Pipe the key into cryptsetup luksOpen.
	if err := openLUKS(*device, *mapperName, luksKey); err != nil {
		fmt.Fprintf(os.Stderr, "agentkms-disk: luksOpen: %v\n", err)
		os.Exit(1)
	}
}

type genericCredResponse struct {
	Secrets map[string]string `json:"secrets"`
}

func fetchLUKSKey(client *http.Client, serverAddr, machineID string) ([]byte, error) {
	url := serverAddr + "/credentials/generic/disk/" + machineID
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var cred genericCredResponse
	if err := json.NewDecoder(resp.Body).Decode(&cred); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	keyStr, ok := cred.Secrets["luks_key"]
	if !ok || keyStr == "" {
		return nil, fmt.Errorf("luks_key not found in credential response")
	}

	return []byte(keyStr), nil
}

func openLUKS(device, mapperName string, key []byte) error {
	// cryptsetup luksOpen reads the key from stdin when --key-file=- is given.
	cmd := exec.Command("cryptsetup", "luksOpen", device, mapperName, "--key-file=-")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		defer stdin.Close()
		stdin.Write(key)
		zeroBytes(key)
	}()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
