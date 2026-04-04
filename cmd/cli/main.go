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

type credentialResponse struct {
	Secrets map[string]string `json:"secrets"`
}

func main() {
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
