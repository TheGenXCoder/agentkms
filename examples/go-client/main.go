// Example: Using AgentKMS from a Go application.
//
// This demonstrates the full lifecycle:
//   1. Authenticate via mTLS → receive session token
//   2. Fetch LLM credentials → use them for an API call
//   3. Revoke session token on shutdown
//
// No external dependencies — uses only the Go standard library.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

const akmsAddr = "https://127.0.0.1:8443"

func main() {
	// Load mTLS credentials from ~/.agentkms/dev/
	client, err := newMTLSClient()
	if err != nil {
		log.Fatalf("Failed to create mTLS client: %v", err)
	}

	// Step 1: Authenticate — get a session token
	token, err := authenticate(client)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}
	fmt.Printf("Authenticated. Token expires in 15 minutes.\n")

	// Step 2: Fetch LLM credentials
	apiKey, err := fetchCredential(client, token, "anthropic")
	if err != nil {
		log.Fatalf("Credential fetch failed: %v", err)
	}
	fmt.Printf("Got Anthropic API key: %s...%s\n", apiKey[:7], apiKey[len(apiKey)-4:])

	// Use the key for your LLM call here...
	// The key is in memory only — never write it to disk.

	// Step 3: Revoke session token when done
	if err := revoke(client, token); err != nil {
		log.Printf("Warning: revocation failed: %v", err)
	}
	fmt.Println("Session revoked. Credentials cleared.")
}

// newMTLSClient creates an HTTP client with mutual TLS using dev certificates.
func newMTLSClient() (*http.Client, error) {
	home, _ := os.UserHomeDir()
	certDir := filepath.Join(home, ".agentkms", "dev")

	// Find the first client directory
	clientsDir := filepath.Join(certDir, "clients")
	entries, err := os.ReadDir(clientsDir)
	if err != nil {
		return nil, fmt.Errorf("no client certs found in %s: %w", clientsDir, err)
	}
	clientDir := filepath.Join(clientsDir, entries[0].Name())

	cert, err := tls.LoadX509KeyPair(
		filepath.Join(clientDir, "client.crt"),
		filepath.Join(clientDir, "client.key"),
	)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caCert, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("load CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}, nil
}

func authenticate(client *http.Client) (string, error) {
	resp, err := client.Post(akmsAddr+"/auth/session", "application/json", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth failed (%d): %s", resp.StatusCode, body)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Token, nil
}

func fetchCredential(client *http.Client, token, provider string) (string, error) {
	req, _ := http.NewRequest("GET", akmsAddr+"/credentials/llm/"+provider, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("credential fetch failed (%d): %s", resp.StatusCode, body)
	}

	var result struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.APIKey, nil
}

func revoke(client *http.Client, token string) error {
	req, _ := http.NewRequest("POST", akmsAddr+"/auth/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke failed (%d): %s", resp.StatusCode, body)
	}
	return nil
}
