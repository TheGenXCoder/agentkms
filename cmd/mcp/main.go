// Command agentkms-mcp is a Model Context Protocol (MCP) server that exposes
// AgentKMS credential vending and cryptographic operations to any MCP-compatible
// AI tool (Claude Code, Cursor, Windsurf, etc.).
//
// It communicates over stdio (line-delimited JSON-RPC 2.0) and connects to a
// running AgentKMS instance over mTLS.
//
// Usage:
//
//	# Add to Claude Code settings:
//	{
//	  "mcpServers": {
//	    "agentkms": { "command": "agentkms-mcp" }
//	  }
//	}
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ── JSON-RPC 2.0 types ──────────────────────────────────────────────────────

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ── MCP types ────────────────────────────────────────────────────────────────

type toolDef struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

type toolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ── Server ───────────────────────────────────────────────────────────────────

type server struct {
	client  *http.Client
	addr    string
	token   string
	certDir string
}

func main() {
	s, err := newServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentkms-mcp: %v\n", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.writeError(nil, -32700, "Parse error")
			continue
		}

		s.handle(&req)
	}
}

func newServer() (*server, error) {
	home, _ := os.UserHomeDir()
	certDir := os.Getenv("AGENTKMS_CERT_DIR")
	if certDir == "" {
		certDir = filepath.Join(home, ".agentkms", "dev")
	}

	addr := os.Getenv("AGENTKMS_ADDR")
	if addr == "" {
		addr = "https://127.0.0.1:8443"
	}

	client, err := newMTLSClient(certDir)
	if err != nil {
		return nil, fmt.Errorf("mTLS setup failed: %w (run 'agentkms-dev enroll' first)", err)
	}

	return &server{
		client:  client,
		addr:    addr,
		certDir: certDir,
	}, nil
}

func newMTLSClient(certDir string) (*http.Client, error) {
	clientsDir := filepath.Join(certDir, "clients")
	entries, err := os.ReadDir(clientsDir)
	if err != nil {
		return nil, fmt.Errorf("no client certs in %s", clientsDir)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no client cert directories found")
	}
	clientDir := filepath.Join(clientsDir, entries[0].Name())

	cert, err := tls.LoadX509KeyPair(
		filepath.Join(clientDir, "client.crt"),
		filepath.Join(clientDir, "client.key"),
	)
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		return nil, err
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

// ── Request dispatch ─────────────────────────────────────────────────────────

func (s *server) handle(req *rpcRequest) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "notifications/initialized":
		// Notification — no response. Authenticate now.
		s.authenticate()
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(req)
	case "ping":
		s.write(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{}})
	default:
		if req.ID != nil {
			s.writeError(req.ID, -32601, "Method not found: "+req.Method)
		}
	}
}

func (s *server) handleInitialize(req *rpcRequest) {
	s.write(rpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "agentkms",
				"version": "1.0.0",
			},
		},
	})
}

func (s *server) handleToolsList(req *rpcRequest) {
	tools := []toolDef{
		{
			Name:        "agentkms_get_credential",
			Description: "Fetch a short-lived LLM API key from AgentKMS. The key is vended over mTLS, held in memory only, and never written to disk. Supported providers: anthropic, openai, google, azure, bedrock, mistral, groq, xai.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"provider": map[string]interface{}{
						"type":        "string",
						"description": "LLM provider name",
						"enum":        []string{"anthropic", "openai", "google", "azure", "bedrock", "mistral", "groq", "xai"},
					},
				},
				"required": []string{"provider"},
			},
		},
		{
			Name:        "agentkms_list_providers",
			Description: "List all LLM providers that have credentials stored in AgentKMS.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "agentkms_get_secret",
			Description: "Fetch a generic secret from AgentKMS by path (e.g., 'forge/telegram' for a Telegram bot token).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Secret path (e.g., 'forge/telegram', 'myapp/database')",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "agentkms_sign",
			Description: "Sign a payload using a key stored in AgentKMS. Returns the signature only — private key material never leaves the server.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"key_id": map[string]interface{}{
						"type":        "string",
						"description": "Key identifier",
					},
					"payload": map[string]interface{}{
						"type":        "string",
						"description": "Data to sign (will be SHA-256 hashed before signing)",
					},
					"algorithm": map[string]interface{}{
						"type":        "string",
						"description": "Signing algorithm",
						"enum":        []string{"ES256", "RS256", "EdDSA"},
						"default":     "ES256",
					},
				},
				"required": []string{"key_id", "payload"},
			},
		},
		{
			Name:        "agentkms_encrypt",
			Description: "Encrypt data using a key stored in AgentKMS. Returns ciphertext only.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"key_id": map[string]interface{}{
						"type":        "string",
						"description": "Encryption key identifier",
					},
					"plaintext": map[string]interface{}{
						"type":        "string",
						"description": "Data to encrypt",
					},
				},
				"required": []string{"key_id", "plaintext"},
			},
		},
		{
			Name:        "agentkms_decrypt",
			Description: "Decrypt data using a key stored in AgentKMS. Returns plaintext only.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"key_id": map[string]interface{}{
						"type":        "string",
						"description": "Encryption key identifier",
					},
					"ciphertext": map[string]interface{}{
						"type":        "string",
						"description": "Data to decrypt (base64-encoded, from a previous encrypt call)",
					},
				},
				"required": []string{"key_id", "ciphertext"},
			},
		},
	}

	s.write(rpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]interface{}{"tools": tools},
	})
}

func (s *server) handleToolsCall(req *rpcRequest) {
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.writeError(req.ID, -32602, "Invalid params")
		return
	}

	// Ensure we have a session token
	if s.token == "" {
		if err := s.authenticate(); err != nil {
			s.toolError(req.ID, "Authentication failed: "+err.Error())
			return
		}
	}

	switch params.Name {
	case "agentkms_get_credential":
		s.callGetCredential(req.ID, params.Arguments)
	case "agentkms_list_providers":
		s.callListProviders(req.ID)
	case "agentkms_get_secret":
		s.callGetSecret(req.ID, params.Arguments)
	case "agentkms_sign":
		s.callSign(req.ID, params.Arguments)
	case "agentkms_encrypt":
		s.callEncrypt(req.ID, params.Arguments)
	case "agentkms_decrypt":
		s.callDecrypt(req.ID, params.Arguments)
	default:
		s.writeError(req.ID, -32602, "Unknown tool: "+params.Name)
	}
}

// ── Tool implementations ─────────────────────────────────────────────────────

func (s *server) callGetCredential(id json.RawMessage, args map[string]interface{}) {
	provider, _ := args["provider"].(string)
	if provider == "" {
		s.toolError(id, "provider is required")
		return
	}

	body, err := s.apiGet("/credentials/llm/" + provider)
	if err != nil {
		s.toolError(id, err.Error())
		return
	}

	var cred struct {
		Provider  string `json:"provider"`
		ExpiresAt string `json:"expires_at"`
	}
	json.Unmarshal(body, &cred)

	s.toolResult(id, fmt.Sprintf("Credential vended for %s (expires: %s). Key is available in the response but not displayed for security.", cred.Provider, cred.ExpiresAt))
}

func (s *server) callListProviders(id json.RawMessage) {
	body, err := s.apiGet("/credentials/llm")
	if err != nil {
		s.toolError(id, err.Error())
		return
	}

	var result struct {
		Providers []string `json:"providers"`
	}
	json.Unmarshal(body, &result)

	s.toolResult(id, fmt.Sprintf("Available providers: %s", strings.Join(result.Providers, ", ")))
}

func (s *server) callGetSecret(id json.RawMessage, args map[string]interface{}) {
	path, _ := args["path"].(string)
	if path == "" {
		s.toolError(id, "path is required")
		return
	}

	_, err := s.apiGet("/credentials/generic/" + path)
	if err != nil {
		s.toolError(id, err.Error())
		return
	}

	s.toolResult(id, fmt.Sprintf("Secret retrieved for path '%s'. Value is available in the response but not displayed for security.", path))
}

func (s *server) callSign(id json.RawMessage, args map[string]interface{}) {
	keyID, _ := args["key_id"].(string)
	payload, _ := args["payload"].(string)
	alg, _ := args["algorithm"].(string)
	if alg == "" {
		alg = "ES256"
	}

	reqBody := map[string]interface{}{
		"payload":   payload,
		"algorithm": alg,
	}

	body, err := s.apiPost("/sign/"+keyID, reqBody)
	if err != nil {
		s.toolError(id, err.Error())
		return
	}

	var result struct {
		Signature  string `json:"signature"`
		KeyVersion int    `json:"key_version"`
	}
	json.Unmarshal(body, &result)

	s.toolResult(id, fmt.Sprintf("Signed with key '%s' (version %d, algorithm %s). Signature: %s...%s",
		keyID, result.KeyVersion, alg, result.Signature[:8], result.Signature[len(result.Signature)-4:]))
}

func (s *server) callEncrypt(id json.RawMessage, args map[string]interface{}) {
	keyID, _ := args["key_id"].(string)
	plaintext, _ := args["plaintext"].(string)

	body, err := s.apiPost("/encrypt/"+keyID, map[string]interface{}{"plaintext": plaintext})
	if err != nil {
		s.toolError(id, err.Error())
		return
	}

	var result struct {
		Ciphertext string `json:"ciphertext"`
	}
	json.Unmarshal(body, &result)

	s.toolResult(id, fmt.Sprintf("Encrypted with key '%s'. Ciphertext length: %d bytes.", keyID, len(result.Ciphertext)))
}

func (s *server) callDecrypt(id json.RawMessage, args map[string]interface{}) {
	keyID, _ := args["key_id"].(string)
	ciphertext, _ := args["ciphertext"].(string)

	body, err := s.apiPost("/decrypt/"+keyID, map[string]interface{}{"ciphertext": ciphertext})
	if err != nil {
		s.toolError(id, err.Error())
		return
	}

	var result struct {
		Plaintext string `json:"plaintext"`
	}
	json.Unmarshal(body, &result)

	s.toolResult(id, fmt.Sprintf("Decrypted successfully. Plaintext length: %d bytes.", len(result.Plaintext)))
}

// ── AgentKMS API helpers ─────────────────────────────────────────────────────

func (s *server) authenticate() error {
	resp, err := s.client.Post(s.addr+"/auth/session", "application/json", nil)
	if err != nil {
		return fmt.Errorf("cannot reach AgentKMS at %s: %w", s.addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth failed (%d): %s", resp.StatusCode, body)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	s.token = result.Token
	return nil
}

func (s *server) apiGet(path string) ([]byte, error) {
	req, _ := http.NewRequest("GET", s.addr+path, nil)
	req.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		// Token expired — re-auth and retry once
		if err := s.authenticate(); err != nil {
			return nil, err
		}
		req, _ = http.NewRequest("GET", s.addr+path, nil)
		req.Header.Set("Authorization", "Bearer "+s.token)
		resp, err = s.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ = io.ReadAll(resp.Body)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AgentKMS %s returned %d: %s", path, resp.StatusCode, body)
	}
	return body, nil
}

func (s *server) apiPost(path string, payload interface{}) ([]byte, error) {
	data, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", s.addr+path, strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		if err := s.authenticate(); err != nil {
			return nil, err
		}
		req, _ = http.NewRequest("POST", s.addr+path, strings.NewReader(string(data)))
		req.Header.Set("Authorization", "Bearer "+s.token)
		req.Header.Set("Content-Type", "application/json")
		resp, err = s.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ = io.ReadAll(resp.Body)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AgentKMS %s returned %d: %s", path, resp.StatusCode, body)
	}
	return body, nil
}

// ── Response helpers ─────────────────────────────────────────────────────────

func (s *server) write(resp rpcResponse) {
	data, _ := json.Marshal(resp)
	fmt.Fprintf(os.Stdout, "%s\n", data)
}

func (s *server) writeError(id json.RawMessage, code int, msg string) {
	s.write(rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: msg},
	})
}

func (s *server) toolResult(id json.RawMessage, text string) {
	s.write(rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]interface{}{
			"content": []contentItem{{Type: "text", Text: text}},
		},
	})
}

func (s *server) toolError(id json.RawMessage, msg string) {
	s.write(rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]interface{}{
			"content":  []contentItem{{Type: "text", Text: "Error: " + msg}},
			"isError":  true,
		},
	})
}
