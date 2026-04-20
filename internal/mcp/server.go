package mcp

// Server handles MCP protocol requests over JSON-RPC 2.0.
type Server struct {
	tools []map[string]any
}

// Request represents a JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id,omitempty"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

// Error represents a JSON-RPC 2.0 error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewServer creates a new MCP server instance.
func NewServer() *Server {
	s := &Server{}
	s.tools = []map[string]any{
		{
			"name":        "get_credential",
			"description": "Retrieve a credential from the vault",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"name": map[string]any{"type": "string", "description": "Credential name"}},
				"required":   []string{"name"},
			},
		},
		{
			"name":        "list_providers",
			"description": "List available secret providers",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "get_secret",
			"description": "Retrieve a secret from a provider",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"key": map[string]any{"type": "string", "description": "Secret key"}},
				"required":   []string{"key"},
			},
		},
		{
			"name":        "sign",
			"description": "Sign data using a configured key",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"data": map[string]any{"type": "string", "description": "Data to sign"}},
				"required":   []string{"data"},
			},
		},
		{
			"name":        "encrypt",
			"description": "Encrypt data using a configured key",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"data": map[string]any{"type": "string", "description": "Data to encrypt"}},
				"required":   []string{"data"},
			},
		},
		{
			"name":        "decrypt",
			"description": "Decrypt data using a configured key",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"data": map[string]any{"type": "string", "description": "Data to decrypt"}},
				"required":   []string{"data"},
			},
		},
	}
	return s
}

// HandleRequest processes a single JSON-RPC request and returns a response.
func (s *Server) HandleRequest(req Request) Response {
	// Validate jsonrpc field
	if req.JSONRPC != "2.0" {
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &Error{Code: -32600, Message: "invalid request"},
		}
	}

	switch req.Method {
	case "initialize":
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"name":    "agentkms-mcp",
				"version": "0.3.0",
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
			},
		}

	case "tools/list":
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": s.tools,
			},
		}

	case "tools/call":
		toolName, _ := req.Params["name"].(string)
		for _, tool := range s.tools {
			if tool["name"] == toolName {
				// Tool exists but execution is not yet implemented
				return Response{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  map[string]any{"content": []map[string]any{{"type": "text", "text": "not implemented"}}},
				}
			}
		}
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &Error{Code: -32601, Message: "method not found"},
		}

	default:
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &Error{Code: -32601, Message: "method not found"},
		}
	}
}
