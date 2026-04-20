package mcp

// Server handles MCP protocol requests over JSON-RPC 2.0.
type Server struct{}

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
	return &Server{}
}

// HandleRequest processes a single JSON-RPC request and returns a response.
func (s *Server) HandleRequest(req Request) Response {
	return Response{}
}
