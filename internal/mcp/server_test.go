package mcp

import (
	"testing"
)

func TestMCP_Initialize(t *testing.T) {
	s := NewServer()
	resp := s.HandleRequest(Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	})

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", resp.JSONRPC)
	}
	if resp.ID != 1 {
		t.Errorf("expected id 1, got %v", resp.ID)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected result with server info, got nil")
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result to be map[string]any, got %T", resp.Result)
	}
	if _, exists := result["name"]; !exists {
		t.Error("expected result to contain 'name' field")
	}
	if _, exists := result["version"]; !exists {
		t.Error("expected result to contain 'version' field")
	}
	if _, exists := result["capabilities"]; !exists {
		t.Error("expected result to contain 'capabilities' field")
	}
}

func TestMCP_ToolsList(t *testing.T) {
	s := NewServer()
	resp := s.HandleRequest(Request{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	})

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", resp.JSONRPC)
	}
	if resp.ID != 2 {
		t.Errorf("expected id 2, got %v", resp.ID)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected result with tools list, got nil")
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result to be map[string]any, got %T", resp.Result)
	}
	tools, exists := result["tools"]
	if !exists {
		t.Fatal("expected result to contain 'tools' field")
	}

	toolList, ok := tools.([]map[string]any)
	if !ok {
		t.Fatalf("expected tools to be []map[string]any, got %T", tools)
	}
	if len(toolList) == 0 {
		t.Error("expected at least one tool in the list")
	}

	// Each tool should have a name and inputSchema
	for i, tool := range toolList {
		if _, exists := tool["name"]; !exists {
			t.Errorf("tool[%d] missing 'name' field", i)
		}
		if _, exists := tool["inputSchema"]; !exists {
			t.Errorf("tool[%d] missing 'inputSchema' field", i)
		}
	}
}

func TestMCP_ToolsCall_UnknownTool(t *testing.T) {
	s := NewServer()
	resp := s.HandleRequest(Request{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]any{
			"name": "nonexistent_tool",
		},
	})

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", resp.JSONRPC)
	}
	if resp.ID != 3 {
		t.Errorf("expected id 3, got %v", resp.ID)
	}
	if resp.Error == nil {
		t.Fatal("expected error for unknown tool, got nil")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601 (method not found), got %d", resp.Error.Code)
	}
}

func TestMCP_InvalidMethod(t *testing.T) {
	s := NewServer()
	resp := s.HandleRequest(Request{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "totally/bogus/method",
	})

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", resp.JSONRPC)
	}
	if resp.ID != 4 {
		t.Errorf("expected id 4, got %v", resp.ID)
	}
	if resp.Error == nil {
		t.Fatal("expected error for invalid method, got nil")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", resp.Error.Code)
	}
}

func TestMCP_MissingJSONRPC(t *testing.T) {
	s := NewServer()
	resp := s.HandleRequest(Request{
		// JSONRPC intentionally empty
		ID:     5,
		Method: "initialize",
	})

	if resp.Error == nil {
		t.Fatal("expected error for missing jsonrpc field, got nil")
	}
	// -32600 is Invalid Request per JSON-RPC 2.0 spec
	if resp.Error.Code != -32600 {
		t.Errorf("expected error code -32600 (invalid request), got %d", resp.Error.Code)
	}
}

func TestMCP_ToolsList_ContainsGetCredential(t *testing.T) {
	s := NewServer()
	resp := s.HandleRequest(Request{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "tools/list",
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected result, got nil")
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result to be map[string]any, got %T", resp.Result)
	}
	tools, ok := result["tools"].([]map[string]any)
	if !ok {
		t.Fatalf("expected tools to be []map[string]any, got %T", result["tools"])
	}

	found := false
	for _, tool := range tools {
		if tool["name"] == "get_credential" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected tools/list to include 'get_credential' tool")
	}
}

func TestMCP_ToolsList_ContainsListProviders(t *testing.T) {
	s := NewServer()
	resp := s.HandleRequest(Request{
		JSONRPC: "2.0",
		ID:      7,
		Method:  "tools/list",
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected result, got nil")
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result to be map[string]any, got %T", resp.Result)
	}
	tools, ok := result["tools"].([]map[string]any)
	if !ok {
		t.Fatalf("expected tools to be []map[string]any, got %T", result["tools"])
	}

	found := false
	for _, tool := range tools {
		if tool["name"] == "list_providers" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected tools/list to include 'list_providers' tool")
	}
}
