package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSIEMAuditSink_Log(t *testing.T) {
	ctx := context.Background()

	var receivedBody []byte
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("X-API-Key")
		// Read all data from r.Body.
		buf := make([]byte, r.ContentLength)
		_, err := r.Body.Read(buf)
		if err != nil && err.Error() != "EOF" {
			t.Errorf("failed to read body: %v", err)
		}
		receivedBody = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := SIEMConfig{
		Address:    server.URL,
		AuthHeader: "X-API-Key",
		AuthValue:  "test-key",
		BufferSize: 1,
	}
	sink, err := NewSIEMAuditSink(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create sink: %v", err)
	}

	ev, _ := New()
	ev.Operation = OperationSign
	ev.KeyID = "test-key"

	if err := sink.Log(ctx, ev); err != nil {
		t.Fatalf("Log() failed: %v", err)
	}

	if receivedAuth != "test-key" {
		t.Errorf("expected X-API-Key %q, got %q", "test-key", receivedAuth)
	}

	var evReceived AuditEvent
	if err := json.Unmarshal(receivedBody, &evReceived); err != nil {
		t.Fatalf("failed to unmarshal SIEM event: %v", err)
	}

	if evReceived.EventID != ev.EventID {
		t.Errorf("expected event ID %q, got %q", ev.EventID, evReceived.EventID)
	}
}

func TestSIEMAuditSink_Batching(t *testing.T) {
	ctx := context.Background()

	var receivedCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		for dec.More() {
			var ev AuditEvent
			if err := dec.Decode(&ev); err != nil {
				t.Errorf("failed to decode SIEM event: %v", err)
			}
			receivedCount++
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := SIEMConfig{
		Address:    server.URL,
		BufferSize: 2,
	}
	sink, err := NewSIEMAuditSink(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create sink: %v", err)
	}

	ev1, _ := New()
	_ = sink.Log(ctx, ev1)
	if receivedCount != 0 {
		t.Errorf("expected 0 events, got %d", receivedCount)
	}

	ev2, _ := New()
	_ = sink.Log(ctx, ev2)
	if receivedCount != 2 {
		t.Errorf("expected 2 events, got %d", receivedCount)
	}
}
