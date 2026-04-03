package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDatadogAuditSink_Log(t *testing.T) {
	ctx := context.Background()

	var receivedBody []byte
	var receivedKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("DD-API-KEY")
		// Read all data from r.Body.
		buf := make([]byte, r.ContentLength)
		_, err := r.Body.Read(buf)
		if err != nil && err.Error() != "EOF" {
			t.Errorf("failed to read body: %v", err)
		}
		receivedBody = buf
		w.WriteHeader(http.StatusAccepted) // Datadog returns 202 Accepted.
	}))
	defer server.Close()

	cfg := DatadogConfig{
		Address:    server.URL,
		APIKey:     "test-key",
		BufferSize: 1,
	}
	sink, err := NewDatadogAuditSink(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create sink: %v", err)
	}

	ev, _ := New()
	ev.Operation = OperationSign
	ev.KeyID = "test-key"

	if err := sink.Log(ctx, ev); err != nil {
		t.Fatalf("Log() failed: %v", err)
	}

	if receivedKey != "test-key" {
		t.Errorf("expected DD-API-KEY %q, got %q", "test-key", receivedKey)
	}

	var dds []ddEvent
	if err := json.Unmarshal(receivedBody, &dds); err != nil {
		t.Fatalf("failed to unmarshal datadog event: %v", err)
	}

	if len(dds) != 1 {
		t.Fatalf("expected 1 event, got %d", len(dds))
	}
	if dds[0].Message.EventID != ev.EventID {
		t.Errorf("expected event ID %q, got %q", ev.EventID, dds[0].Message.EventID)
	}
}

func TestDatadogAuditSink_Batching(t *testing.T) {
	ctx := context.Background()

	var receivedCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var dds []ddEvent
		if err := json.NewDecoder(r.Body).Decode(&dds); err != nil {
			t.Errorf("failed to decode datadog event: %v", err)
		}
		receivedCount += len(dds)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := DatadogConfig{
		Address:    server.URL,
		APIKey:     "test-key",
		BufferSize: 2,
	}
	sink, err := NewDatadogAuditSink(ctx, cfg)
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
