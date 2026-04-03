package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSplunkAuditSink_Log(t *testing.T) {
	ctx := context.Background()

	// 1. Setup mock HEC server.
	var receivedBody []byte
	var receivedToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("Authorization")
		var err error
		// Read all data from r.Body.
		buf := make([]byte, r.ContentLength)
		_, err = r.Body.Read(buf)
		if err != nil && err.Error() != "EOF" {
			t.Errorf("failed to read body: %v", err)
		}
		receivedBody = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// 2. Construct sink.
	cfg := SplunkConfig{
		Address:    server.URL,
		Token:      "test-token",
		BufferSize: 1,
	}
	sink, err := NewSplunkAuditSink(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create sink: %v", err)
	}

	// 3. Log an event.
	ev, _ := New()
	ev.Operation = OperationSign
	ev.Outcome = OutcomeSuccess
	ev.KeyID = "test-key"

	if err := sink.Log(ctx, ev); err != nil {
		t.Fatalf("Log() failed: %v", err)
	}

	// 4. Verify results.
	if receivedToken != "Splunk test-token" {
		t.Errorf("expected token %q, got %q", "Splunk test-token", receivedToken)
	}

	var se splunkEvent
	if err := json.Unmarshal(receivedBody, &se); err != nil {
		t.Fatalf("failed to unmarshal splunk event: %v", err)
	}

	if se.Event.EventID != ev.EventID {
		t.Errorf("expected event ID %q, got %q", ev.EventID, se.Event.EventID)
	}
	if se.Event.Operation != OperationSign {
		t.Errorf("expected operation %q, got %q", OperationSign, se.Event.Operation)
	}
}

func TestSplunkAuditSink_Batching(t *testing.T) {
	ctx := context.Background()

	var receivedCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HEC expects multiple JSON objects concatenated.
		dec := json.NewDecoder(r.Body)
		for dec.More() {
			var se splunkEvent
			if err := dec.Decode(&se); err != nil {
				t.Errorf("failed to decode splunk event: %v", err)
			}
			receivedCount++
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := SplunkConfig{
		Address:    server.URL,
		Token:      "test-token",
		BufferSize: 2,
	}
	sink, err := NewSplunkAuditSink(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create sink: %v", err)
	}

	// First log should not trigger a write (buffered).
	ev1, _ := New()
	if err := sink.Log(ctx, ev1); err != nil {
		t.Fatalf("Log(1) failed: %v", err)
	}
	if receivedCount != 0 {
		t.Errorf("expected 0 events, got %d", receivedCount)
	}

	// Second log should trigger a write of both events.
	ev2, _ := New()
	if err := sink.Log(ctx, ev2); err != nil {
		t.Fatalf("Log(2) failed: %v", err)
	}
	if receivedCount != 2 {
		t.Errorf("expected 2 events, got %d", receivedCount)
	}
}

func TestSplunkAuditSink_Flush(t *testing.T) {
	ctx := context.Background()

	var receivedCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		for dec.More() {
			var se splunkEvent
			if err := dec.Decode(&se); err != nil {
				t.Errorf("failed to decode splunk event: %v", err)
			}
			receivedCount++
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := SplunkConfig{
		Address:    server.URL,
		Token:      "test-token",
		BufferSize: 10,
	}
	sink, err := NewSplunkAuditSink(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create sink: %v", err)
	}

	ev1, _ := New()
	_ = sink.Log(ctx, ev1)
	if receivedCount != 0 {
		t.Errorf("expected 0 events before flush, got %d", receivedCount)
	}

	if err := sink.Flush(ctx); err != nil {
		t.Fatalf("Flush() failed: %v", err)
	}
	if receivedCount != 1 {
		t.Errorf("expected 1 event after flush, got %d", receivedCount)
	}
}
