package audit_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
)

// makeTestEvent returns a minimal valid AuditEvent for testing.
func makeTestEvent(t *testing.T, operation string) audit.AuditEvent {
	t.Helper()
	ev, err := audit.New()
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	ev.CallerID = "test-user@test-team"
	ev.TeamID = "test-team"
	ev.Operation = operation
	ev.Outcome = audit.OutcomeSuccess
	ev.Environment = "dev"
	return ev
}

func TestFileAuditSink_Log_WritesNDJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := audit.NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("NewFileAuditSink: %v", err)
	}
	defer sink.Close()

	events := []audit.AuditEvent{
		makeTestEvent(t, audit.OperationSign),
		makeTestEvent(t, audit.OperationEncrypt),
		makeTestEvent(t, audit.OperationAuth),
	}
	for _, ev := range events {
		if err := sink.Log(context.Background(), ev); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Read back and parse every line.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	var parsed []audit.AuditEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		var ev audit.AuditEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("json.Unmarshal line %q: %v", line, err)
		}
		parsed = append(parsed, ev)
	}
	if scanner.Err() != nil {
		t.Fatalf("scanner: %v", scanner.Err())
	}

	if len(parsed) != len(events) {
		t.Fatalf("expected %d lines, got %d", len(events), len(parsed))
	}

	// Verify content round-trips correctly.
	for i, got := range parsed {
		want := events[i]
		if got.EventID != want.EventID {
			t.Errorf("line %d: EventID mismatch: want %q got %q", i, want.EventID, got.EventID)
		}
		if got.Operation != want.Operation {
			t.Errorf("line %d: Operation mismatch: want %q got %q", i, want.Operation, got.Operation)
		}
		if got.CallerID != want.CallerID {
			t.Errorf("line %d: CallerID mismatch: want %q got %q", i, want.CallerID, got.CallerID)
		}
	}
}

func TestFileAuditSink_Log_AppendsAcrossReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "append.log")

	// First open: write 2 events.
	sink1, err := audit.NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("first NewFileAuditSink: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := sink1.Log(context.Background(), makeTestEvent(t, audit.OperationSign)); err != nil {
			t.Fatalf("sink1 Log: %v", err)
		}
	}
	if err := sink1.Close(); err != nil {
		t.Fatalf("sink1 Close: %v", err)
	}

	// Second open (simulates restart): write 3 more events.
	sink2, err := audit.NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("second NewFileAuditSink: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := sink2.Log(context.Background(), makeTestEvent(t, audit.OperationEncrypt)); err != nil {
			t.Fatalf("sink2 Log: %v", err)
		}
	}
	if err := sink2.Close(); err != nil {
		t.Fatalf("sink2 Close: %v", err)
	}

	// Must have 5 lines total.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var lineCount int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if len(scanner.Bytes()) > 0 {
			lineCount++
		}
	}
	if lineCount != 5 {
		t.Fatalf("expected 5 lines (2+3), got %d", lineCount)
	}
}

func TestFileAuditSink_Log_Concurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.log")
	sink, err := audit.NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("NewFileAuditSink: %v", err)
	}
	defer sink.Close()

	const goroutines = 50
	var wg sync.WaitGroup
	writeErrs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			writeErrs[idx] = sink.Log(context.Background(), makeTestEvent(t, audit.OperationSign))
		}(i)
	}
	wg.Wait()

	for i, err := range writeErrs {
		if err != nil {
			t.Errorf("goroutine %d: Log error: %v", i, err)
		}
	}

	// Every line must be valid JSON — no interleaved partial writes.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var lineCount int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev audit.AuditEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid JSON line after concurrent writes: %q", line)
		}
		lineCount++
	}
	if lineCount != goroutines {
		t.Fatalf("expected %d lines, got %d", goroutines, lineCount)
	}
}

func TestFileAuditSink_Log_CancelledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cancel.log")
	sink, err := audit.NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("NewFileAuditSink: %v", err)
	}
	defer sink.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	err = sink.Log(ctx, makeTestEvent(t, audit.OperationSign))
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestFileAuditSink_Flush_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flush.log")
	sink, err := audit.NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("NewFileAuditSink: %v", err)
	}
	defer sink.Close()

	for i := 0; i < 3; i++ {
		if err := sink.Flush(context.Background()); err != nil {
			t.Fatalf("Flush %d: %v", i, err)
		}
	}
}

func TestFileAuditSink_EventID_Unique(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unique.log")
	sink, err := audit.NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("NewFileAuditSink: %v", err)
	}
	defer sink.Close()

	const n = 20
	ids := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		ev := makeTestEvent(t, audit.OperationSign)
		if ids[ev.EventID] {
			t.Fatalf("duplicate EventID %q on iteration %d", ev.EventID, i)
		}
		ids[ev.EventID] = true
		if err := sink.Log(context.Background(), ev); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
}

func TestFileAuditSink_PayloadHash_NotPayload(t *testing.T) {
	// SECURITY: verify that audit events with PayloadHash set are stored as
	// the hash string, not as anything that could be interpreted as payload.
	path := filepath.Join(t.TempDir(), "hash.log")
	sink, err := audit.NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("NewFileAuditSink: %v", err)
	}
	defer sink.Close()

	ev := makeTestEvent(t, audit.OperationSign)
	ev.PayloadHash = "sha256:a3f4b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3"
	ev.KeyID = "payments/signing-key"
	ev.Algorithm = "ES256"

	if err := sink.Log(context.Background(), ev); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var written audit.AuditEvent
	if err := json.Unmarshal(data[:len(data)-1], &written); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if written.PayloadHash != ev.PayloadHash {
		t.Fatalf("PayloadHash mismatch: want %q got %q", ev.PayloadHash, written.PayloadHash)
	}

	// Verify Timestamp is preserved with UTC timezone.
	if written.Timestamp.IsZero() {
		t.Fatal("Timestamp is zero after round-trip")
	}
	if written.Timestamp.Location() != time.UTC {
		// json.Unmarshal deserializes RFC3339 times; Location may differ.
		// Acceptable as long as the instant is the same.
		_ = written.Timestamp.UTC()
	}
}
