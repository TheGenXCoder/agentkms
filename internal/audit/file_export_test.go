package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileAuditSink_FlushExportClose(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "audit.log")

	sink, err := NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("Failed to create sink: %v", err)
	}

	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)

	ev1 := AuditEvent{EventID: "1", Timestamp: now.Add(-2 * time.Hour)}
	ev2 := AuditEvent{EventID: "2", Timestamp: now}
	ev3 := AuditEvent{EventID: "3", Timestamp: now.Add(2 * time.Hour)}

	// Write events
	for _, ev := range []AuditEvent{ev1, ev2, ev3} {
		if err := sink.Log(ctx, ev); err != nil {
			t.Fatalf("Failed to log event: %v", err)
		}
	}

	// Test Flush
	if err := sink.Flush(ctx); err != nil {
		t.Fatalf("Failed to flush: %v", err)
	}

	// Test Export
	start := now.Add(-1 * time.Hour)
	end := now.Add(1 * time.Hour)
	events, err := sink.Export(ctx, start, end)
	if err != nil {
		t.Fatalf("Failed to export: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event in range, got %d", len(events))
	}
	if events[0].EventID != "2" {
		t.Errorf("Expected event 2, got %s", events[0].EventID)
	}

	// Test Close
	if err := sink.Close(); err != nil {
		t.Fatalf("Failed to close: %v", err)
	}
}

func TestFileAuditSink_ExportCancel(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "audit.log")

	sink, err := NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("Failed to create sink: %v", err)
	}

	// Write some data
	err = sink.Log(context.Background(), AuditEvent{EventID: "1", Timestamp: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	sink.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Pre-cancel

	_, err = sink.Export(ctx, time.Time{}, time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("Expected error due to cancelled context")
	}
}

func TestFileAuditSink_FlushCancel(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "audit.log")

	sink, err := NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("Failed to create sink: %v", err)
	}
	defer os.Remove(path) // Cleanup since we don't close cleanly

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Pre-cancel

	err = sink.Flush(ctx)
	if err == nil {
		t.Fatal("Expected error due to cancelled context")
	}
}
