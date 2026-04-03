package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockExporter struct {
	events []AuditEvent
	err    error
}

func (m *mockExporter) Log(ctx context.Context, ev AuditEvent) error { return nil }
func (m *mockExporter) Flush(ctx context.Context) error              { return nil }
func (m *mockExporter) Export(ctx context.Context, start, end time.Time) ([]AuditEvent, error) {
	return m.events, m.err
}

type plainSink struct{}
func (p *plainSink) Log(ctx context.Context, ev AuditEvent) error { return nil }
func (p *plainSink) Flush(ctx context.Context) error              { return nil }

func TestMultiAuditor_Export(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	// Scenario 1: No sinks
	m1 := NewMultiAuditor()
	if _, err := m1.Export(ctx, now, now); err == nil {
		t.Fatal("Expected error with no sinks")
	}

	// Scenario 2: Sinks, but no exporter
	m2 := NewMultiAuditor(&plainSink{})
	if _, err := m2.Export(ctx, now, now); err == nil {
		t.Fatal("Expected error with no exporters")
	}

	// Scenario 3: First exporter fails, second succeeds
	m3 := NewMultiAuditor(
		&mockExporter{err: errors.New("fail")},
		&mockExporter{events: []AuditEvent{{EventID: "ok"}}},
	)
	events, err := m3.Export(ctx, now, now)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(events) != 1 || events[0].EventID != "ok" {
		t.Fatalf("Expected event 'ok', got %v", events)
	}
}
