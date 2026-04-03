package audit

import (
	"context"
	"testing"
	"time"
)

type mockExporter struct {
	events []AuditEvent
	err    error
}

func (m *mockExporter) Log(ctx context.Context, ev AuditEvent) error { return nil }
func (m *mockExporter) Flush(ctx context.Context) error              { return nil }
func (m *mockExporter) Export(ctx context.Context, start, end time.Time) (<-chan AuditEvent, <-chan error) {
	out := make(chan AuditEvent, len(m.events))
	errc := make(chan error, 1)
	for _, ev := range m.events {
		out <- ev
	}
	close(out)
	if m.err != nil {
		errc <- m.err
	}
	close(errc)
	return out, errc
}

type plainSink struct{}
func (p *plainSink) Log(ctx context.Context, ev AuditEvent) error { return nil }
func (p *plainSink) Flush(ctx context.Context) error              { return nil }

func TestMultiAuditor_Export(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	// Scenario 1: No sinks
	m1 := NewMultiAuditor()
	out1, errc1 := m1.Export(ctx, now, now)
	for range out1 {}
	if err := <-errc1; err == nil {
		t.Fatal("Expected error with no sinks")
	}

	// Scenario 2: Sinks, but no exporter
	m2 := NewMultiAuditor(&plainSink{})
	out2, errc2 := m2.Export(ctx, now, now)
	for range out2 {}
	if err := <-errc2; err == nil {
		t.Fatal("Expected error with no exporters")
	}

	// Scenario 3: Returns the first exporter
	m3 := NewMultiAuditor(
		&mockExporter{events: []AuditEvent{{EventID: "ok"}}},
		&mockExporter{events: []AuditEvent{{EventID: "ignored"}}},
	)
	out3, errc3 := m3.Export(ctx, now, now)
	var events []AuditEvent
	for ev := range out3 {
		events = append(events, ev)
	}
	if err := <-errc3; err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(events) != 1 || events[0].EventID != "ok" {
		t.Fatalf("Expected event 'ok', got %v", events)
	}
}
