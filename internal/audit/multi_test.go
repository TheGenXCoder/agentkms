package audit_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/agentkms/agentkms/internal/audit"
)

// ── Stub audit sink for testing ───────────────────────────────────────────────

// stubSink is a test-only Auditor that records received events and can be
// configured to return errors.
//
// NOTE: stubSink is not safe for concurrent use.  MultiAuditor calls sinks
// sequentially (not in parallel), so no synchronisation is needed here.
type stubSink struct {
	name     string
	logErr   error // if non-nil, Log returns this error
	flushErr error // if non-nil, Flush returns this error

	logCount   atomic.Int64
	flushCount atomic.Int64
	events     []audit.AuditEvent
}

func (s *stubSink) Log(_ context.Context, ev audit.AuditEvent) error {
	s.logCount.Add(1)
	s.events = append(s.events, ev)
	return s.logErr
}

func (s *stubSink) Flush(_ context.Context) error {
	s.flushCount.Add(1)
	return s.flushErr
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestMultiAuditor_Log_FansOutToAllSinks(t *testing.T) {
	a := &stubSink{name: "sink-a"}
	b := &stubSink{name: "sink-b"}
	c := &stubSink{name: "sink-c"}

	multi := audit.NewMultiAuditor(a, b, c)
	ev := makeTestEvent(t, audit.OperationSign)

	if err := multi.Log(context.Background(), ev); err != nil {
		t.Fatalf("Log: %v", err)
	}

	for _, s := range []*stubSink{a, b, c} {
		if got := s.logCount.Load(); got != 1 {
			t.Errorf("sink %q: expected 1 Log call, got %d", s.name, got)
		}
	}
}

func TestMultiAuditor_Log_CallsAllSinksEvenOnPartialFailure(t *testing.T) {
	boom := errors.New("sink-b is unavailable")
	a := &stubSink{name: "sink-a"}
	b := &stubSink{name: "sink-b", logErr: boom}
	c := &stubSink{name: "sink-c"}

	multi := audit.NewMultiAuditor(a, b, c)
	err := multi.Log(context.Background(), makeTestEvent(t, audit.OperationEncrypt))

	// Error must be returned (sink-b failed).
	if err == nil {
		t.Fatal("expected error when one sink fails, got nil")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("expected joined error to contain sink-b error; got: %v", err)
	}

	// sink-a and sink-c must still have received the event.
	if a.logCount.Load() != 1 {
		t.Errorf("sink-a: expected 1 call, got %d", a.logCount.Load())
	}
	if c.logCount.Load() != 1 {
		t.Errorf("sink-c: expected 1 call, got %d", c.logCount.Load())
	}
}

func TestMultiAuditor_Log_AllSinksFailCollectsAllErrors(t *testing.T) {
	errA := errors.New("sink-a down")
	errB := errors.New("sink-b down")
	a := &stubSink{name: "sink-a", logErr: errA}
	b := &stubSink{name: "sink-b", logErr: errB}

	multi := audit.NewMultiAuditor(a, b)
	err := multi.Log(context.Background(), makeTestEvent(t, audit.OperationAuth))

	if err == nil {
		t.Fatal("expected error when all sinks fail")
	}
	if !errors.Is(err, errA) {
		t.Errorf("expected joined error to contain errA; got: %v", err)
	}
	if !errors.Is(err, errB) {
		t.Errorf("expected joined error to contain errB; got: %v", err)
	}
}

func TestMultiAuditor_Flush_CallsAllSinks(t *testing.T) {
	a := &stubSink{name: "sink-a"}
	b := &stubSink{name: "sink-b"}

	multi := audit.NewMultiAuditor(a, b)
	if err := multi.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if a.flushCount.Load() != 1 {
		t.Errorf("sink-a: expected 1 Flush call, got %d", a.flushCount.Load())
	}
	if b.flushCount.Load() != 1 {
		t.Errorf("sink-b: expected 1 Flush call, got %d", b.flushCount.Load())
	}
}

func TestMultiAuditor_Flush_ContinuesOnPartialFailure(t *testing.T) {
	flushErr := errors.New("sink-a flush failed")
	a := &stubSink{name: "sink-a", flushErr: flushErr}
	b := &stubSink{name: "sink-b"}

	multi := audit.NewMultiAuditor(a, b)
	err := multi.Flush(context.Background())

	if err == nil {
		t.Fatal("expected error when one sink flush fails")
	}
	if !errors.Is(err, flushErr) {
		t.Fatalf("expected flushErr in joined error; got: %v", err)
	}

	// sink-b must still have been flushed.
	if b.flushCount.Load() != 1 {
		t.Errorf("sink-b should have been flushed even after sink-a failed; count=%d",
			b.flushCount.Load())
	}
}

func TestMultiAuditor_EmptySinks_NoError(t *testing.T) {
	multi := audit.NewMultiAuditor() // no sinks

	if err := multi.Log(context.Background(), makeTestEvent(t, audit.OperationSign)); err != nil {
		t.Fatalf("Log with no sinks returned error: %v", err)
	}
	if err := multi.Flush(context.Background()); err != nil {
		t.Fatalf("Flush with no sinks returned error: %v", err)
	}
	if multi.Sinks() != 0 {
		t.Fatalf("Sinks() should be 0, got %d", multi.Sinks())
	}
}

func TestMultiAuditor_Sinks_ReturnsCount(t *testing.T) {
	a := &stubSink{}
	b := &stubSink{}
	multi := audit.NewMultiAuditor(a, b)
	if multi.Sinks() != 2 {
		t.Fatalf("expected 2 sinks, got %d", multi.Sinks())
	}
}

func TestMultiAuditor_Log_MultipleCalls_AllDelivered(t *testing.T) {
	sink := &stubSink{name: "single-sink"}
	multi := audit.NewMultiAuditor(sink)

	const n = 10
	for i := 0; i < n; i++ {
		if err := multi.Log(context.Background(), makeTestEvent(t, audit.OperationSign)); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	if sink.logCount.Load() != n {
		t.Fatalf("expected %d Log calls, got %d", n, sink.logCount.Load())
	}
}

func TestMultiAuditor_Log_EventFieldsPreserved(t *testing.T) {
	sink := &stubSink{name: "preserve"}
	multi := audit.NewMultiAuditor(sink)

	ev := makeTestEvent(t, audit.OperationDecrypt)
	ev.KeyID = "payments/signing-key"
	ev.KeyVersion = 3
	ev.Algorithm = "ES256"
	ev.PayloadHash = "sha256:abc123"
	ev.Outcome = audit.OutcomeDenied
	ev.DenyReason = "policy: operation not permitted for identity"
	ev.SourceIP = "10.0.1.42"
	ev.Environment = "production"

	if err := multi.Log(context.Background(), ev); err != nil {
		t.Fatalf("Log: %v", err)
	}

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 event in sink, got %d", len(sink.events))
	}
	got := sink.events[0]

	checks := []struct {
		field string
		want  interface{}
		got   interface{}
	}{
		{"EventID", ev.EventID, got.EventID},
		{"Operation", ev.Operation, got.Operation},
		{"KeyID", ev.KeyID, got.KeyID},
		{"KeyVersion", ev.KeyVersion, got.KeyVersion},
		{"Algorithm", ev.Algorithm, got.Algorithm},
		{"PayloadHash", ev.PayloadHash, got.PayloadHash},
		{"Outcome", ev.Outcome, got.Outcome},
		{"DenyReason", ev.DenyReason, got.DenyReason},
		{"SourceIP", ev.SourceIP, got.SourceIP},
		{"Environment", ev.Environment, got.Environment},
	}
	for _, c := range checks {
		if c.want != c.got {
			t.Errorf("field %s: want %v, got %v", c.field, c.want, c.got)
		}
	}
}
