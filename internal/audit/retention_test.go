package audit

import (
	"strings"
	"testing"
	"time"
)

// helper: makeEvent creates an AuditEvent with the given timestamp.
func makeEvent(t *testing.T, ts time.Time) AuditEvent {
	t.Helper()
	id, err := NewEventID()
	if err != nil {
		t.Fatalf("NewEventID: %v", err)
	}
	return AuditEvent{
		EventID:   id,
		Timestamp: ts,
		CallerID:  "test@team",
		Operation: OperationSign,
		Outcome:   OutcomeSuccess,
	}
}

// ── Prune tests ──────────────────────────────────────────────────────────────

func TestPruner_AllWithinRetention(t *testing.T) {
	now := time.Now().UTC()
	pruner := NewRetentionPruner(24 * time.Hour)

	events := []AuditEvent{
		makeEvent(t, now.Add(-1*time.Hour)),
		makeEvent(t, now.Add(-12*time.Hour)),
		makeEvent(t, now.Add(-23*time.Hour)),
	}

	result := pruner.Prune(events, now)
	if len(result) != 3 {
		t.Fatalf("expected 3 events, got %d", len(result))
	}
}

func TestPruner_AllExpired(t *testing.T) {
	now := time.Now().UTC()
	pruner := NewRetentionPruner(24 * time.Hour)

	events := []AuditEvent{
		makeEvent(t, now.Add(-25*time.Hour)),
		makeEvent(t, now.Add(-48*time.Hour)),
		makeEvent(t, now.Add(-72*time.Hour)),
	}

	result := pruner.Prune(events, now)
	if len(result) != 0 {
		t.Fatalf("expected 0 events, got %d", len(result))
	}
}

func TestPruner_MixedAges(t *testing.T) {
	now := time.Now().UTC()
	pruner := NewRetentionPruner(24 * time.Hour)

	events := []AuditEvent{
		makeEvent(t, now.Add(-1*time.Hour)),   // within
		makeEvent(t, now.Add(-12*time.Hour)),  // within
		makeEvent(t, now.Add(-23*time.Hour)),  // within
		makeEvent(t, now.Add(-25*time.Hour)),  // expired
		makeEvent(t, now.Add(-100*time.Hour)), // expired
	}

	result := pruner.Prune(events, now)
	if len(result) != 3 {
		t.Fatalf("expected 3 events (2 pruned), got %d", len(result))
	}
}

func TestPruner_ExactBoundary(t *testing.T) {
	now := time.Now().UTC()
	pruner := NewRetentionPruner(24 * time.Hour)

	// Event exactly at the 24h boundary should be kept (inclusive).
	boundary := now.Add(-24 * time.Hour)
	events := []AuditEvent{
		makeEvent(t, boundary),
	}

	result := pruner.Prune(events, now)
	if len(result) != 1 {
		t.Fatalf("expected 1 event (boundary inclusive), got %d", len(result))
	}
}

func TestPruner_CustomRetention(t *testing.T) {
	now := time.Now().UTC()
	pruner := NewRetentionPruner(1 * time.Hour)

	events := []AuditEvent{
		makeEvent(t, now.Add(-30*time.Minute)), // within 1h
		makeEvent(t, now.Add(-59*time.Minute)), // within 1h
		makeEvent(t, now.Add(-2*time.Hour)),    // expired (>1h)
		makeEvent(t, now.Add(-5*time.Hour)),    // expired (>1h)
	}

	result := pruner.Prune(events, now)
	if len(result) != 2 {
		t.Fatalf("expected 2 events with 1h retention, got %d", len(result))
	}
}

// ── PruneHint tests ──────────────────────────────────────────────────────────

func TestPruneHint_NothingPruned(t *testing.T) {
	pruner := NewRetentionPruner(24 * time.Hour)

	hint := pruner.PruneHint(10, 10)
	if hint != "" {
		t.Fatalf("expected empty string when nothing pruned, got %q", hint)
	}
}

func TestPruneHint_SomePruned(t *testing.T) {
	pruner := NewRetentionPruner(24 * time.Hour)

	hint := pruner.PruneHint(47, 33)

	// Must mention the count of pruned events.
	if !strings.Contains(hint, "14") {
		t.Errorf("hint should contain pruned count '14', got %q", hint)
	}
	// Must mention the total before count.
	if !strings.Contains(hint, "47") {
		t.Errorf("hint should contain total '47', got %q", hint)
	}
	// Must mention the Pro upgrade extension.
	if !strings.Contains(hint, "c9-retention-unlimited") {
		t.Errorf("hint should contain 'c9-retention-unlimited', got %q", hint)
	}
}

func TestPruneHint_AllPruned(t *testing.T) {
	pruner := NewRetentionPruner(24 * time.Hour)

	hint := pruner.PruneHint(25, 0)

	if hint == "" {
		t.Fatal("expected non-empty hint when all events pruned")
	}
	// Should mention all were pruned.
	if !strings.Contains(hint, "25") {
		t.Errorf("hint should reference total count '25', got %q", hint)
	}
	if !strings.Contains(hint, "c9-retention-unlimited") {
		t.Errorf("hint should contain 'c9-retention-unlimited', got %q", hint)
	}
}
