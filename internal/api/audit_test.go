package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/api"
	"github.com/agentkms/agentkms/internal/audit"
	"github.com/agentkms/agentkms/internal/backend"
	"github.com/agentkms/agentkms/internal/policy"
)

// ── AU-10: Audit Log Export ──────────────────────────────────────────────────

// exportableAuditor is a capturingAuditor that also implements audit.Exporter.
type exportableAuditor struct {
	capturingAuditor
}

func (a *exportableAuditor) Export(ctx context.Context, start, end time.Time) ([]audit.AuditEvent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []audit.AuditEvent
	for _, ev := range a.events {
		if (ev.Timestamp.After(start) || ev.Timestamp.Equal(start)) &&
			(ev.Timestamp.Before(end) || ev.Timestamp.Equal(end)) {
			out = append(out, ev)
		}
	}
	return out, nil
}

func TestHandleExportAuditLogs(t *testing.T) {
	b := backend.NewDevBackend()
	aud := &exportableAuditor{}
	// Use an engine that allows "audit_export".
	srv := newServerWithAuditor(t, b, aud, policy.AllowAllEngine{})

	// 1. Create some audit events.
	now := time.Now().UTC()
	aud.Log(context.Background(), audit.AuditEvent{
		EventID: "ev1", Timestamp: now.Add(-10 * time.Minute), Operation: "sign", Outcome: "success",
	})
	aud.Log(context.Background(), audit.AuditEvent{
		EventID: "ev2", Timestamp: now.Add(-5 * time.Minute), Operation: "encrypt", Outcome: "success",
	})
	aud.Log(context.Background(), audit.AuditEvent{
		EventID: "ev3", Timestamp: now, Operation: "decrypt", Outcome: "success",
	})

	// 2. Export with time range covering ev1 and ev2.
	start := now.Add(-15 * time.Minute).Format(time.RFC3339)
	end := now.Add(-2 * time.Minute).Format(time.RFC3339)
	path := "/audit/export?start=" + start + "&end=" + end

	rr := request(t, srv, http.MethodGet, path, nil)
	assertStatus(t, rr, http.StatusOK)

	if rr.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Errorf("expected Content-Type application/x-ndjson, got %q", rr.Header().Get("Content-Type"))
	}

	// 3. Verify response body contains ev1 and ev2.
	dec := json.NewDecoder(rr.Body)
	var received []audit.AuditEvent
	for dec.More() {
		var ev audit.AuditEvent
		if err := dec.Decode(&ev); err != nil {
			t.Fatalf("failed to decode exported event: %v", err)
		}
		received = append(received, ev)
	}

	if len(received) != 2 {
		t.Fatalf("expected 2 events, got %d", len(received))
	}
	if received[0].EventID != "ev1" || received[1].EventID != "ev2" {
		t.Errorf("received events mismatch: %+v", received)
	}
}

// ── LV-06: Credential Use Audit ──────────────────────────────────────────────

func TestHandleLogCredentialUse(t *testing.T) {
	b := backend.NewDevBackend()
	srv, aud := newAllowServer(t, b)

	body := map[string]string{
		"provider": "anthropic",
		"action":   "chat",
	}

	rr := request(t, srv, http.MethodPost, "/audit/use", jsonReader(t, body))
	assertStatus(t, rr, http.StatusNoContent)

	ev, ok := aud.lastEvent()
	if !ok {
		t.Fatal("no audit event recorded for credential use")
	}

	if ev.Operation != "credential_use" {
		t.Errorf("expected operation %q, got %q", "credential_use", ev.Operation)
	}
	if ev.KeyID != "llm/anthropic" {
		t.Errorf("expected key ID %q, got %q", "llm/anthropic", ev.KeyID)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// newServerWithAuditor is a helper to inject a custom auditor.
func newServerWithAuditor(t *testing.T, b backend.Backend, a audit.Auditor, p policy.EngineI) http.Handler {
	t.Helper()
	return api.NewServer(b, a, p, "dev")
}
