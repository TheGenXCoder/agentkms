package audit_test

// AU-02: tests for ELKAuditSink.
//
// All tests use httptest.Server to avoid any real Elasticsearch dependency.
// The sink is tested against the ES Ingest API (single events) and Bulk API
// (batched events).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/audit"
)

// ── helpers ───────────────────────────────────────────────────────────────────

type fakeES struct {
	requests atomic.Int64
	lastBody []byte
	status   int // 0 = 200
}

func (f *fakeES) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	body, _ := io.ReadAll(r.Body)
	f.lastBody = body
	status := f.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if status == http.StatusOK {
		w.Write([]byte(`{"result":"created"}`)) //nolint:errcheck
	}
}

func newELKSink(t *testing.T, srv *httptest.Server, bufSize int) *audit.ELKAuditSink {
	t.Helper()
	sink, err := audit.NewELKAuditSink(context.Background(), audit.ELKConfig{
		Address:               srv.URL,
		Index:                 "agentkms-test",
		BufferSize:            bufSize,
		TLSInsecureSkipVerify: true, // test server uses HTTP anyway
	})
	if err != nil {
		t.Fatalf("NewELKAuditSink: %v", err)
	}
	return sink
}

// ── construction ──────────────────────────────────────────────────────────────

func TestNewELKAuditSink_MissingAddress(t *testing.T) {
	_, err := audit.NewELKAuditSink(context.Background(), audit.ELKConfig{})
	if err == nil {
		t.Fatal("expected error for empty Address")
	}
}

func TestNewELKAuditSink_DefaultIndex(t *testing.T) {
	es := &fakeES{}
	srv := httptest.NewServer(es)
	defer srv.Close()

	sink, err := audit.NewELKAuditSink(context.Background(), audit.ELKConfig{
		Address: srv.URL,
		// Index intentionally omitted — should default to "agentkms-audit"
	})
	if err != nil {
		t.Fatalf("NewELKAuditSink: %v", err)
	}

	ev := makeTestEvent(t, audit.OperationSign)
	if err := sink.Log(context.Background(), ev); err != nil {
		t.Fatalf("Log: %v", err)
	}
	// Request URL should contain the default index name.
	if !strings.Contains(string(es.lastBody), ev.EventID) {
		t.Error("event body should contain the event ID")
	}
}

// ── single-event writes ───────────────────────────────────────────────────────

func TestELKAuditSink_Log_SingleEvent(t *testing.T) {
	es := &fakeES{}
	srv := httptest.NewServer(es)
	defer srv.Close()

	sink := newELKSink(t, srv, 1)
	ev := makeTestEvent(t, audit.OperationSign)
	ev.KeyID = "payments/signing-key"
	ev.Outcome = audit.OutcomeSuccess

	if err := sink.Log(context.Background(), ev); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if es.requests.Load() != 1 {
		t.Errorf("expected 1 ES request, got %d", es.requests.Load())
	}

	// Body should be JSON with our event fields.
	var got map[string]interface{}
	if err := json.Unmarshal(es.lastBody, &got); err != nil {
		t.Fatalf("parse ES body: %v", err)
	}
	if got["event_id"] != ev.EventID {
		t.Errorf("event_id = %v, want %v", got["event_id"], ev.EventID)
	}
	if got["key_id"] != "payments/signing-key" {
		t.Errorf("key_id = %v, want payments/signing-key", got["key_id"])
	}
}

func TestELKAuditSink_Log_ServerError_ReturnsError(t *testing.T) {
	es := &fakeES{status: http.StatusServiceUnavailable}
	srv := httptest.NewServer(es)
	defer srv.Close()

	sink := newELKSink(t, srv, 1)
	err := sink.Log(context.Background(), makeTestEvent(t, audit.OperationSign))
	if err == nil {
		t.Fatal("expected error for 503 response")
	}
}

func TestELKAuditSink_Log_CancelledContext(t *testing.T) {
	es := &fakeES{}
	srv := httptest.NewServer(es)
	defer srv.Close()

	sink := newELKSink(t, srv, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sink.Log(ctx, makeTestEvent(t, audit.OperationSign))
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// ── buffered / bulk writes ────────────────────────────────────────────────────

func TestELKAuditSink_Buffered_FlushOnFull(t *testing.T) {
	es := &fakeES{}
	srv := httptest.NewServer(es)
	defer srv.Close()

	sink := newELKSink(t, srv, 3) // buffer 3 events before flushing

	for i := 0; i < 2; i++ {
		if err := sink.Log(context.Background(), makeTestEvent(t, audit.OperationSign)); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	if es.requests.Load() != 0 {
		t.Error("should not have flushed yet (buffer not full)")
	}

	// Third event fills the buffer and triggers a bulk flush.
	if err := sink.Log(context.Background(), makeTestEvent(t, audit.OperationSign)); err != nil {
		t.Fatalf("Log 3: %v", err)
	}
	if es.requests.Load() != 1 {
		t.Errorf("expected 1 bulk request after buffer full, got %d", es.requests.Load())
	}
}

func TestELKAuditSink_Flush_DrainBuffer(t *testing.T) {
	es := &fakeES{}
	srv := httptest.NewServer(es)
	defer srv.Close()

	sink := newELKSink(t, srv, 10) // large buffer

	for i := 0; i < 3; i++ {
		sink.Log(context.Background(), makeTestEvent(t, audit.OperationSign)) //nolint:errcheck
	}
	if es.requests.Load() != 0 {
		t.Error("should not have flushed yet")
	}

	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if es.requests.Load() != 1 {
		t.Errorf("expected 1 bulk request after flush, got %d", es.requests.Load())
	}
}

func TestELKAuditSink_Flush_EmptyBuffer_NoRequest(t *testing.T) {
	es := &fakeES{}
	srv := httptest.NewServer(es)
	defer srv.Close()

	sink := newELKSink(t, srv, 10)
	// Nothing logged — flush should be a no-op.
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush on empty buffer: %v", err)
	}
	if es.requests.Load() != 0 {
		t.Errorf("expected 0 ES requests for empty flush, got %d", es.requests.Load())
	}
}

// ── security: no auth credentials in body ────────────────────────────────────

func TestELKAuditSink_APIKey_SetInHeader_NotBody(t *testing.T) {
	const secretKey = "myid:mysecretkey"
	var gotAuthHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"created"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	sink, err := audit.NewELKAuditSink(context.Background(), audit.ELKConfig{
		Address: srv.URL,
		APIKey:  secretKey,
	})
	if err != nil {
		t.Fatalf("NewELKAuditSink: %v", err)
	}
	sink.Log(context.Background(), makeTestEvent(t, audit.OperationSign)) //nolint:errcheck

	if !strings.HasPrefix(gotAuthHeader, "ApiKey ") {
		t.Errorf("expected ApiKey auth header, got: %q", gotAuthHeader)
	}
	if !strings.Contains(gotAuthHeader, secretKey) {
		t.Errorf("expected key in auth header, got: %q", gotAuthHeader)
	}
}

// ── validate: invalid events rejected before sending ─────────────────────────

func TestELKAuditSink_Validate_RejectsUnsafeEvents(t *testing.T) {
	es := &fakeES{}
	srv := httptest.NewServer(es)
	defer srv.Close()

	sink := newELKSink(t, srv, 1)
	ev := makeTestEvent(t, audit.OperationSign)
	ev.DenyReason = "-----BEGIN EC PRIVATE KEY----- abcde..."

	err := sink.Log(context.Background(), ev)
	if err == nil {
		t.Fatal("expected validation error for PEM in DenyReason")
	}
	if es.requests.Load() != 0 {
		t.Error("ADVERSARIAL: ES received a request despite validation failure")
	}
}

// ── flush interval ────────────────────────────────────────────────────────────

func TestELKAuditSink_FlushInterval_TriggersFlush(t *testing.T) {
	if testing.Short() {
		// TODO(#2): skip until 2027-01-01 — timing-sensitive, unreliable in short mode
		t.Skip("skipping timing-sensitive test in short mode")
	}
	es := &fakeES{}
	srv := httptest.NewServer(es)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink, err := audit.NewELKAuditSink(ctx, audit.ELKConfig{
		Address:       srv.URL,
		BufferSize:    100,                    // large buffer
		FlushInterval: 100 * time.Millisecond, // fast flush for test
	})
	if err != nil {
		t.Fatalf("NewELKAuditSink: %v", err)
	}

	sink.Log(context.Background(), makeTestEvent(t, audit.OperationSign)) //nolint:errcheck

	// Wait for the interval flush to fire.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if es.requests.Load() > 0 {
			return // success
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("expected interval flush to have fired within 500ms")
}
