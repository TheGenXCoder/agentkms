package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDatadogAuditSink_Flush_Extra(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink, err := NewDatadogAuditSink(ctx, DatadogConfig{
		Address:       ts.URL,
		APIKey:        "test-key",
		FlushInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = sink.Log(ctx, AuditEvent{EventID: "1", Timestamp: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)

	err = sink.Flush(ctx)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSplunkAuditSink_Flush_Extra(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink, err := NewSplunkAuditSink(ctx, SplunkConfig{
		Address:       ts.URL,
		Token:         "test-token",
		FlushInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = sink.Log(ctx, AuditEvent{EventID: "1", Timestamp: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)

	err = sink.Flush(ctx)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSIEMAuditSink_Flush_Extra(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink, err := NewSIEMAuditSink(ctx, SIEMConfig{
		Address:       ts.URL,
		FlushInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = sink.Log(ctx, AuditEvent{EventID: "1", Timestamp: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)

	err = sink.Flush(ctx)
	if err != nil {
		t.Fatal(err)
	}
}
