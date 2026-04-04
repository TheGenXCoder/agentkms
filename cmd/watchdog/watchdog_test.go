package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// mockDestroyer records calls to Destroy.
type mockDestroyer struct {
	called atomic.Bool
	device string
}

func (m *mockDestroyer) Destroy(device string) error {
	m.called.Store(true)
	m.device = device
	return nil
}

func TestWatchdog_TriggersAfterGrace(t *testing.T) {
	// Server that always returns 401.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	destroyer := &mockDestroyer{}
	client := srv.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	run(ctx, client, srv.URL, "/dev/fake", 10*time.Millisecond, 2, destroyer)

	if !destroyer.called.Load() {
		t.Error("expected destroyer to be called after grace period exceeded")
	}
	if destroyer.device != "/dev/fake" {
		t.Errorf("expected device /dev/fake, got %q", destroyer.device)
	}
}

func TestWatchdog_DoesNotTriggerOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	destroyer := &mockDestroyer{}
	client := srv.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	run(ctx, client, srv.URL, "/dev/fake", 10*time.Millisecond, 3, destroyer)

	if destroyer.called.Load() {
		t.Error("destroyer should NOT be called when validation succeeds")
	}
}

func TestWatchdog_RecoveryResetsCounter(t *testing.T) {
	// Fail twice, then succeed, then fail again — should never reach grace=5.
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n == 1 || n == 2 {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	destroyer := &mockDestroyer{}
	client := srv.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	run(ctx, client, srv.URL, "/dev/fake", 10*time.Millisecond, 5, destroyer)

	if destroyer.called.Load() {
		t.Error("destroyer should NOT be called — recovery happened before grace")
	}
}

func TestValidate_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := validate(srv.Client(), srv.URL); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestValidate_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := validate(srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
}

func TestValidate_NetworkError(t *testing.T) {
	err := validate(&http.Client{Timeout: 100 * time.Millisecond},
		"http://127.0.0.1:1") // nothing listening
	if err == nil {
		t.Fatal("expected network error, got nil")
	}
}

func TestLogOnlyDestroyer(t *testing.T) {
	d := &logOnlyDestroyer{}
	if err := d.Destroy("/dev/test"); err != nil {
		t.Fatalf("log-only destroyer should not error: %v", err)
	}
}

func TestValidate_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := validate(srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected error for 500, got nil")
	}
}

func TestWatchdog_GraceExactlyMet(t *testing.T) {
	// Exactly grace failures — should trigger.
	var callCount atomic.Int32
	grace := 3
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	destroyer := &mockDestroyer{}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	run(ctx, srv.Client(), srv.URL, "/dev/test", 10*time.Millisecond, grace, destroyer)
	if !destroyer.called.Load() {
		t.Errorf("expected destroy after exactly %d failures, calls=%d", grace, callCount.Load())
	}
}

func TestMockDestroyerError(t *testing.T) {
	d := &errorDestroyer{}
	err := d.Destroy("/dev/test")
	if err == nil {
		t.Fatal("expected error from errorDestroyer")
	}
}

type errorDestroyer struct{}

func (e *errorDestroyer) Destroy(device string) error {
	return fmt.Errorf("simulated destroy error")
}
