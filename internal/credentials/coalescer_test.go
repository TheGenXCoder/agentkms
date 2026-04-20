package credentials

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// helper: creates a vend function that returns a fixed ScopedResult and counts calls.
func mockVend(callCount *atomic.Int64) func() (*ScopedResult, error) {
	return func() (*ScopedResult, error) {
		callCount.Add(1)
		return &ScopedResult{
			Credential:     &VendedCredential{Provider: "github"},
			EffectiveScope: Scope{Kind: "github-pat"},
			ScopeHash:      "hash123",
		}, nil
	}
}

func TestCoalescer_FirstCall_InvokesVend(t *testing.T) {
	c := NewCoalescer(5 * time.Second)
	var calls atomic.Int64

	result, err := c.CoalesceOrCall("scope-a", mockVend(&calls))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected vend to be called once, got %d", calls.Load())
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Credential.Provider != "github" {
		t.Fatalf("expected token 'github', got %q", result.Credential.Provider)
	}
}

func TestCoalescer_SecondCall_ReturnsCached(t *testing.T) {
	c := NewCoalescer(5 * time.Second)
	var calls atomic.Int64

	// First call — populates cache.
	_, err := c.CoalesceOrCall("scope-a", mockVend(&calls))
	if err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}

	// Second call — should return cached, not call vend again.
	result, err := c.CoalesceOrCall("scope-a", mockVend(&calls))
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected vend called once total (cached), got %d", calls.Load())
	}
	if result == nil {
		t.Fatal("expected non-nil cached result")
	}
	if result.Credential.Provider != "github" {
		t.Fatalf("expected cached token 'github', got %q", result.Credential.Provider)
	}
}

func TestCoalescer_ExpiredEntry_CallsVendAgain(t *testing.T) {
	ttl := 50 * time.Millisecond
	c := NewCoalescer(ttl)
	var calls atomic.Int64

	// First call.
	_, err := c.CoalesceOrCall("scope-a", mockVend(&calls))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}

	// Wait for TTL to expire.
	time.Sleep(ttl + 10*time.Millisecond)

	// Second call after expiration — should call vend again.
	_, err = c.CoalesceOrCall("scope-a", mockVend(&calls))
	if err != nil {
		t.Fatalf("unexpected error after expiry: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 calls after expiry, got %d", calls.Load())
	}
}

func TestCoalescer_DifferentHashes_IndependentCalls(t *testing.T) {
	c := NewCoalescer(5 * time.Second)
	var callsA, callsB atomic.Int64

	_, err := c.CoalesceOrCall("scope-a", mockVend(&callsA))
	if err != nil {
		t.Fatalf("unexpected error for scope-a: %v", err)
	}

	_, err = c.CoalesceOrCall("scope-b", mockVend(&callsB))
	if err != nil {
		t.Fatalf("unexpected error for scope-b: %v", err)
	}

	if callsA.Load() != 1 {
		t.Fatalf("expected scope-a vend called once, got %d", callsA.Load())
	}
	if callsB.Load() != 1 {
		t.Fatalf("expected scope-b vend called once, got %d", callsB.Load())
	}
}

func TestCoalescer_VendError_NotCached(t *testing.T) {
	c := NewCoalescer(5 * time.Second)
	var calls atomic.Int64
	vendErr := errors.New("upstream failure")

	failingVend := func() (*ScopedResult, error) {
		calls.Add(1)
		return nil, vendErr
	}

	// First call — returns error.
	_, err := c.CoalesceOrCall("scope-err", failingVend)
	if err == nil {
		t.Fatal("expected error from vend, got nil")
	}
	if !errors.Is(err, vendErr) {
		t.Fatalf("expected vendErr, got %v", err)
	}

	// Second call — should retry (error not cached).
	_, err = c.CoalesceOrCall("scope-err", failingVend)
	if err == nil {
		t.Fatal("expected error on retry, got nil")
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 calls (error not cached), got %d", calls.Load())
	}
}

func TestCoalescer_Concurrent_SingleFlight(t *testing.T) {
	c := NewCoalescer(5 * time.Second)
	var calls atomic.Int64

	slowVend := func() (*ScopedResult, error) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond) // simulate upstream latency
		return &ScopedResult{
			Credential:     &VendedCredential{Provider: "concurrent"},
			EffectiveScope: Scope{Kind: "github-pat"},
			ScopeHash:      "concurrent-hash",
		}, nil
	}

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	results := make([]*ScopedResult, numGoroutines)
	errs := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = c.CoalesceOrCall("same-scope", slowVend)
		}(i)
	}

	wg.Wait()

	// All should succeed.
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d got error: %v", i, err)
		}
	}

	// Vend should have been called exactly once (singleflight).
	if calls.Load() != 1 {
		t.Fatalf("expected vend called once (singleflight), got %d", calls.Load())
	}

	// All results should be non-nil.
	for i, r := range results {
		if r == nil {
			t.Fatalf("goroutine %d got nil result", i)
		}
	}
}

func TestCoalescer_Size(t *testing.T) {
	c := NewCoalescer(5 * time.Second)
	var calls atomic.Int64

	if c.Size() != 0 {
		t.Fatalf("expected size 0 initially, got %d", c.Size())
	}

	_, _ = c.CoalesceOrCall("scope-1", mockVend(&calls))
	if c.Size() != 1 {
		t.Fatalf("expected size 1 after one entry, got %d", c.Size())
	}

	_, _ = c.CoalesceOrCall("scope-2", mockVend(&calls))
	if c.Size() != 2 {
		t.Fatalf("expected size 2 after two entries, got %d", c.Size())
	}

	// Same scope — should not increase size.
	_, _ = c.CoalesceOrCall("scope-1", mockVend(&calls))
	if c.Size() != 2 {
		t.Fatalf("expected size 2 (no new entry), got %d", c.Size())
	}
}

func TestCoalescer_Flush(t *testing.T) {
	c := NewCoalescer(5 * time.Second)
	var calls atomic.Int64

	_, _ = c.CoalesceOrCall("scope-1", mockVend(&calls))
	_, _ = c.CoalesceOrCall("scope-2", mockVend(&calls))

	if c.Size() != 2 {
		t.Fatalf("expected size 2 before flush, got %d", c.Size())
	}

	c.Flush()

	if c.Size() != 0 {
		t.Fatalf("expected size 0 after flush, got %d", c.Size())
	}

	// After flush, calling same scope should invoke vend again.
	callsBefore := calls.Load()
	_, err := c.CoalesceOrCall("scope-1", mockVend(&calls))
	if err != nil {
		t.Fatalf("unexpected error after flush: %v", err)
	}
	if calls.Load() != callsBefore+1 {
		t.Fatalf("expected vend called after flush, calls went from %d to %d", callsBefore, calls.Load())
	}
}
