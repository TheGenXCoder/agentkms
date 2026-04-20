package credentials

import (
	"testing"
	"time"
)

func TestTracker_Track_And_ExpiredSince(t *testing.T) {
	ct := NewCredentialTracker()
	// Credential expired 1 second ago.
	ct.Track("cred-001", time.Now().Add(-1*time.Second))

	expired := ct.ExpiredSince(time.Now())
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired credential, got %d", len(expired))
	}
	if expired[0] != "cred-001" {
		t.Fatalf("expected cred-001, got %s", expired[0])
	}
}

func TestTracker_NotExpiredYet(t *testing.T) {
	ct := NewCredentialTracker()
	// Credential expires 1 hour from now.
	ct.Track("cred-future", time.Now().Add(1*time.Hour))

	expired := ct.ExpiredSince(time.Now())
	if len(expired) != 0 {
		t.Fatalf("expected 0 expired credentials, got %d", len(expired))
	}
}

func TestTracker_MultipleCredentials_OnlyExpiredReturned(t *testing.T) {
	ct := NewCredentialTracker()
	ct.Track("cred-past", time.Now().Add(-10*time.Second))
	ct.Track("cred-future-1", time.Now().Add(1*time.Hour))
	ct.Track("cred-future-2", time.Now().Add(2*time.Hour))

	expired := ct.ExpiredSince(time.Now())
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired credential, got %d", len(expired))
	}
	if expired[0] != "cred-past" {
		t.Fatalf("expected cred-past, got %s", expired[0])
	}
}

func TestTracker_ExpiredSince_ClearsReturned(t *testing.T) {
	ct := NewCredentialTracker()
	ct.Track("cred-consumed", time.Now().Add(-5*time.Second))

	// First call should return the expired credential.
	first := ct.ExpiredSince(time.Now())
	if len(first) != 1 {
		t.Fatalf("first call: expected 1 expired, got %d", len(first))
	}

	// Second call should NOT return the same UUID again.
	second := ct.ExpiredSince(time.Now())
	if len(second) != 0 {
		t.Fatalf("second call: expected 0 expired (consumed), got %d", len(second))
	}
}

func TestTracker_IsExpired_True(t *testing.T) {
	ct := NewCredentialTracker()
	ct.Track("cred-check", time.Now().Add(-1*time.Second))

	// Consume via ExpiredSince first.
	ct.ExpiredSince(time.Now())

	if !ct.IsExpired("cred-check") {
		t.Fatal("expected IsExpired to return true after credential was consumed by ExpiredSince")
	}
}

func TestTracker_IsExpired_False(t *testing.T) {
	ct := NewCredentialTracker()

	// Untracked UUID.
	if ct.IsExpired("cred-unknown") {
		t.Fatal("expected IsExpired to return false for untracked UUID")
	}

	// Tracked but not yet expired.
	ct.Track("cred-active", time.Now().Add(1*time.Hour))
	if ct.IsExpired("cred-active") {
		t.Fatal("expected IsExpired to return false for non-expired credential")
	}
}

func TestTracker_Track_ZeroTime(t *testing.T) {
	ct := NewCredentialTracker()
	// Zero time should be treated as "already expired".
	ct.Track("cred-zero", time.Time{})

	expired := ct.ExpiredSince(time.Now())
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired credential for zero ExpiresAt, got %d", len(expired))
	}
	if expired[0] != "cred-zero" {
		t.Fatalf("expected cred-zero, got %s", expired[0])
	}
}
