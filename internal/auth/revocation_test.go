package auth_test

import (
	"sync"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/auth"
)

func TestRevocationList_NewIsEmpty(t *testing.T) {
	rl := auth.NewRevocationList()
	if rl.Len() != 0 {
		t.Errorf("Len() = %d on fresh list, want 0", rl.Len())
	}
}

func TestRevocationList_IsRevoked_NotPresent(t *testing.T) {
	rl := auth.NewRevocationList()
	if rl.IsRevoked("nonexistent-jti") {
		t.Error("IsRevoked returned true for a JTI that was never revoked")
	}
}

func TestRevocationList_Revoke_ThenIsRevoked(t *testing.T) {
	rl := auth.NewRevocationList()
	exp := time.Now().UTC().Add(15 * time.Minute)

	rl.Revoke("abc-123", exp)

	if !rl.IsRevoked("abc-123") {
		t.Error("IsRevoked returned false immediately after Revoke")
	}
}

func TestRevocationList_Revoke_Idempotent(t *testing.T) {
	rl := auth.NewRevocationList()
	exp := time.Now().UTC().Add(15 * time.Minute)

	rl.Revoke("abc-123", exp)
	rl.Revoke("abc-123", exp) // second revoke must not panic or change state
	rl.Revoke("abc-123", exp)

	if !rl.IsRevoked("abc-123") {
		t.Error("IsRevoked returned false after idempotent revocation")
	}
	if rl.Len() != 1 {
		t.Errorf("Len() = %d, want 1 after idempotent revocation", rl.Len())
	}
}

func TestRevocationList_MultipleEntries(t *testing.T) {
	rl := auth.NewRevocationList()
	exp := time.Now().UTC().Add(time.Hour)

	rl.Revoke("jti-1", exp)
	rl.Revoke("jti-2", exp)
	rl.Revoke("jti-3", exp)

	if !rl.IsRevoked("jti-1") || !rl.IsRevoked("jti-2") || !rl.IsRevoked("jti-3") {
		t.Error("one or more JTIs not reported as revoked")
	}
	if rl.IsRevoked("jti-4") {
		t.Error("jti-4 was never revoked but IsRevoked returned true")
	}
}

func TestRevocationList_ExpiredEntriesPruned(t *testing.T) {
	rl := auth.NewRevocationList()

	// Revoke a token that has already expired.
	pastExp := time.Now().UTC().Add(-1 * time.Second)
	rl.Revoke("expired-jti", pastExp)

	// The revocation was recorded.
	// Now trigger a prune by revoking another token.
	futureExp := time.Now().UTC().Add(time.Hour)
	rl.Revoke("live-jti", futureExp)

	// After the prune, the expired entry should be gone.
	if rl.Len() != 1 {
		t.Errorf("Len() = %d after prune, want 1 (only live-jti)", rl.Len())
	}
	if rl.IsRevoked("expired-jti") {
		t.Error("expired JTI still present after prune")
	}
	if !rl.IsRevoked("live-jti") {
		t.Error("live JTI missing after prune")
	}
}

// TestRevocationList_ConcurrentAccess exercises the list under concurrent
// goroutines to catch race conditions (run with -race).
func TestRevocationList_ConcurrentAccess(t *testing.T) {
	rl := auth.NewRevocationList()
	exp := time.Now().UTC().Add(time.Hour)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			jti := jtiForN(n)
			rl.Revoke(jti, exp)
			_ = rl.IsRevoked(jti)
			_ = rl.Len()
		}(i)
	}

	wg.Wait()

	if rl.Len() != goroutines {
		t.Errorf("Len() = %d, want %d after concurrent revocations", rl.Len(), goroutines)
	}
}

// jtiForN generates a deterministic JTI string for test goroutine n.
func jtiForN(n int) string {
	return "test-jti-" + string(rune('A'+n%26)) + "-" + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
