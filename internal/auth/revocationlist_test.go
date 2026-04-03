package auth

import (
	"testing"
	"time"
)

func TestRevocationList_Len_Prune(t *testing.T) {
	rl := NewRevocationList()

	// Revoke a token that expires in the future
	rl.Revoke("jti1", time.Now().Add(1*time.Hour))
	if rl.Len() != 1 {
		t.Errorf("Expected len 1, got %d", rl.Len())
	}
	if !rl.IsRevoked("jti1") {
		t.Error("Expected jti1 to be revoked")
	}

	// Revoke a token that has already expired
	rl.Revoke("jti2", time.Now().Add(-1*time.Hour))
	// This will call pruneExpired() inside Revoke(), which should remove jti2 immediately,
	// but let's check len
	if rl.Len() != 1 {
		t.Errorf("Expected len 1 after pruning jti2, got %d", rl.Len())
	}
	if rl.IsRevoked("jti2") {
		t.Error("Expected jti2 not to be revoked (pruned)")
	}
}
