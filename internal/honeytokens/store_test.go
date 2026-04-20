package honeytokens

import (
	"regexp"
	"testing"
)

// uuidRe matches a standard UUID v4 format (8-4-4-4-12 hex groups).
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func TestStore_Create_UnderCap(t *testing.T) {
	s := NewStore(5)
	for i := 0; i < 3; i++ {
		_, err := s.Create("tok")
		if err != nil {
			t.Fatalf("create %d: unexpected error: %v", i+1, err)
		}
	}
}

func TestStore_Create_AtCap(t *testing.T) {
	s := NewStore(5)
	for i := 0; i < 5; i++ {
		_, err := s.Create("tok")
		if err != nil {
			t.Fatalf("create %d: unexpected error: %v", i+1, err)
		}
	}
	// 6th must fail with a hard error mentioning the cap/limit.
	_, err := s.Create("one-too-many")
	if err == nil {
		t.Fatal("expected error on 6th create, got nil")
	}
	msg := err.Error()
	if !containsAny(msg, "cap", "limit") {
		t.Fatalf("error should mention cap or limit, got: %s", msg)
	}
}

func TestStore_Create_ReturnsUUID(t *testing.T) {
	s := NewStore(5)
	uuid, err := s.Create("tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uuid == "" {
		t.Fatal("expected non-empty UUID, got empty string")
	}
	if !uuidRe.MatchString(uuid) {
		t.Fatalf("returned value %q does not look like a UUID", uuid)
	}
}

func TestStore_Revoke_FreesSlot(t *testing.T) {
	s := NewStore(5)
	var uuids []string
	for i := 0; i < 5; i++ {
		u, err := s.Create("tok")
		if err != nil {
			t.Fatalf("create %d: unexpected error: %v", i+1, err)
		}
		uuids = append(uuids, u)
	}
	if err := s.Revoke(uuids[0]); err != nil {
		t.Fatalf("revoke: unexpected error: %v", err)
	}
	// Now a slot is free — 6th create should succeed.
	_, err := s.Create("replacement")
	if err != nil {
		t.Fatalf("create after revoke: unexpected error: %v", err)
	}
}

func TestStore_Revoke_Unknown(t *testing.T) {
	s := NewStore(5)
	err := s.Revoke("00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatal("expected error when revoking unknown UUID, got nil")
	}
}

func TestStore_Active_Count(t *testing.T) {
	s := NewStore(5)
	for i := 0; i < 3; i++ {
		if _, err := s.Create("tok"); err != nil {
			t.Fatalf("create %d: unexpected error: %v", i+1, err)
		}
	}
	if got := s.Active(); got != 3 {
		t.Fatalf("Active() = %d, want 3", got)
	}
}

func TestStore_List_ReturnsAll(t *testing.T) {
	s := NewStore(5)
	names := []string{"alpha", "bravo", "charlie"}
	for _, n := range names {
		if _, err := s.Create(n); err != nil {
			t.Fatalf("create %q: unexpected error: %v", n, err)
		}
	}
	list := s.List()
	if len(list) != 3 {
		t.Fatalf("List() returned %d items, want 3", len(list))
	}
	got := make(map[string]bool)
	for _, info := range list {
		got[info.Name] = true
		if info.UUID == "" {
			t.Fatalf("List() entry %q has empty UUID", info.Name)
		}
	}
	for _, n := range names {
		if !got[n] {
			t.Fatalf("List() missing name %q", n)
		}
	}
}

func TestStore_List_ExcludesRevoked(t *testing.T) {
	s := NewStore(5)
	var uuids []string
	for _, n := range []string{"alpha", "bravo", "charlie"} {
		u, err := s.Create(n)
		if err != nil {
			t.Fatalf("create %q: unexpected error: %v", n, err)
		}
		uuids = append(uuids, u)
	}
	if err := s.Revoke(uuids[1]); err != nil {
		t.Fatalf("revoke: unexpected error: %v", err)
	}
	list := s.List()
	if len(list) != 2 {
		t.Fatalf("List() returned %d items after revoke, want 2", len(list))
	}
	for _, info := range list {
		if info.Name == "bravo" {
			t.Fatal("List() still contains revoked token 'bravo'")
		}
	}
}

// containsAny reports whether s contains any of the substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
