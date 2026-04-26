package binding_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/agentkms/agentkms/internal/credentials"
	"github.com/agentkms/agentkms/internal/credentials/binding"
)

// ── Validation tests ──────────────────────────────────────────────────────────

func TestValidate_ValidBinding(t *testing.T) {
	b := validBinding("test-binding")
	if err := b.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidate_InvalidName(t *testing.T) {
	cases := []string{
		"",
		"UPPER",
		"-starts-with-dash",
		"has space",
		"has/slash",
		"1starts-with-digit",
		"this-name-is-way-too-long-it-definitely-exceeds-63-characters-yes-it-does-absolutely",
	}
	for _, name := range cases {
		b := validBinding(name)
		if err := b.Validate(); err == nil {
			t.Errorf("expected error for name %q, got nil", name)
		}
	}
}

func TestValidate_MissingProviderKind(t *testing.T) {
	b := validBinding("my-binding")
	b.ProviderKind = ""
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for missing provider_kind")
	}
}

func TestValidate_NoDestinations(t *testing.T) {
	b := validBinding("my-binding")
	b.Destinations = nil
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for empty destinations")
	}
}

func TestValidate_InvalidDestinationKind(t *testing.T) {
	b := validBinding("my-binding")
	b.Destinations = []binding.DestinationSpec{
		{Kind: "UPPERCASE", TargetID: "owner/repo:SECRET"},
	}
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for invalid destination kind")
	}
}

func TestValidate_MissingTargetID(t *testing.T) {
	b := validBinding("my-binding")
	b.Destinations = []binding.DestinationSpec{
		{Kind: "github-secret", TargetID: ""},
	}
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for missing target_id")
	}
}

// ── JSON round-trip ───────────────────────────────────────────────────────────

func TestJSONRoundTrip(t *testing.T) {
	b := validBinding("round-trip")
	b.Metadata.Tags = []string{"ci", "prod"}
	b.ProviderParams = map[string]any{"app_name": "my-app"}
	b.Destinations[0].Params = map[string]any{"visibility": "all"}

	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var b2 binding.CredentialBinding
	if err := json.Unmarshal(data, &b2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if b2.Name != b.Name {
		t.Errorf("name: got %q want %q", b2.Name, b.Name)
	}
	if b2.ProviderKind != b.ProviderKind {
		t.Errorf("provider_kind: got %q want %q", b2.ProviderKind, b.ProviderKind)
	}
	if len(b2.Destinations) != len(b.Destinations) {
		t.Errorf("destinations len: got %d want %d", len(b2.Destinations), len(b.Destinations))
	}
	if len(b2.Metadata.Tags) != 2 {
		t.Errorf("tags: got %v want [ci prod]", b2.Metadata.Tags)
	}
}

func TestJSONRoundTrip_LastCredentialUUID(t *testing.T) {
	b := validBinding("uuid-round-trip")
	b.Metadata.LastCredentialUUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var b2 binding.CredentialBinding
	if err := json.Unmarshal(data, &b2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if b2.Metadata.LastCredentialUUID != b.Metadata.LastCredentialUUID {
		t.Errorf("LastCredentialUUID: got %q want %q",
			b2.Metadata.LastCredentialUUID, b.Metadata.LastCredentialUUID)
	}
}

func TestJSONRoundTrip_LastCredentialUUID_OmitEmpty(t *testing.T) {
	b := validBinding("uuid-omitempty")
	// LastCredentialUUID intentionally left empty

	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Field must be absent from JSON when empty (omitempty).
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	meta, ok := raw["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata not a map")
	}
	if _, present := meta["last_credential_uuid"]; present {
		t.Error("last_credential_uuid should be absent when empty (omitempty)")
	}
}

// TestJSONRoundTrip_BindingState verifies that the BindingState field
// survives a JSON marshal/unmarshal cycle and is omitted when empty.
func TestJSONRoundTrip_BindingState(t *testing.T) {
	// Non-empty: round-trips correctly.
	b := validBinding("state-round-trip")
	b.Metadata.BindingState = "ok"

	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var b2 binding.CredentialBinding
	if err := json.Unmarshal(data, &b2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b2.Metadata.BindingState != "ok" {
		t.Errorf("BindingState: got %q want %q", b2.Metadata.BindingState, "ok")
	}

	// Empty: must be absent from JSON (omitempty).
	b3 := validBinding("state-omitempty")
	// BindingState intentionally left empty
	data3, err := json.Marshal(b3)
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data3, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	meta, ok := raw["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata not a map")
	}
	if _, present := meta["binding_state"]; present {
		t.Error("binding_state should be absent from JSON when empty (omitempty)")
	}

	// All valid state strings round-trip.
	for _, state := range []string{"ok", "degraded", "rotation_failed"} {
		b4 := validBinding("state-" + state)
		b4.Metadata.BindingState = state
		d, err := json.Marshal(b4)
		if err != nil {
			t.Fatalf("marshal %q: %v", state, err)
		}
		var b5 binding.CredentialBinding
		if err := json.Unmarshal(d, &b5); err != nil {
			t.Fatalf("unmarshal %q: %v", state, err)
		}
		if b5.Metadata.BindingState != state {
			t.Errorf("state %q: got %q after round-trip", state, b5.Metadata.BindingState)
		}
	}
}

// ── Storage round-trip ────────────────────────────────────────────────────────

func TestKVBindingStore_SaveGetDeleteList(t *testing.T) {
	store := newTestStore()
	ctx := context.Background()

	b := validBinding("my-binding")
	b.Metadata.CreatedAt = binding.NowUTC()

	// Save
	if err := store.Save(ctx, b); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Get
	got, err := store.Get(ctx, "my-binding")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != b.Name {
		t.Errorf("Get name: got %q want %q", got.Name, b.Name)
	}
	if got.ProviderKind != b.ProviderKind {
		t.Errorf("Get provider_kind: got %q want %q", got.ProviderKind, b.ProviderKind)
	}

	// List
	all, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("List len: got %d want 1", len(all))
	}

	// Delete
	if err := store.Delete(ctx, "my-binding"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Get after delete must return ErrNotFound
	if _, err := store.Get(ctx, "my-binding"); err == nil {
		t.Fatal("expected ErrNotFound after delete, got nil")
	}
}

func TestKVBindingStore_GetNotFound(t *testing.T) {
	store := newTestStore()
	ctx := context.Background()
	_, err := store.Get(ctx, "does-not-exist")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestKVBindingStore_MultipleBindings(t *testing.T) {
	store := newTestStore()
	ctx := context.Background()

	names := []string{"alpha", "beta", "gamma"}
	for _, n := range names {
		b := validBinding(n)
		if err := store.Save(ctx, b); err != nil {
			t.Fatalf("Save %q: %v", n, err)
		}
	}

	all, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != len(names) {
		t.Fatalf("List len: got %d want %d", len(all), len(names))
	}
}

func TestKVBindingStore_Overwrite(t *testing.T) {
	store := newTestStore()
	ctx := context.Background()

	b := validBinding("overwrite-me")
	if err := store.Save(ctx, b); err != nil {
		t.Fatalf("Save: %v", err)
	}

	b.ProviderKind = "updated-provider"
	if err := store.Save(ctx, b); err != nil {
		t.Fatalf("Save (overwrite): %v", err)
	}

	got, err := store.Get(ctx, "overwrite-me")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ProviderKind != "updated-provider" {
		t.Errorf("ProviderKind not updated: got %q", got.ProviderKind)
	}
}

// ── Summary ───────────────────────────────────────────────────────────────────

func TestSummary(t *testing.T) {
	b := validBinding("my-binding")
	b.Metadata.Tags = []string{"prod"}
	s := b.Summary()
	if s.Name != "my-binding" {
		t.Errorf("Name: got %q", s.Name)
	}
	if s.DestinationCount != 1 {
		t.Errorf("DestinationCount: got %d want 1", s.DestinationCount)
	}
	if len(s.Tags) != 1 || s.Tags[0] != "prod" {
		t.Errorf("Tags: got %v", s.Tags)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// validBinding returns a minimal, valid CredentialBinding for the given name.
func validBinding(name string) binding.CredentialBinding {
	return binding.CredentialBinding{
		Name:         name,
		ProviderKind: "github-app-token",
		Scope: credentials.Scope{
			Kind: "llm-session",
		},
		Destinations: []binding.DestinationSpec{
			{
				Kind:     "github-secret",
				TargetID: "owner/repo:SECRET_NAME",
			},
		},
		RotationPolicy: binding.RotationPolicy{
			ManualOnly: true,
		},
	}
}

// newTestStore returns a BindingStore backed by an in-memory KV for testing.
func newTestStore() binding.BindingStore {
	return binding.NewKVBindingStore(newMemKV())
}

// memKV is an in-memory implementation of credentials.KVWriter for tests.
type memKV struct {
	data map[string]map[string]string
}

func newMemKV() credentials.KVWriter {
	return &memKV{data: make(map[string]map[string]string)}
}

func (m *memKV) GetSecret(_ context.Context, path string) (map[string]string, error) {
	v, ok := m.data[path]
	if !ok {
		return nil, credentials.ErrCredentialNotFound
	}
	out := make(map[string]string, len(v))
	for k, val := range v {
		out[k] = val
	}
	return out, nil
}

func (m *memKV) SetSecret(_ context.Context, path string, fields map[string]string) error {
	cp := make(map[string]string, len(fields))
	for k, v := range fields {
		cp[k] = v
	}
	m.data[path] = cp
	return nil
}

func (m *memKV) DeleteSecret(_ context.Context, path string) error {
	delete(m.data, path)
	return nil
}

func (m *memKV) ListPaths(_ context.Context) ([]string, error) {
	paths := make([]string, 0, len(m.data))
	for p := range m.data {
		paths = append(paths, p)
	}
	return paths, nil
}
