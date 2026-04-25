package plugin

// capabilities_test.go — tests for capability negotiation on provider services.
//
// These tests cover:
//  1. Capability negotiation works for provider adapters at startup.
//  2. Capability mismatch detection (host requires "X", plugin doesn't advertise it).
//  3. Version compatibility: >= check accepts plugins built against older API versions.
//  4. Registry: register/lookup/list deliverers.

import (
	"testing"
)

// ── Capability negotiation — provider adapters ────────────────────────────────

// TestCapabilities_ScopeValidatorGRPC_DefaultNil verifies that a ScopeValidatorGRPC
// adapter has nil capabilities before any negotiation occurs (as constructed by
// GRPCClient before the host calls Capabilities()).
func TestCapabilities_ScopeValidatorGRPC_DefaultNil(t *testing.T) {
	adapter := &ScopeValidatorGRPC{
		client:       nil,
		kind:         "test",
		capabilities: nil,
	}

	if caps := adapter.Capabilities(); caps != nil {
		t.Errorf("Capabilities() = %v, want nil before negotiation", caps)
	}
}

// TestCapabilities_AdaptersStoreAndReturnCapabilities verifies that the
// capability slice stored on each adapter type is returned correctly.
func TestCapabilities_AdaptersStoreAndReturnCapabilities(t *testing.T) {
	caps := []string{"health", "revoke", "audit"}

	t.Run("ScopeValidatorGRPC", func(t *testing.T) {
		a := &ScopeValidatorGRPC{capabilities: caps}
		if got := a.Capabilities(); len(got) != 3 {
			t.Errorf("Capabilities() len = %d, want 3", len(got))
		}
	})

	t.Run("ScopeAnalyzerGRPC", func(t *testing.T) {
		a := &ScopeAnalyzerGRPC{capabilities: caps}
		if got := a.Capabilities(); len(got) != 3 {
			t.Errorf("Capabilities() len = %d, want 3", len(got))
		}
	})

	t.Run("ScopeSerializerGRPC", func(t *testing.T) {
		a := &ScopeSerializerGRPC{capabilities: caps}
		if got := a.Capabilities(); len(got) != 3 {
			t.Errorf("Capabilities() len = %d, want 3", len(got))
		}
	})

	t.Run("CredentialVenderGRPC", func(t *testing.T) {
		a := &CredentialVenderGRPC{capabilities: caps}
		if got := a.Capabilities(); len(got) != 3 {
			t.Errorf("Capabilities() len = %d, want 3", len(got))
		}
	})
}

// TestCapabilities_Mismatch_RequiredCapabilityMissing verifies that a host-side
// capability check correctly identifies when a required capability is missing.
//
// This models the orchestrator pattern: after Capabilities() is called at startup,
// the host checks whether the plugin advertises the required feature.
func TestCapabilities_Mismatch_RequiredCapabilityMissing(t *testing.T) {
	advertised := []string{"health"} // plugin advertises "health" only

	// hasCapability is the check the host performs.
	hasCapability := func(caps []string, required string) bool {
		for _, c := range caps {
			if c == required {
				return true
			}
		}
		return false
	}

	if hasCapability(advertised, "health") == false {
		t.Error("expected 'health' to be found in capabilities")
	}

	if hasCapability(advertised, "revoke") {
		t.Error("expected 'revoke' NOT to be found — mismatch not detected")
	}
}

// TestCapabilities_EmptySetIsValid verifies that a plugin advertising no
// capabilities (empty slice) is a valid state, not an error. Legacy plugins
// that predate the Capabilities RPC return no capabilities.
func TestCapabilities_EmptySetIsValid(t *testing.T) {
	a := &ScopeValidatorGRPC{capabilities: []string{}}

	caps := a.Capabilities()
	if caps == nil {
		t.Error("Capabilities() returned nil, want empty non-nil slice")
	}
	if len(caps) != 0 {
		t.Errorf("Capabilities() len = %d, want 0", len(caps))
	}
}

// ── Version compatibility ─────────────────────────────────────────────────────

// TestVersion_ForwardCompat_OlderPluginAccepted verifies the >= fix:
// a plugin declaring APIVersion < CurrentAPIVersion is now accepted.
//
// Runs only when CurrentAPIVersion > 1 (otherwise there's nothing to test).
func TestVersion_ForwardCompat_OlderPluginAccepted(t *testing.T) {
	if CurrentAPIVersion <= 1 {
		t.Skip("CurrentAPIVersion is 1; no older version to test forward compat against")
	}

	r := NewRegistry()
	info := PluginInfo{
		Kind:       "aws-sts",
		APIVersion: CurrentAPIVersion - 1, // older plugin
		Name:       "aws-plugin",
		Version:    "0.0.9",
	}
	v := &mockScopeValidator{kind: "aws-sts"}

	if err := r.RegisterWithInfo(info, v); err != nil {
		t.Errorf("RegisterWithInfo with APIVersion < CurrentAPIVersion should succeed (forward compat), got: %v", err)
	}
}

// TestVersion_CurrentVersionAccepted verifies the happy path: exact version match.
func TestVersion_CurrentVersionAccepted(t *testing.T) {
	r := NewRegistry()
	info := PluginInfo{
		Kind:       "stripe",
		APIVersion: CurrentAPIVersion,
		Name:       "stripe-plugin",
		Version:    "1.0.0",
	}
	v := &mockScopeValidator{kind: "stripe"}

	if err := r.RegisterWithInfo(info, v); err != nil {
		t.Errorf("RegisterWithInfo with APIVersion == CurrentAPIVersion should succeed, got: %v", err)
	}
}

// TestVersion_FutureVersionRejected verifies that a plugin requiring a newer
// API version than the host supports is still rejected.
func TestVersion_FutureVersionRejected(t *testing.T) {
	r := NewRegistry()
	info := PluginInfo{
		Kind:       "future-plugin",
		APIVersion: CurrentAPIVersion + 1,
		Name:       "future-plugin",
		Version:    "99.0.0",
	}
	v := &mockScopeValidator{kind: "future-plugin"}

	err := r.RegisterWithInfo(info, v)
	if err == nil {
		t.Error("RegisterWithInfo with APIVersion > CurrentAPIVersion should fail, got nil")
	}
}

// ── Registry: deliverer operations ───────────────────────────────────────────

// TestRegistry_RegisterDeliverer_And_LookupDeliverer verifies the basic
// register/lookup round-trip for DestinationDeliverer.
func TestRegistry_RegisterDeliverer_And_LookupDeliverer(t *testing.T) {
	r := NewRegistry()
	d := &mockDestinationDeliverer{kind: "github-secret"}

	if err := r.RegisterDeliverer("github-secret", d); err != nil {
		t.Fatalf("RegisterDeliverer returned unexpected error: %v", err)
	}

	got, err := r.LookupDeliverer("github-secret")
	if err != nil {
		t.Fatalf("LookupDeliverer returned unexpected error: %v", err)
	}
	if got != d {
		t.Errorf("LookupDeliverer returned %v, want %v", got, d)
	}
}

// TestRegistry_LookupDeliverer_NotFound verifies that an error is returned for unknown kinds.
func TestRegistry_LookupDeliverer_NotFound(t *testing.T) {
	r := NewRegistry()

	_, err := r.LookupDeliverer("nonexistent")
	if err == nil {
		t.Fatal("LookupDeliverer should return an error for unregistered kind, got nil")
	}
}

// TestRegistry_RegisterDeliverer_DuplicateKind verifies that registering the
// same kind twice returns an error.
func TestRegistry_RegisterDeliverer_DuplicateKind(t *testing.T) {
	r := NewRegistry()
	d1 := &mockDestinationDeliverer{kind: "k8s-secret"}
	d2 := &mockDestinationDeliverer{kind: "k8s-secret"}

	if err := r.RegisterDeliverer("k8s-secret", d1); err != nil {
		t.Fatalf("first RegisterDeliverer: %v", err)
	}
	err := r.RegisterDeliverer("k8s-secret", d2)
	if err == nil {
		t.Fatal("second RegisterDeliverer with same kind should return error, got nil")
	}
}

// TestRegistry_DelivererKinds_ReturnsAll verifies DelivererKinds returns all
// registered kinds.
func TestRegistry_DelivererKinds_ReturnsAll(t *testing.T) {
	r := NewRegistry()
	kinds := []string{"github-secret", "k8s-secret", "vault-kv"}

	for _, k := range kinds {
		if err := r.RegisterDeliverer(k, &mockDestinationDeliverer{kind: k}); err != nil {
			t.Fatalf("RegisterDeliverer(%q): %v", k, err)
		}
	}

	got := r.DelivererKinds()
	if len(got) != 3 {
		t.Fatalf("DelivererKinds() returned %d items, want 3", len(got))
	}

	have := make(map[string]bool)
	for _, k := range got {
		have[k] = true
	}
	for _, k := range kinds {
		if !have[k] {
			t.Errorf("DelivererKinds() missing %q", k)
		}
	}
}

// TestRegistry_AllTypesCoexist_WithDeliverer verifies that registering a
// validator AND a deliverer for the same kind is legal (independent maps).
func TestRegistry_AllTypesCoexist_WithDeliverer(t *testing.T) {
	r := NewRegistry()
	kind := "aws-s3"

	if err := r.Register(kind, &mockScopeValidator{kind: kind}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.RegisterDeliverer(kind, &mockDestinationDeliverer{kind: kind}); err != nil {
		t.Fatalf("RegisterDeliverer: %v", err)
	}

	if _, err := r.Lookup(kind); err != nil {
		t.Errorf("Lookup after Register: %v", err)
	}
	if _, err := r.LookupDeliverer(kind); err != nil {
		t.Errorf("LookupDeliverer after RegisterDeliverer: %v", err)
	}
}
