package policy_test

// Tests for VaultPolicyLoader — P-05.
// All tests use httptest.Server; no real Vault dependency.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/policy"
	"github.com/agentkms/agentkms/pkg/identity"
)

// ── fixtures ──────────────────────────────────────────────────────────────────

const minimalPolicyYAML = `
version: 1
rules:
  - id: allow-sign
    effect: allow
    match:
      identity:
        caller_id_pattern: "*"
      operations: [sign]
`

const updatedPolicyYAML = `
version: 1
rules:
  - id: allow-all-ops
    effect: allow
    match:
      identity:
        caller_id_pattern: "*"
      operations: [sign, encrypt, decrypt, list_keys]
`

const invalidPolicyYAML = `
version: 1
rules:
  - id: ""
    effect: UNKNOWN_EFFECT
`

// ── fake Vault KV server ──────────────────────────────────────────────────────

type fakeKV struct {
	calls     atomic.Int64
	status    atomic.Int32 // 0 means 200
	policyDoc string
	lastToken string
}

func (f *fakeKV) setStatus(s int) { f.status.Store(int32(s)) }

func (f *fakeKV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	f.lastToken = r.Header.Get("X-Vault-Token")

	status := int(f.status.Load())
	if status == 0 {
		status = http.StatusOK
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if status != http.StatusOK {
		return
	}
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"data": map[string]string{
				"policy": f.policyDoc,
			},
		},
	}
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

func newFakeKVServer(policyDoc string) (*fakeKV, *policy.VaultPolicyLoader, func()) {
	f := &fakeKV{policyDoc: policyDoc}
	srv := httptest.NewServer(f)
	loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
		Address:    srv.URL,
		Token:      "test-token",
		KVMount:    "kv",
		PolicyPath: "policy/test",
	})
	return f, loader, srv.Close
}

// ── Load from KV ─────────────────────────────────────────────────────────────

func TestVaultPolicyLoader_Load_Success(t *testing.T) {
	_, loader, close := newFakeKVServer(minimalPolicyYAML)
	defer close()

	if err := loader.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	eng := loader.Engine()
	if eng == nil {
		t.Fatal("Engine() returned nil after successful Load")
	}
}

func TestVaultPolicyLoader_EngineI_NotNilAfterLoad(t *testing.T) {
	_, loader, close := newFakeKVServer(minimalPolicyYAML)
	defer close()

	loader.Load(context.Background()) //nolint:errcheck
	ei := loader.EngineI()
	if ei == nil {
		t.Fatal("EngineI() returned nil")
	}
}

func TestVaultPolicyLoader_Engine_PanicsBeforeLoad(t *testing.T) {
	loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
		Address: "http://127.0.0.1:1",
		Token:   "tok",
	})
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic before Load()")
		}
	}()
	loader.Engine()
}

func TestVaultPolicyLoader_Load_SendsTokenInHeader(t *testing.T) {
	f, loader, close := newFakeKVServer(minimalPolicyYAML)
	defer close()

	loader.Load(context.Background()) //nolint:errcheck

	if f.lastToken != "test-token" {
		t.Errorf("expected X-Vault-Token = test-token, got %q", f.lastToken)
	}
}

// ── Deny-by-default from Vault ────────────────────────────────────────────────

func TestVaultPolicyLoader_LoadedEngine_DenyByDefault(t *testing.T) {
	// Policy allows only sign — anything else must be denied.
	_, loader, close := newFakeKVServer(minimalPolicyYAML)
	defer close()

	loader.Load(context.Background()) //nolint:errcheck
	eng := loader.EngineI()

	decision, err := eng.Evaluate(context.Background(), identityForTest("user@team", "team"), "encrypt", "any/key")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allow {
		t.Error("expected deny for operation not in policy")
	}
}

// ── KV 404 with local fallback ────────────────────────────────────────────────

func TestVaultPolicyLoader_Load_KVNotFound_UsesLocalFallback(t *testing.T) {
	// KV returns 404.
	f := &fakeKV{policyDoc: ""}
	f.setStatus(http.StatusNotFound)
	srv := httptest.NewServer(f)
	defer srv.Close()

	// Write a local fallback policy.
	tmpDir := t.TempDir()
	fallbackPath := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(fallbackPath, []byte(minimalPolicyYAML), 0600); err != nil {
		t.Fatalf("write fallback: %v", err)
	}

	loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
		Address:           srv.URL,
		Token:             "tok",
		PolicyPath:        "policy/test",
		LocalFallbackPath: fallbackPath,
	})

	if err := loader.Load(context.Background()); err != nil {
		t.Fatalf("Load with fallback: %v", err)
	}

	// Engine must be non-nil (loaded from fallback).
	if loader.Engine() == nil {
		t.Error("Engine nil after fallback load")
	}
}

func TestVaultPolicyLoader_Load_KVNotFound_NoFallback_Error(t *testing.T) {
	f := &fakeKV{policyDoc: ""}
	f.setStatus(http.StatusNotFound)
	srv := httptest.NewServer(f)
	defer srv.Close()

	loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
		Address:    srv.URL,
		Token:      "tok",
		PolicyPath: "policy/test",
		// No LocalFallbackPath
	})

	err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error when KV is 404 and no fallback")
	}
}

// ── Invalid policy rejected ───────────────────────────────────────────────────

func TestVaultPolicyLoader_Load_InvalidPolicy_Error(t *testing.T) {
	_, loader, close := newFakeKVServer(invalidPolicyYAML)
	defer close()

	err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid policy YAML from KV")
	}
}

func TestVaultPolicyLoader_ReloadLoop_RetainsLastValidOnError(t *testing.T) {
	if testing.Short() {
		// TODO(#4): skip until 2027-01-01 — timing-sensitive reload test
		t.Skip("skipping timing-sensitive reload test in short mode")
	}

	// Initial: valid policy.
	f := &fakeKV{policyDoc: minimalPolicyYAML}
	srv := httptest.NewServer(f)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
		Address:        srv.URL,
		Token:          "tok",
		PolicyPath:     "policy/test",
		ReloadInterval: 50 * time.Millisecond, // fast for test
	})
	if err := loader.Load(ctx); err != nil {
		t.Fatalf("initial Load: %v", err)
	}

	// Now make KV return a server error.
	f.setStatus(http.StatusInternalServerError)
	time.Sleep(200 * time.Millisecond) // wait for reload loop

	// Engine must still be non-nil (last valid policy retained).
	if loader.Engine() == nil {
		t.Error("Engine should not be nil after failed reload")
	}
}

// ── Hot-reload ────────────────────────────────────────────────────────────────

func TestVaultPolicyLoader_HotReload_UpdatesEngine(t *testing.T) {
	if testing.Short() {
		// TODO(#4): skip until 2027-01-01 — timing-sensitive reload test
		t.Skip("skipping timing-sensitive reload test in short mode")
	}

	var callCount atomic.Int32
	policyDoc := minimalPolicyYAML

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		doc := policyDoc
		if n > 2 {
			doc = updatedPolicyYAML // serve updated policy on 3rd+ call
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"data":{"data":{"policy":%q}}}`, doc) //nolint:errcheck
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
		Address:        srv.URL,
		Token:          "tok",
		PolicyPath:     "policy/test",
		ReloadInterval: 50 * time.Millisecond,
	})
	if err := loader.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Poll the engine until the updated policy is visible. Observing
	// callCount >= 3 does not guarantee the engine has been swapped in — there
	// is a window between HTTP response and engine update. Poll the actual
	// observable (engine behavior) instead.
	deadline := time.Now().Add(2 * time.Second)
	var lastDecision policy.Decision
	var lastErr error
	for time.Now().Before(deadline) {
		eng := loader.EngineI()
		lastDecision, lastErr = eng.Evaluate(context.Background(), identityForTest("u@t", "t"), "encrypt", "k")
		if lastErr == nil && lastDecision.Allow {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("Evaluate (last attempt): %v (callCount=%d)", lastErr, callCount.Load())
	}
	t.Errorf("expected encrypt to be allowed after policy hot-reload (callCount=%d)", callCount.Load())
}

// ── Cancelled context ─────────────────────────────────────────────────────────

func TestVaultPolicyLoader_Load_CancelledContext(t *testing.T) {
	f := &fakeKV{policyDoc: minimalPolicyYAML}
	srv := httptest.NewServer(f)
	defer srv.Close()

	loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
		Address:    srv.URL,
		Token:      "tok",
		PolicyPath: "policy/test",
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Load

	// May succeed or fail depending on timing; must not panic.
	_ = loader.Load(ctx)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func identityForTest(callerID, teamID string) identity.Identity {
	return identity.Identity{CallerID: callerID, TeamID: teamID}
}
