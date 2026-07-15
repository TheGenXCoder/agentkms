package policy_test

// load_signed_test.go — Task 3: signed-bundle load path (file + vault + fail-closed).
//
// Contracts:
//   - good signed bundle loads into the engine
//   - bad signature keeps last-good policy on reload
//   - unsigned YAML rejected when RequireSignature is true
//   - unsigned YAML accepted when RequireSignature is false (dev)

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
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
)

func testKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func trustWith(t *testing.T, keyID string, pub ed25519.PublicKey) *policy.TrustStore {
	t.Helper()
	ts := policy.NewTrustStore()
	ts.AddKey(keyID, pub)
	return ts
}

func mustSignBundle(t *testing.T, yamlBody string, priv ed25519.PrivateKey, keyID string) []byte {
	t.Helper()
	b, err := policy.SignPolicyYAML([]byte(yamlBody), priv, keyID)
	if err != nil {
		t.Fatalf("SignPolicyYAML: %v", err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal bundle: %v", err)
	}
	return data
}

// ── LoadTrustStoreFromJSON ────────────────────────────────────────────────────

func TestLoadTrustStoreFromJSON_RoundTrip(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	raw, err := json.Marshal(map[string]string{
		"primary": hex.EncodeToString(pub),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts, err := policy.LoadTrustStoreFromJSON(raw)
	if err != nil {
		t.Fatalf("LoadTrustStoreFromJSON: %v", err)
	}
	got, ok := ts.Lookup("primary")
	if !ok {
		t.Fatal("expected primary key")
	}
	if !bytes.Equal(got, pub) {
		t.Error("public key mismatch after hex round-trip")
	}
}

func TestLoadTrustStoreFromFile(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"k1":%q}`, hex.EncodeToString(pub))), 0600); err != nil {
		t.Fatal(err)
	}
	ts, err := policy.LoadTrustStoreFromFile(path)
	if err != nil {
		t.Fatalf("LoadTrustStoreFromFile: %v", err)
	}
	if ts.Len() != 1 {
		t.Errorf("Len = %d, want 1", ts.Len())
	}
}

// ── LoadPolicyFromPath ────────────────────────────────────────────────────────

func TestLoadPolicyFromPath_GoodBundleJSON(t *testing.T) {
	pub, priv := testKeypair(t)
	trust := trustWith(t, "primary", pub)
	bundle := mustSignBundle(t, minimalPolicyYAML, priv, "primary")

	path := filepath.Join(t.TempDir(), "policy.bundle.json")
	if err := os.WriteFile(path, bundle, 0600); err != nil {
		t.Fatal(err)
	}

	p, err := policy.LoadPolicyFromPath(path, policy.LoadConfig{
		RequireSignature: true,
		Trust:            trust,
	})
	if err != nil {
		t.Fatalf("LoadPolicyFromPath good bundle: %v", err)
	}
	if p == nil || p.Version != "1" {
		t.Fatalf("unexpected policy: %+v", p)
	}
}

func TestLoadPolicyFromPath_SiblingBundlePreferred(t *testing.T) {
	pub, priv := testKeypair(t)
	trust := trustWith(t, "primary", pub)
	dir := t.TempDir()

	// YAML alone would allow only sign; signed bundle allows encrypt too.
	yamlPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(yamlPath, []byte(minimalPolicyYAML), 0600); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "policy.bundle.json")
	if err := os.WriteFile(bundlePath, mustSignBundle(t, updatedPolicyYAML, priv, "primary"), 0600); err != nil {
		t.Fatal(err)
	}

	p, err := policy.LoadPolicyFromPath(yamlPath, policy.LoadConfig{
		RequireSignature: true,
		Trust:            trust,
	})
	if err != nil {
		t.Fatalf("LoadPolicyFromPath: %v", err)
	}
	// updatedPolicyYAML has rule allow-all-ops
	if len(p.Rules) != 1 || p.Rules[0].ID != "allow-all-ops" {
		t.Errorf("expected sibling bundle policy, got %+v", p.Rules)
	}
}

func TestLoadPolicyFromPath_UnsignedRejectedWhenRequired(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(yamlPath, []byte(minimalPolicyYAML), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := policy.LoadPolicyFromPath(yamlPath, policy.LoadConfig{
		RequireSignature: true,
		Trust:            policy.NewTrustStore(),
	})
	if err == nil {
		t.Fatal("expected error rejecting unsigned YAML when signature required")
	}
}

func TestLoadPolicyFromPath_UnsignedAllowedWhenNotRequired(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(yamlPath, []byte(minimalPolicyYAML), 0600); err != nil {
		t.Fatal(err)
	}

	p, err := policy.LoadPolicyFromPath(yamlPath, policy.LoadConfig{
		RequireSignature: false,
		Trust:            nil,
	})
	if err != nil {
		t.Fatalf("unsigned YAML should load in dev: %v", err)
	}
	if p == nil {
		t.Fatal("nil policy")
	}
}

func TestLoadPolicyFromPath_BadBundleSignatureRejected(t *testing.T) {
	pub, priv := testKeypair(t)
	trust := trustWith(t, "primary", pub)
	b, err := policy.SignPolicyYAML([]byte(minimalPolicyYAML), priv, "primary")
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt signature.
	sig, _ := base64.StdEncoding.DecodeString(b.Signature)
	sig[0] ^= 0xFF
	b.Signature = base64.StdEncoding.EncodeToString(sig)
	raw, _ := json.Marshal(b)

	path := filepath.Join(t.TempDir(), "policy.bundle.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}

	p, err := policy.LoadPolicyFromPath(path, policy.LoadConfig{
		RequireSignature: true,
		Trust:            trust,
	})
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
	if p != nil {
		t.Fatal("expected nil policy on bad signature")
	}
}

// ── VaultPolicyLoader signed bundle ───────────────────────────────────────────

type fakeKVFields struct {
	calls  atomic.Int64
	status atomic.Int32
	fields map[string]string
}

func (f *fakeKVFields) setStatus(s int) { f.status.Store(int32(s)) }

func (f *fakeKVFields) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	status := int(f.status.Load())
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status != http.StatusOK {
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"data": f.fields,
		},
	})
}

func TestVaultPolicyLoader_Load_GoodSignedBundle(t *testing.T) {
	pub, priv := testKeypair(t)
	trust := trustWith(t, "primary", pub)
	bundle := string(mustSignBundle(t, minimalPolicyYAML, priv, "primary"))

	f := &fakeKVFields{fields: map[string]string{"policy.bundle": bundle}}
	srv := httptest.NewServer(f)
	defer srv.Close()

	loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
		Address:          srv.URL,
		Token:            "tok",
		PolicyPath:       "policy/test",
		RequireSignature: true,
		Trust:            trust,
	})
	if err := loader.Load(context.Background()); err != nil {
		t.Fatalf("Load good bundle: %v", err)
	}
	if loader.Engine() == nil {
		t.Fatal("Engine nil after good signed load")
	}
}

func TestVaultPolicyLoader_Load_UnsignedRejectedWhenRequired(t *testing.T) {
	pub, _ := testKeypair(t)
	trust := trustWith(t, "primary", pub)

	f := &fakeKVFields{fields: map[string]string{"policy": minimalPolicyYAML}}
	srv := httptest.NewServer(f)
	defer srv.Close()

	loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
		Address:          srv.URL,
		Token:            "tok",
		PolicyPath:       "policy/test",
		RequireSignature: true,
		Trust:            trust,
	})
	err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error rejecting unsigned policy when signature required")
	}
}

func TestVaultPolicyLoader_BadSignature_KeepsLastGood(t *testing.T) {
	pub, priv := testKeypair(t)
	trust := trustWith(t, "primary", pub)
	goodBundle := string(mustSignBundle(t, minimalPolicyYAML, priv, "primary"))

	// Bad bundle: same structure, corrupted signature.
	badB, err := policy.SignPolicyYAML([]byte(updatedPolicyYAML), priv, "primary")
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(badB.Signature)
	sig[0] ^= 0xFF
	badB.Signature = base64.StdEncoding.EncodeToString(sig)
	badRaw, _ := json.Marshal(badB)

	var serveBad atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := goodBundle
		if serveBad.Load() {
			doc = string(badRaw)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]string{"policy.bundle": doc},
			},
		})
	}))
	defer srv.Close()

	loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
		Address:          srv.URL,
		Token:            "tok",
		PolicyPath:       "policy/test",
		RequireSignature: true,
		Trust:            trust,
	})
	if err := loader.Load(context.Background()); err != nil {
		t.Fatalf("initial Load: %v", err)
	}

	// Capture rule set from first good load (minimal = allow-sign only).
	first := loader.Engine().GetPolicy()
	if len(first.Rules) != 1 || first.Rules[0].ID != "allow-sign" {
		t.Fatalf("unexpected initial policy: %+v", first.Rules)
	}

	// Flip to bad signature and force a reload via internal path:
	// use a short reload loop, or call Load again — Load always reloads.
	// reload() on error must keep last engine. We exercise via background loop.
	serveBad.Store(true)

	// Direct second Load should fail but not wipe engine.
	// Note: Load starts another reloadLoop if interval set; use zero interval
	// and call reload by Load again — Load always calls reload first.
	// But Load with zero interval still replaces on success only.
	// We need to trigger reload that fails. Since Load() returns the error from
	// reload, and reload does not clear engine on error, a second Load that
	// fails should leave engine intact.
	err = loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error on bad signature reload")
	}

	// Last good policy retained.
	got := loader.Engine().GetPolicy()
	if len(got.Rules) != 1 || got.Rules[0].ID != "allow-sign" {
		t.Errorf("last-good not retained after bad sig; got %+v", got.Rules)
	}
}

func TestVaultPolicyLoader_BadSignature_ReloadLoopKeepsLastGood(t *testing.T) {
	if testing.Short() {
		// TODO(#4): skip until 2027-01-01 — timing-sensitive reload test
		t.Skip("skipping timing-sensitive reload test in short mode")
	}

	pub, priv := testKeypair(t)
	trust := trustWith(t, "primary", pub)
	goodBundle := string(mustSignBundle(t, minimalPolicyYAML, priv, "primary"))

	badB, _ := policy.SignPolicyYAML([]byte(updatedPolicyYAML), priv, "primary")
	sig, _ := base64.StdEncoding.DecodeString(badB.Signature)
	sig[0] ^= 0xFF
	badB.Signature = base64.StdEncoding.EncodeToString(sig)
	badRaw, _ := json.Marshal(badB)

	var serveBad atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := goodBundle
		if serveBad.Load() {
			doc = string(badRaw)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]string{"policy.bundle": doc},
			},
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loader := policy.NewVaultPolicyLoader(policy.VaultPolicyConfig{
		Address:          srv.URL,
		Token:            "tok",
		PolicyPath:       "policy/test",
		ReloadInterval:   40 * time.Millisecond,
		RequireSignature: true,
		Trust:            trust,
	})
	if err := loader.Load(ctx); err != nil {
		t.Fatalf("initial Load: %v", err)
	}

	serveBad.Store(true)
	time.Sleep(150 * time.Millisecond)

	got := loader.Engine().GetPolicy()
	if len(got.Rules) != 1 || got.Rules[0].ID != "allow-sign" {
		t.Errorf("reload loop must keep last-good on bad sig; got %+v", got.Rules)
	}
}
