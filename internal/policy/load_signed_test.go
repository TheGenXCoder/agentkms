package policy_test

// load_signed_test.go — Task 3: VaultPolicyLoader signed-bundle path (fail-closed).
//
// Contracts under test:
//   - good signed bundle (KV field policy.bundle) loads
//   - bad signature keeps last-good policy on reload
//   - unsigned YAML rejected when RequireSignature is true

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentkms/agentkms/internal/policy"
)

func vaultTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func vaultTrust(t *testing.T, keyID string, pub ed25519.PublicKey) *policy.TrustStore {
	t.Helper()
	ts := policy.NewTrustStore()
	ts.AddKey(keyID, pub)
	return ts
}

func vaultMustSignBundle(t *testing.T, yamlBody string, priv ed25519.PrivateKey, keyID string) []byte {
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

func TestVaultPolicyLoader_Load_GoodSignedBundle(t *testing.T) {
	pub, priv := vaultTestKeypair(t)
	trust := vaultTrust(t, "primary", pub)
	bundle := string(vaultMustSignBundle(t, minimalPolicyYAML, priv, "primary"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]string{"policy.bundle": bundle},
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
		t.Fatalf("Load good bundle: %v", err)
	}
	if loader.Engine() == nil {
		t.Fatal("Engine nil after good signed load")
	}
	got := loader.Engine().GetPolicy()
	if len(got.Rules) != 1 || got.Rules[0].ID != "allow-sign" {
		t.Errorf("unexpected policy rules: %+v", got.Rules)
	}
}

func TestVaultPolicyLoader_Load_UnsignedRejectedWhenRequired(t *testing.T) {
	pub, _ := vaultTestKeypair(t)
	trust := vaultTrust(t, "primary", pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]string{"policy": minimalPolicyYAML},
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
	err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error rejecting unsigned policy when signature required")
	}
}

func TestVaultPolicyLoader_BadSignature_KeepsLastGood(t *testing.T) {
	pub, priv := vaultTestKeypair(t)
	trust := vaultTrust(t, "primary", pub)
	goodBundle := string(vaultMustSignBundle(t, minimalPolicyYAML, priv, "primary"))

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

	first := loader.Engine().GetPolicy()
	if len(first.Rules) != 1 || first.Rules[0].ID != "allow-sign" {
		t.Fatalf("unexpected initial policy: %+v", first.Rules)
	}

	serveBad.Store(true)
	// Second Load fails closed; engine must retain last-good policy.
	if err := loader.Load(context.Background()); err == nil {
		t.Fatal("expected error on bad signature reload")
	}

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

	pub, priv := vaultTestKeypair(t)
	trust := vaultTrust(t, "primary", pub)
	goodBundle := string(vaultMustSignBundle(t, minimalPolicyYAML, priv, "primary"))

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
