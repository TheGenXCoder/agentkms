package policy

// signed_bundle_smoke_test.go — Task 5: signed-policy-bundles integration
// smoke test.
//
// End-to-end path: generate an ephemeral Ed25519 key, sign the canonical
// docs/examples/policy-catalog-visibility.yaml with SignPolicyYAML, register
// the pubkey in a TrustStore, load the resulting bundle through the real
// LoadPolicyFromPath verify+load path (RequireSignature: true, matching prod
// config), and confirm the deny-list behavior for supersecret/** still holds
// once evaluated through Engine — not just at ParseAndVerify.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"crypto/ed25519"

	"github.com/agentkms/agentkms/pkg/identity"
)

// catalogVisibilityPolicyPath returns the absolute path to
// docs/examples/policy-catalog-visibility.yaml.
func catalogVisibilityPolicyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "docs", "examples", "policy-catalog-visibility.yaml")
}

func TestSignedBundle_Smoke_CatalogVisibilityDenyListHoldsThroughEngine(t *testing.T) {
	yamlPath := catalogVisibilityPolicyPath(t)
	yamlBody, err := os.ReadFile(yamlPath) // #nosec G304 — fixed test fixture path
	if err != nil {
		t.Fatalf("reading %q: %v", yamlPath, err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating ephemeral test key: %v", err)
	}

	bundle, err := SignPolicyYAML(yamlBody, priv, "smoke-test-key")
	if err != nil {
		t.Fatalf("SignPolicyYAML: %v", err)
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshalling bundle: %v", err)
	}

	bundlePath := filepath.Join(t.TempDir(), "policy-catalog-visibility.bundle.json")
	if err := os.WriteFile(bundlePath, bundleJSON, 0o600); err != nil {
		t.Fatalf("writing bundle file: %v", err)
	}

	trust := NewTrustStore()
	trust.AddKey("smoke-test-key", pub)

	p, err := LoadPolicyFromPath(bundlePath, LoadConfig{RequireSignature: true, Trust: trust})
	if err != nil {
		t.Fatalf("LoadPolicyFromPath(%q): %v", bundlePath, err)
	}

	eng := New(*p)
	caller := identity.Identity{CallerID: "app@platform-team"}

	t.Run("vend_allowed_for_stripe_master", func(t *testing.T) {
		d := eng.Evaluate(caller, OpCredentialVend, "supersecret/stripe-master")
		if !d.Allow {
			t.Errorf("credential_vend on supersecret/stripe-master: Allow = false, want true (DenyReason: %q)", d.DenyReason)
		}
	})

	t.Run("metadata_list_denied_for_supersecret_tree", func(t *testing.T) {
		d := eng.Evaluate(caller, OpMetadataList, "supersecret/stripe-master")
		if d.Allow {
			t.Error("metadata_list on supersecret/** : Allow = true, want false (deny-list-supersecret must hold)")
		}
	})
}

func TestSignedBundle_Smoke_UnsignedYAMLRejectedWhenSignatureRequired(t *testing.T) {
	yamlPath := catalogVisibilityPolicyPath(t)
	trust := NewTrustStore()
	trust.AddKey("smoke-test-key", ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))

	if _, err := LoadPolicyFromPath(yamlPath, LoadConfig{RequireSignature: true, Trust: trust}); err == nil {
		t.Fatal("LoadPolicyFromPath() on raw unsigned YAML succeeded with RequireSignature=true, want error")
	}
}
