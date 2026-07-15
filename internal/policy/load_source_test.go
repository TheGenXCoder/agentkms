package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const loadSourcePolicyYAML = `version: "1"
rules:
  - id: allow-all
    effect: allow
    match:
      identity:
        caller_id_pattern: "*"
      operations: ["sign"]
`

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func TestLoadPolicyFromPath_GoodBundle(t *testing.T) {
	pub, priv := testKeyPair(t)
	trust := NewTrustStore()
	trust.AddKey("primary", pub)

	b, err := SignPolicyYAML([]byte(loadSourcePolicyYAML), priv, "primary")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(b)
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.bundle.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := LoadPolicyFromPath(path, LoadConfig{Trust: trust, RequireSignature: true})
	if err != nil {
		t.Fatalf("LoadPolicyFromPath: %v", err)
	}
	if p == nil || len(p.Rules) != 1 {
		t.Fatalf("unexpected policy: %+v", p)
	}
}

func TestLoadPolicyFromPath_UnsignedRejectedWhenRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(loadSourcePolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	trust := NewTrustStore()
	_, err := LoadPolicyFromPath(path, LoadConfig{Trust: trust, RequireSignature: true})
	if err == nil {
		t.Fatal("expected error for unsigned YAML when RequireSignature")
	}
}

func TestLoadPolicyFromPath_UnsignedAllowedWhenNotRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(loadSourcePolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicyFromPath(path, LoadConfig{RequireSignature: false})
	if err != nil {
		t.Fatalf("LoadPolicyFromPath: %v", err)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("rules=%d", len(p.Rules))
	}
}

func TestLoadPolicyFromPath_PrefersBundleBesideYAML(t *testing.T) {
	pub, priv := testKeyPair(t)
	trust := NewTrustStore()
	trust.AddKey("primary", pub)
	b, err := SignPolicyYAML([]byte(loadSourcePolicyYAML), priv, "primary")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(b)
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(yamlPath, []byte("version: \"1\"\nrules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.bundle.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicyFromPath(yamlPath, LoadConfig{Trust: trust, RequireSignature: true})
	if err != nil {
		t.Fatalf("LoadPolicyFromPath: %v", err)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("expected rules from bundle not empty yaml, got %d", len(p.Rules))
	}
}

func TestLoadTrustStoreFromJSON_File(t *testing.T) {
	pub, _ := testKeyPair(t)
	doc := map[string]string{"primary": hex.EncodeToString(pub)}
	raw, _ := json.Marshal(doc)
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ts, err := LoadTrustStoreFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ts.Lookup("primary")
	if !ok || !got.Equal(pub) {
		t.Fatalf("lookup failed ok=%v", ok)
	}
}

func TestParseAndVerify_TamperFailsClosed(t *testing.T) {
	pub, priv := testKeyPair(t)
	trust := NewTrustStore()
	trust.AddKey("primary", pub)
	good, err := SignPolicyYAML([]byte(loadSourcePolicyYAML), priv, "primary")
	if err != nil {
		t.Fatal(err)
	}
	goodRaw, _ := json.Marshal(good)
	p1, err := ParseAndVerify(goodRaw, trust)
	if err != nil || p1 == nil {
		t.Fatalf("good: %v", err)
	}
	var bad Bundle
	_ = json.Unmarshal(goodRaw, &bad)
	bad.PolicyYAML = bad.PolicyYAML + "\n# tampered"
	badRaw, _ := json.Marshal(bad)
	p2, err := ParseAndVerify(badRaw, trust)
	if err == nil || p2 != nil {
		t.Fatal("expected tampered bundle to fail")
	}
}
