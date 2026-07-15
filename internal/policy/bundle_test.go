package policy

// bundle_test.go — TDD for signed policy bundle verification (Task 1).
//
// Fail-closed contract under test: ParseAndVerify must return a *Policy only
// when the bundle's signature is valid for a trusted key_id and covers the
// exact PolicyYAML bytes returned. Every other case — bad signature, unknown
// key_id, tampered YAML, malformed envelope — must return a non-nil error
// and a nil Policy.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

const validPolicyYAML = "version: \"1\"\nrules: []\n"

func signedBundle(t *testing.T, priv ed25519.PrivateKey, keyID, yamlBody string) Bundle {
	t.Helper()
	sig := ed25519.Sign(priv, []byte(yamlBody))
	return Bundle{
		Version:    1,
		PolicyYAML: yamlBody,
		Signature:  base64.StdEncoding.EncodeToString(sig),
		KeyID:      keyID,
	}
}

func marshalBundle(t *testing.T, b Bundle) []byte {
	t.Helper()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshalling test bundle: %v", err)
	}
	return data
}

func TestBundle_ParseAndVerify_GoodSignatureLoads(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	trust := NewTrustStore()
	trust.AddKey("primary", pub)

	b := signedBundle(t, priv, "primary", validPolicyYAML)
	p, err := ParseAndVerify(marshalBundle(t, b), trust)
	if err != nil {
		t.Fatalf("ParseAndVerify() unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("ParseAndVerify() returned nil Policy for a validly signed bundle")
	}
	if p.Version != "1" {
		t.Errorf("Policy.Version = %q, want \"1\"", p.Version)
	}
}

func TestBundle_ParseAndVerify_BadSignatureErrors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	trust := NewTrustStore()
	trust.AddKey("primary", pub)

	b := signedBundle(t, priv, "primary", validPolicyYAML)
	// Corrupt the signature bytes while keeping it valid base64.
	sigBytes, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil {
		t.Fatalf("decoding generated signature: %v", err)
	}
	sigBytes[0] ^= 0xFF
	b.Signature = base64.StdEncoding.EncodeToString(sigBytes)

	p, err := ParseAndVerify(marshalBundle(t, b), trust)
	if err == nil {
		t.Fatal("ParseAndVerify() succeeded with a corrupted signature, want error")
	}
	if p != nil {
		t.Fatal("ParseAndVerify() returned a non-nil Policy despite a bad signature")
	}
}

func TestBundle_ParseAndVerify_UnknownKeyIDErrors(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	trust := NewTrustStore() // no keys registered

	b := signedBundle(t, priv, "primary", validPolicyYAML)
	p, err := ParseAndVerify(marshalBundle(t, b), trust)
	if err == nil {
		t.Fatal("ParseAndVerify() succeeded with an untrusted key_id, want error")
	}
	if p != nil {
		t.Fatal("ParseAndVerify() returned a non-nil Policy for an untrusted key_id")
	}
}

func TestBundle_ParseAndVerify_TamperedYAMLErrors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	trust := NewTrustStore()
	trust.AddKey("primary", pub)

	b := signedBundle(t, priv, "primary", validPolicyYAML)
	// Tamper with the YAML after signing without re-signing.
	b.PolicyYAML = validPolicyYAML + "# tampered\n"

	p, err := ParseAndVerify(marshalBundle(t, b), trust)
	if err == nil {
		t.Fatal("ParseAndVerify() succeeded with tampered YAML, want error")
	}
	if p != nil {
		t.Fatal("ParseAndVerify() returned a non-nil Policy for tampered YAML")
	}
}

func TestBundle_ParseAndVerify_MalformedEnvelopeErrors(t *testing.T) {
	trust := NewTrustStore()
	p, err := ParseAndVerify([]byte("not json"), trust)
	if err == nil {
		t.Fatal("ParseAndVerify() succeeded on malformed JSON envelope, want error")
	}
	if p != nil {
		t.Fatal("ParseAndVerify() returned a non-nil Policy for a malformed envelope")
	}
}

func TestTrustStore_VerifyBundle_MalformedSignatureErrors(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	trust := NewTrustStore()
	trust.AddKey("primary", pub)

	b := Bundle{Version: 1, PolicyYAML: validPolicyYAML, Signature: "not-base64!!", KeyID: "primary"}
	if err := trust.VerifyBundle(b); err == nil {
		t.Fatal("VerifyBundle() succeeded with non-base64 signature, want error")
	}
}

func TestLoadBundleJSON_RoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	want := signedBundle(t, priv, "primary", validPolicyYAML)
	got, err := LoadBundleJSON(marshalBundle(t, want))
	if err != nil {
		t.Fatalf("LoadBundleJSON() unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("LoadBundleJSON() = %+v, want %+v", got, want)
	}
}
