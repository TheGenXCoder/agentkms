package policy

// sign_test.go — TDD for offline/CI policy bundle signing (Task 2).
//
// Round-trip contract under test: a Bundle produced by SignPolicyYAML must
// verify successfully via ParseAndVerify against a TrustStore holding the
// matching public key, with no re-serialization step in between. Bad inputs
// (empty yaml, empty key_id, wrong key length) must fail closed.

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func TestSignPolicyYAML_RoundTripWithParseAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}

	b, err := SignPolicyYAML([]byte(validPolicyYAML), priv, "primary")
	if err != nil {
		t.Fatalf("SignPolicyYAML() unexpected error: %v", err)
	}
	if b.KeyID != "primary" {
		t.Errorf("Bundle.KeyID = %q, want %q", b.KeyID, "primary")
	}
	if b.PolicyYAML != validPolicyYAML {
		t.Errorf("Bundle.PolicyYAML = %q, want %q", b.PolicyYAML, validPolicyYAML)
	}
	if b.SignedAt == "" {
		t.Error("Bundle.SignedAt is empty, want an RFC3339 timestamp")
	}

	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshalling signed bundle: %v", err)
	}

	trust := NewTrustStore()
	trust.AddKey("primary", pub)

	p, err := ParseAndVerify(data, trust)
	if err != nil {
		t.Fatalf("ParseAndVerify() on freshly signed bundle: %v", err)
	}
	if p == nil || p.Version != "1" {
		t.Fatalf("ParseAndVerify() returned unexpected policy: %+v", p)
	}
}

func TestSignPolicyYAML_EmptyYAMLErrors(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	if _, err := SignPolicyYAML(nil, priv, "primary"); err == nil {
		t.Fatal("SignPolicyYAML() succeeded with nil YAML, want error")
	}
	if _, err := SignPolicyYAML([]byte{}, priv, "primary"); err == nil {
		t.Fatal("SignPolicyYAML() succeeded with empty YAML slice, want error")
	}
}

func TestSignPolicyYAML_EmptyKeyIDErrors(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	if _, err := SignPolicyYAML([]byte(validPolicyYAML), priv, ""); err == nil {
		t.Fatal("SignPolicyYAML() succeeded with empty key_id, want error")
	}
}

func TestSignPolicyYAML_BadKeyLengthErrors(t *testing.T) {
	shortKey := make(ed25519.PrivateKey, 10)
	if _, err := SignPolicyYAML([]byte(validPolicyYAML), shortKey, "primary"); err == nil {
		t.Fatal("SignPolicyYAML() succeeded with a truncated private key, want error")
	}
}

func TestSignPolicyYAML_TamperAfterSignFailsVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	b, err := SignPolicyYAML([]byte(validPolicyYAML), priv, "primary")
	if err != nil {
		t.Fatalf("SignPolicyYAML() unexpected error: %v", err)
	}
	b.PolicyYAML += "\n# tampered"

	trust := NewTrustStore()
	trust.AddKey("primary", pub)
	if err := trust.VerifyBundle(b); err == nil {
		t.Fatal("VerifyBundle() succeeded on a bundle tampered after signing, want error")
	}
}
