package policy

// bundle.go — signed policy bundle envelope + verification.
//
// A Bundle wraps a raw policy YAML document with an Ed25519 signature over
// the exact UTF-8 bytes of that document, so AgentKMS only activates policy
// signed by a trusted key. Verification is fail-closed: an unknown key_id,
// malformed signature, or signature mismatch are all indistinguishable
// rejections from the caller's perspective — ParseAndVerify returns a nil
// Policy and a non-nil error in every such case, never a partially-trusted
// result.
//
// The signature covers PolicyYAML as returned by JSON decoding, not a
// re-serialized form — this avoids canonicalization bugs where two JSON or
// YAML encoders disagree on whitespace/ordering and silently invalidate (or
// worse, revalidate a tampered) signature.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Bundle is the JSON envelope (v1) carrying a signed policy document.
type Bundle struct {
	Version    int    `json:"version"`
	PolicyYAML string `json:"policy_yaml"` // raw YAML text
	Signature  string `json:"signature"`   // base64.StdEncoding of ed25519 sig
	KeyID      string `json:"key_id"`
	SignedAt   string `json:"signed_at,omitempty"`
}

// LoadBundleJSON parses a JSON-encoded Bundle envelope. It does not verify
// the signature or load the wrapped policy.
func LoadBundleJSON(data []byte) (Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return Bundle{}, fmt.Errorf("policy: unmarshalling bundle JSON: %w", err)
	}
	return b, nil
}

// VerifyBundle checks that b.Signature is a valid Ed25519 signature, by the
// key registered under b.KeyID, over the exact bytes of b.PolicyYAML.
//
// Fail-closed: an unknown key_id, a signature that is not valid base64, or a
// signature that does not verify all return a non-nil error.
func (t *TrustStore) VerifyBundle(b Bundle) error {
	pub, ok := t.Lookup(b.KeyID)
	if !ok {
		return fmt.Errorf("policy: bundle key_id %q is not trusted", b.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil {
		return fmt.Errorf("policy: decoding bundle signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(b.PolicyYAML), sig) {
		return fmt.Errorf("policy: signature verification failed for key_id %q", b.KeyID)
	}
	return nil
}

// ParseAndVerify parses a JSON-encoded Bundle from data, verifies its
// signature against trust, and only then loads the wrapped policy YAML via
// LoadFromBytes. It returns a nil Policy alongside any error — including
// verification failure — so callers cannot accidentally use a partially
// processed result.
func ParseAndVerify(data []byte, trust *TrustStore) (*Policy, error) {
	b, err := LoadBundleJSON(data)
	if err != nil {
		return nil, err
	}
	if err := trust.VerifyBundle(b); err != nil {
		return nil, err
	}
	return LoadFromBytes([]byte(b.PolicyYAML))
}
