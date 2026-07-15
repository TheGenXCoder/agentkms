package policy

// trust.go — trust store for signed policy bundle keys.
//
// A TrustStore maps a bundle's key_id to the Ed25519 public key that must
// have produced its signature. There is no implicit trust: a key_id absent
// from the store is rejected by VerifyBundle, never treated as "any key ok".

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// TrustStore holds the set of Ed25519 public keys trusted to sign policy
// bundles, indexed by key_id.
type TrustStore struct {
	keys map[string]ed25519.PublicKey
}

// NewTrustStore returns an empty TrustStore.
func NewTrustStore() *TrustStore {
	return &TrustStore{keys: make(map[string]ed25519.PublicKey)}
}

// AddKey registers pub as the trusted public key for keyID, overwriting any
// key previously registered under the same id.
func (t *TrustStore) AddKey(keyID string, pub ed25519.PublicKey) {
	t.keys[keyID] = pub
}

// Lookup returns the public key registered under keyID, and whether one was
// found.
func (t *TrustStore) Lookup(keyID string) (ed25519.PublicKey, bool) {
	pub, ok := t.keys[keyID]
	return pub, ok
}

// Len returns the number of trusted keys.
func (t *TrustStore) Len() int {
	if t == nil {
		return 0
	}
	return len(t.keys)
}

// LoadTrustStoreFromJSON parses a JSON object mapping key_id → hex-encoded
// Ed25519 public key (32 bytes / 64 hex chars). Empty maps are rejected.
//
// Example:
//
//	{"primary": "a1b2c3..."}
func LoadTrustStoreFromJSON(data []byte) (*TrustStore, error) {
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("policy: unmarshalling trust keys JSON: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("policy: trust keys JSON contains no keys")
	}
	ts := NewTrustStore()
	for id, hexPub := range raw {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, fmt.Errorf("policy: trust keys JSON has empty key_id")
		}
		hexPub = strings.TrimSpace(hexPub)
		// Accept optional 0x prefix.
		hexPub = strings.TrimPrefix(strings.ToLower(hexPub), "0x")
		pubBytes, err := hex.DecodeString(hexPub)
		if err != nil {
			return nil, fmt.Errorf("policy: trust key %q: invalid hex public key: %w", id, err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("policy: trust key %q: public key length %d, want %d",
				id, len(pubBytes), ed25519.PublicKeySize)
		}
		ts.AddKey(id, ed25519.PublicKey(pubBytes))
	}
	return ts, nil
}

// LoadTrustStoreFromFile reads a trust-keys JSON file from path.
func LoadTrustStoreFromFile(path string) (*TrustStore, error) {
	data, err := os.ReadFile(path) // #nosec G304 — path is caller-supplied config
	if err != nil {
		return nil, fmt.Errorf("policy: reading trust keys file %q: %w", path, err)
	}
	ts, err := LoadTrustStoreFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("policy: loading trust keys from %q: %w", path, err)
	}
	return ts, nil
}
