package policy

// trust.go — trust store for signed policy bundle keys.
//
// A TrustStore maps a bundle's key_id to the Ed25519 public key that must
// have produced its signature. There is no implicit trust: a key_id absent
// from the store is rejected by VerifyBundle, never treated as "any key ok".

import (
	"crypto/ed25519"
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
