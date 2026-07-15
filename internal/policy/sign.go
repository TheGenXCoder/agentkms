package policy

// sign.go — offline/CI signing helper for policy bundles.
//
// This file, and cmd/agentkms's `policy sign` subcommand, are the only
// places in the codebase that touch an ed25519.PrivateKey for policy
// bundles. The server load path (loader.go, vault_loader.go, TrustStore)
// only ever holds public keys — a private key never appears on that path.

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"
)

// SignPolicyYAML builds a v1 Bundle wrapping yaml: signature is
// base64.StdEncoding of ed25519.Sign(priv, yaml) over the exact yaml bytes
// (no re-serialization). keyID is stored in the envelope so the verifying
// side can look up the matching public key in a TrustStore.
//
// Fails closed: empty yaml, an empty keyID, or priv that is not a valid-length
// Ed25519 private key all return an error and a zero Bundle.
func SignPolicyYAML(yaml []byte, priv ed25519.PrivateKey, keyID string) (Bundle, error) {
	if len(yaml) == 0 {
		return Bundle{}, fmt.Errorf("policy: cannot sign empty YAML")
	}
	if keyID == "" {
		return Bundle{}, fmt.Errorf("policy: key_id must not be empty")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return Bundle{}, fmt.Errorf("policy: invalid ed25519 private key length %d (want %d)", len(priv), ed25519.PrivateKeySize)
	}

	sig := ed25519.Sign(priv, yaml)
	return Bundle{
		Version:    1,
		PolicyYAML: string(yaml),
		Signature:  base64.StdEncoding.EncodeToString(sig),
		KeyID:      keyID,
		SignedAt:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}
