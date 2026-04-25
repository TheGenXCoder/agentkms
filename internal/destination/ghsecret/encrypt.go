package ghsecret

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// Seal encrypts plaintext using a libsodium-compatible sealed box addressed to
// the public key encoded in base64PubKey (base64-encoded Curve25519 key as
// returned by the GitHub public-key API).
//
// The output is the raw ciphertext bytes. The caller is responsible for
// base64-encoding the result before sending it to the GitHub API.
//
// Algorithm: NaCl anonymous sealed box (Curve25519 + XSalsa20-Poly1305),
// implemented by golang.org/x/crypto/nacl/box.SealAnonymous. This is
// interoperable with libsodium crypto_box_seal. GitHub requires this exact
// construction for Actions secrets.
//
// A new ephemeral sender keypair is generated for each call by SealAnonymous,
// satisfying the one-time nonce requirement.
func Seal(plaintext []byte, base64PubKey string) ([]byte, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		// GitHub sometimes returns standard or URL-safe base64; try URL-safe.
		pubKeyBytes, err = base64.RawURLEncoding.DecodeString(base64PubKey)
		if err != nil {
			return nil, fmt.Errorf("ghsecret: Seal: decode public key: %w", err)
		}
	}
	if len(pubKeyBytes) != 32 {
		return nil, fmt.Errorf("ghsecret: Seal: public key must be 32 bytes, got %d", len(pubKeyBytes))
	}

	var recipientKey [32]byte
	copy(recipientKey[:], pubKeyBytes)

	ciphertext, err := box.SealAnonymous(nil, plaintext, &recipientKey, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ghsecret: Seal: SealAnonymous: %w", err)
	}
	return ciphertext, nil
}

// SealBase64 is a convenience wrapper that returns the base64-encoded ciphertext
// ready to include in the GitHub API JSON body.
func SealBase64(plaintext []byte, base64PubKey string) (string, error) {
	ct, err := Seal(plaintext, base64PubKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}
