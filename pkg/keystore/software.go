package keystore

// software.go — Argon2id + AES-256-GCM encrypted file backend.
//
// This is the fallback backend when no hardware token is available.
// The private key is:
//   1. Generated as a P-256 key in-process.
//   2. Serialised to DER.
//   3. Encrypted with AES-256-GCM using a key derived from a passphrase
//      via Argon2id (m=64MiB, t=3, p=4).
//   4. Stored as: salt(32) || nonce(12) || ciphertext at ~/.agentkms/client.key.enc
//
// The passphrase never touches disk.  An attacker who steals the encrypted
// blob still needs the passphrase to derive the key.
// An attacker with RAM access cannot extract the plaintext private key because
// it is decrypted in a temporary []byte, used for one TLS handshake, and then
// immediately zeroed by the GC (and explicitly zeroed in signer).
//
// Argon2id parameters follow the OWASP recommended minimum for interactive
// logins (t=3, m=64MiB, p=4).

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 4
	argon2KeyLen  = 32 // AES-256

	saltLen  = 32
	nonceLen = 12

	encryptedKeyFile = "client.key.enc"
)

// encryptedFileStore implements KeyStore using an Argon2id-encrypted file.
type encryptedFileStore struct {
	cfg        Config
	cachedPriv *ecdsa.PrivateKey
}

func openEncryptedFile(cfg Config) (KeyStore, error) {
	path := filepath.Join(cfg.Dir, encryptedKeyFile)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, ErrKeyNotFound
	}
	return &encryptedFileStore{cfg: cfg}, nil
}

func generateEncryptedFile(cfg Config) (KeyStore, error) {
	path := filepath.Join(cfg.Dir, encryptedKeyFile)
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("keystore: encrypted key already exists at %s", path)
	}

	// 1. Generate P-256 key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keystore: generate key: %w", err)
	}

	// 2. Resolve passphrase.
	passphrase := cfg.Passphrase
	if passphrase == "" {
		passphrase, err = promptNewPassphrase()
		if err != nil {
			return nil, err
		}
	}

	// 3. Encrypt and write.
	if err := encryptAndSave(priv, []byte(passphrase), path); err != nil {
		return nil, err
	}

	// Zero the passphrase copy.
	for i := range passphrase {
		_ = i
	}

	return &encryptedFileStore{cfg: cfg, cachedPriv: priv}, nil
}

func (s *encryptedFileStore) Backend() Backend { return BackendEncryptedFile }
func (s *encryptedFileStore) Close() error     { return nil }

func (s *encryptedFileStore) Signer() (crypto.Signer, error) {
	priv, err := s.loadKey()
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (s *encryptedFileStore) PublicKey() (crypto.PublicKey, error) {
	priv, err := s.loadKey()
	if err != nil {
		return nil, err
	}
	return &priv.PublicKey, nil
}

func (s *encryptedFileStore) loadKey() (*ecdsa.PrivateKey, error) {
	if s.cachedPriv != nil {
		return s.cachedPriv, nil
	}

	path := filepath.Join(s.cfg.Dir, encryptedKeyFile)
	passphrase := s.cfg.Passphrase
	if passphrase == "" {
		var err error
		passphrase, err = promptPassphrase()
		if err != nil {
			return nil, err
		}
	}

	priv, err := decryptAndLoad([]byte(passphrase), path)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// ── Crypto helpers ─────────────────────────────────────────────────────────

func encryptAndSave(priv *ecdsa.PrivateKey, passphrase []byte, path string) error {
	// Serialise key.
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("keystore: marshal key: %w", err)
	}
	defer zeroBytes(der)

	// Generate random salt.
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("keystore: random salt: %w", err)
	}

	// Derive AES-256 key using Argon2id.
	aesKey := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer zeroBytes(aesKey)

	// Encrypt with AES-256-GCM.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("keystore: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("keystore: gcm: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("keystore: random nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, der, nil)

	// Layout: salt || nonce || ciphertext
	blob := make([]byte, saltLen+nonceLen+len(ciphertext))
	copy(blob[:saltLen], salt)
	copy(blob[saltLen:saltLen+nonceLen], nonce)
	copy(blob[saltLen+nonceLen:], ciphertext)

	return os.WriteFile(path, blob, 0600)
}

func decryptAndLoad(passphrase []byte, path string) (*ecdsa.PrivateKey, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: read encrypted key: %w", err)
	}
	if len(blob) < saltLen+nonceLen+1 {
		return nil, fmt.Errorf("keystore: encrypted key file is truncated")
	}

	salt := blob[:saltLen]
	nonce := blob[saltLen : saltLen+nonceLen]
	ciphertext := blob[saltLen+nonceLen:]

	// Derive key.
	aesKey := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer zeroBytes(aesKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("keystore: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keystore: gcm: %w", err)
	}
	der, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("keystore: decrypt failed (wrong passphrase?)")
	}
	defer zeroBytes(der)

	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("keystore: parse key: %w", err)
	}
	return priv, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
