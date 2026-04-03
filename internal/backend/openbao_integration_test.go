//go:build integration

// Package backend — B-02: integration tests for OpenBaoBackend.
//
// These tests run against a real Vault/OpenBao instance.  They are gated
// behind the "integration" build tag to keep `go test ./...` fast and free
// of external dependencies.
//
// Running integration tests:
//
//	# Automatic (starts vault server -dev subprocess):
//	go test -v -tags integration ./internal/backend/
//
//	# Against an existing instance:
//	AGENTKMS_VAULT_ADDR=http://127.0.0.1:8200 \
//	  AGENTKMS_VAULT_TOKEN=root \
//	  go test -v -tags integration ./internal/backend/
//
// Test categories (mirrors dev_test.go + OpenBao-specific):
//  1. Happy-path correctness: sign → verify, encrypt → decrypt roundtrips.
//  2. Key versioning: rotate → old ciphertext still decryptable.
//  3. ADVERSARIAL: key material never in return values, error messages, or
//     any Transit response surfaced through the Backend interface.
//  4. Input validation: malformed inputs return sentinel errors.
//  5. Context cancellation: cancelled contexts return errors.
//  6. Concurrency: methods are safe for parallel goroutines.
//  7. ListKeys / RotateKey: metadata only.
//  8. OpenBao-specific: namespace handling, mount path, unknown key types.
package backend

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Test setup ────────────────────────────────────────────────────────────────

// integrationEnv holds the connection details for a running Vault instance.
type integrationEnv struct {
	addr    string
	token   string
	version string // Vault/OpenBao version string, populated in TestMain
}

// globalEnv is set once in TestMain for the duration of the test binary run.
var globalEnv integrationEnv

// vaultProcess is the subprocess handle when we started vault ourselves.
var vaultProcess *os.Process

// TestMain starts (or connects to) a Vault dev server, enables Transit, and
// runs all integration tests.  Vault is stopped on exit if we started it.
func TestMain(m *testing.M) {
	globalEnv = resolveEnv()

	externalAddr := os.Getenv("AGENTKMS_VAULT_ADDR") != ""

	if !waitForVault(globalEnv.addr, globalEnv.token, 3*time.Second) {
		if externalAddr {
			// Caller explicitly pointed at an instance — don't start a dev
			// server; report the failure clearly.
			fmt.Fprintf(os.Stderr, "FATAL: vault not reachable at %s (AGENTKMS_VAULT_ADDR is set)\n",
				globalEnv.addr)
			os.Exit(1)
		}
		// No existing instance and no explicit address — start one.
		proc, err := startVaultDev(globalEnv.addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: could not start vault dev server: %v\n", err)
			os.Exit(1)
		}
		vaultProcess = proc
		if !waitForVault(globalEnv.addr, globalEnv.token, 15*time.Second) {
			vaultProcess.Kill() //nolint:errcheck
			fmt.Fprintf(os.Stderr, "FATAL: vault did not become ready in time\n")
			os.Exit(1)
		}
	}

	// Populate version for use in skip messages.
	globalEnv.version = getVaultVersion(globalEnv.addr, globalEnv.token)

	if err := enableTransit(globalEnv.addr, globalEnv.token, "transit"); err != nil {
		if vaultProcess != nil {
			vaultProcess.Kill() //nolint:errcheck
		}
		fmt.Fprintf(os.Stderr, "FATAL: enable transit: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	if vaultProcess != nil {
		vaultProcess.Kill() //nolint:errcheck
	}
	os.Exit(code)
}

// resolveEnv returns connection details from env vars or defaults.
func resolveEnv() integrationEnv {
	addr := os.Getenv("AGENTKMS_VAULT_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:18200" // non-standard port to avoid conflicts
	}
	token := os.Getenv("AGENTKMS_VAULT_TOKEN")
	if token == "" {
		token = "root"
	}
	return integrationEnv{addr: addr, token: token}
}

// startVaultDev starts a vault dev server as a subprocess.
// Returns the process handle; caller is responsible for killing it.
func startVaultDev(addr string) (*os.Process, error) {
	// Extract host:port from addr for -dev-listen-address.
	listenAddr := strings.TrimPrefix(addr, "http://")
	listenAddr = strings.TrimPrefix(listenAddr, "https://")

	cmd := exec.Command("vault", "server",
		"-dev",
		"-dev-root-token-id=root",
		fmt.Sprintf("-dev-listen-address=%s", listenAddr),
	)
	// Suppress vault's startup output in test runs; redirect to /dev/null.
	cmd.Stdout = os.Stderr // vault logs to stdout in dev mode
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("exec vault: %w", err)
	}
	return cmd.Process, nil
}

// getVaultVersion reads the Vault version string from /v1/sys/health.
// Returns "unknown" on any error.
func getVaultVersion(addr, token string) string {
	req, _ := http.NewRequest(http.MethodGet, addr+"/v1/sys/health", nil)
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close() //nolint:errcheck
	var body struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "unknown"
	}
	return body.Version
}

// waitForVault polls the Vault health endpoint until it responds healthy or
// timeout elapses.  If timeout is zero, it tries once without sleeping.
func waitForVault(addr, token string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	first := true
	for {
		if !first && time.Now().After(deadline) {
			return false
		}
		first = false

		req, _ := http.NewRequest(http.MethodGet, addr+"/v1/sys/health", nil)
		req.Header.Set("X-Vault-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close() //nolint:errcheck
			// 200 = initialised, unsealed, active.
			// 429 = standby (still usable).
			if resp.StatusCode == http.StatusOK || resp.StatusCode == 429 {
				return true
			}
		}

		if timeout == 0 {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// enableTransit mounts the Transit secrets engine at mountPath.
// Silently succeeds if it is already mounted.
func enableTransit(addr, token, mountPath string) error {
	body := `{"type":"transit"}`
	req, err := http.NewRequest(http.MethodPost,
		addr+"/v1/sys/mounts/"+mountPath,
		strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("enable transit: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// 200/204 = success.
	// 400 = path already in use (already mounted) — idempotent, fine.
	// 403 on existing cluster = transit already mounted; treat as idempotent.
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusBadRequest, http.StatusForbidden:
		return nil
	}
	return fmt.Errorf("enable transit: HTTP %d", resp.StatusCode)
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

// newIntegrationBackend returns an OpenBaoBackend pointed at the test instance.
func newIntegrationBackend(t *testing.T) *OpenBaoBackend {
	t.Helper()
	b, err := NewOpenBaoBackend(OpenBaoConfig{
		Address: globalEnv.addr,
		Token:   globalEnv.token,
	})
	if err != nil {
		t.Fatalf("NewOpenBaoBackend: %v", err)
	}
	return b
}

// createKey creates a Transit key for the test and registers a cleanup to
// delete it afterwards.  Each test gets unique key names via t.Name().
func createKey(t *testing.T, b *OpenBaoBackend, keyID string, alg Algorithm) {
	t.Helper()
	ctx := context.Background()
	if err := b.CreateTransitKey(ctx, keyID, alg, "test-team"); err != nil {
		t.Fatalf("CreateTransitKey(%q, %q): %v", keyID, alg, err)
	}
	t.Cleanup(func() {
		deleteTransitKey(globalEnv.addr, globalEnv.token, keyID) //nolint:errcheck
	})
}

// deleteTransitKey removes a Transit key (best-effort, used in cleanup).
// Must first enable deletion, then delete.
func deleteTransitKey(addr, token, keyID string) error {
	// First: allow deletion.
	body := `{"deletion_allowed":true}`
	req, _ := http.NewRequest(http.MethodPost,
		addr+"/v1/transit/keys/"+keyID+"/config",
		strings.NewReader(body))
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	http.DefaultClient.Do(req) //nolint:errcheck

	// Then: delete.
	req2, _ := http.NewRequest(http.MethodDelete, addr+"/v1/transit/keys/"+keyID, nil)
	req2.Header.Set("X-Vault-Token", token)
	_, err := http.DefaultClient.Do(req2)
	return err
}

// uniqueKeyID returns a key ID that is unique to this test invocation
// (avoiding collisions when running tests in parallel or multiple times).
func uniqueKeyID(t *testing.T, suffix string) string {
	t.Helper()
	// Replace characters invalid in Transit key names.
	name := strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	return fmt.Sprintf("inttest-%s-%s", name, suffix)
}

// intTestHash returns a deterministic 32-byte hash for a given string.
func intTestHash(msg string) []byte {
	h := sha256.Sum256([]byte(msg))
	return h[:]
}

// ── 1. Happy-path correctness ─────────────────────────────────────────────────

func TestOpenBao_Sign_ES256_RoundTrip(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "es256")
	createKey(t, b, keyID, AlgorithmES256)

	hash := intTestHash("openBao ES256 roundtrip")
	result, err := b.Sign(context.Background(), keyID, hash, AlgorithmES256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(result.Signature) == 0 {
		t.Fatal("Sign returned empty signature")
	}
	if result.KeyVersion < 1 {
		t.Fatalf("unexpected KeyVersion %d", result.KeyVersion)
	}

	// Verify the signature using the public key from Transit.
	pubKey := getECPublicKey(t, b, keyID, result.KeyVersion)
	if !ecdsa.VerifyASN1(pubKey, hash, result.Signature) {
		t.Fatal("ECDSA signature verification failed")
	}
}

func TestOpenBao_Sign_RS256_RoundTrip(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "rs256")
	createKey(t, b, keyID, AlgorithmRS256)

	hash := intTestHash("openBao RS256 roundtrip")
	result, err := b.Sign(context.Background(), keyID, hash, AlgorithmRS256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(result.Signature) == 0 {
		t.Fatal("Sign returned empty signature")
	}

	pubKey := getRSAPublicKey(t, b, keyID, result.KeyVersion)
	// Vault Transit wraps PKCS1v15 with DigestInfo (SHA-256 OID), so we must
	// verify with crypto.SHA256, not the raw-RSA form (hash=0) used by DevBackend.
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash, result.Signature); err != nil {
		t.Fatalf("RSA signature verification failed: %v", err)
	}
}

func TestOpenBao_Sign_EdDSA_RoundTrip(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "eddsa")
	createKey(t, b, keyID, AlgorithmEdDSA)

	hash := intTestHash("openBao EdDSA roundtrip")
	result, err := b.Sign(context.Background(), keyID, hash, AlgorithmEdDSA)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(result.Signature) != ed25519.SignatureSize {
		t.Fatalf("expected %d-byte EdDSA signature, got %d",
			ed25519.SignatureSize, len(result.Signature))
	}

	pubKey := getEdPublicKey(t, b, keyID, result.KeyVersion)
	if !ed25519.Verify(pubKey, hash, result.Signature) {
		t.Fatal("Ed25519 signature verification failed")
	}
}

func TestOpenBao_Encrypt_Decrypt_RoundTrip(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "aes")
	createKey(t, b, keyID, AlgorithmAES256GCM)

	plaintext := []byte("AgentKMS OpenBao encrypt/decrypt roundtrip test")
	enc, err := b.Encrypt(context.Background(), keyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(enc.Ciphertext) == 0 {
		t.Fatal("Encrypt returned empty ciphertext")
	}
	if bytes.Equal(enc.Ciphertext, plaintext) {
		t.Fatal("ciphertext equals plaintext — encryption not applied")
	}
	if enc.KeyVersion < 1 {
		t.Fatalf("unexpected KeyVersion %d", enc.KeyVersion)
	}

	dec, err := b.Decrypt(context.Background(), keyID, enc.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(dec.Plaintext, plaintext) {
		t.Fatalf("Decrypt produced wrong plaintext:\n  want: %q\n  got:  %q",
			plaintext, dec.Plaintext)
	}
}

func TestOpenBao_Encrypt_EmptyPlaintext(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "aes-empty")
	createKey(t, b, keyID, AlgorithmAES256GCM)

	enc, err := b.Encrypt(context.Background(), keyID, []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty plaintext: %v", err)
	}
	dec, err := b.Decrypt(context.Background(), keyID, enc.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt of empty plaintext: %v", err)
	}
	if len(dec.Plaintext) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(dec.Plaintext))
	}
}

// ── 2. Key versioning ─────────────────────────────────────────────────────────

func TestOpenBao_RotateKey_NewVersionUsed(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "rotate-sign")
	createKey(t, b, keyID, AlgorithmES256)

	hash := intTestHash("before rotation")
	r1, err := b.Sign(context.Background(), keyID, hash, AlgorithmES256)
	if err != nil {
		t.Fatalf("Sign v1: %v", err)
	}
	if r1.KeyVersion != 1 {
		t.Fatalf("expected KeyVersion 1 before rotation, got %d", r1.KeyVersion)
	}

	meta, err := b.RotateKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if meta.Version != 2 {
		t.Fatalf("expected version 2 after rotation, got %d", meta.Version)
	}
	if meta.RotatedAt == nil {
		t.Fatal("RotatedAt should be non-nil after rotation")
	}

	r2, err := b.Sign(context.Background(), keyID, hash, AlgorithmES256)
	if err != nil {
		t.Fatalf("Sign v2: %v", err)
	}
	if r2.KeyVersion != 2 {
		t.Fatalf("expected KeyVersion 2 after rotation, got %d", r2.KeyVersion)
	}
}

func TestOpenBao_RotateKey_OldCiphertextStillDecryptable(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "rotate-enc")
	createKey(t, b, keyID, AlgorithmAES256GCM)

	plaintext := []byte("data encrypted before rotation")
	enc1, err := b.Encrypt(context.Background(), keyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt v1: %v", err)
	}
	if enc1.KeyVersion != 1 {
		t.Fatalf("expected KeyVersion 1, got %d", enc1.KeyVersion)
	}

	if _, err := b.RotateKey(context.Background(), keyID); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	enc2, err := b.Encrypt(context.Background(), keyID, []byte("new data"))
	if err != nil {
		t.Fatalf("Encrypt v2: %v", err)
	}
	if enc2.KeyVersion != 2 {
		t.Fatalf("expected KeyVersion 2 after rotation, got %d", enc2.KeyVersion)
	}

	// Old ciphertext (v1) must still decrypt.
	dec1, err := b.Decrypt(context.Background(), keyID, enc1.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt v1 ciphertext after rotation: %v", err)
	}
	if !bytes.Equal(dec1.Plaintext, plaintext) {
		t.Fatalf("decrypted v1 plaintext mismatch:\n  want: %q\n  got:  %q",
			plaintext, dec1.Plaintext)
	}

	// New ciphertext (v2) also decrypts.
	dec2, err := b.Decrypt(context.Background(), keyID, enc2.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt v2 ciphertext: %v", err)
	}
	if string(dec2.Plaintext) != "new data" {
		t.Fatalf("decrypted v2 plaintext mismatch: %q", dec2.Plaintext)
	}
}

// ── 3. ADVERSARIAL — key material never in return values ──────────────────────

// TestAdversarial_OpenBao_Sign_NoKeyMaterialInResult verifies that no Transit
// operation returns key material through the Backend interface.
//
// Unlike the DevBackend adversarial tests, we cannot access the raw private key
// bytes from inside Transit (that is the whole point of Transit).  Instead, we
// verify:
//  (a) The result fields contain only what the interface promises.
//  (b) The JSON-serialised result contains no "BEGIN" PEM headers.
//  (c) The signature length matches algorithm expectations.
func TestAdversarial_OpenBao_Sign_ES256_ResultContainsNoKeyMaterial(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "adv-es256")
	createKey(t, b, keyID, AlgorithmES256)

	hash := intTestHash("adversarial ES256 OpenBao")
	result, err := b.Sign(context.Background(), keyID, hash, AlgorithmES256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// SignResult must only contain Signature (bytes) and KeyVersion (int).
	// Neither field can hold private key material by type alone, but we also
	// check JSON serialisation.
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(SignResult): %v", err)
	}
	assertNoPEMHeaders(t, "SignResult", encoded)
	assertNoVaultPrefix(t, "SignResult", encoded) // raw vault: prefix must be stripped
}

func TestAdversarial_OpenBao_EncryptResult_NoKeyMaterial(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "adv-aes-enc")
	createKey(t, b, keyID, AlgorithmAES256GCM)

	result, err := b.Encrypt(context.Background(), keyID, []byte("adversarial plaintext"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(EncryptResult): %v", err)
	}

	// Ciphertext is the vault: string — that is fine (it's opaque ciphertext,
	// not key material).  But there must be no PEM-encoded key material.
	assertNoPEMHeaders(t, "EncryptResult", encoded)

	// The plaintext must not appear in the ciphertext bytes.
	if bytes.Contains(result.Ciphertext, []byte("adversarial plaintext")) {
		t.Fatal("ADVERSARIAL: plaintext appears in EncryptResult.Ciphertext")
	}
}

func TestAdversarial_OpenBao_DecryptResult_NoKeyMaterial(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "adv-aes-dec")
	createKey(t, b, keyID, AlgorithmAES256GCM)

	plaintext := []byte("adversarial decrypt test")
	enc, err := b.Encrypt(context.Background(), keyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	dec, err := b.Decrypt(context.Background(), keyID, enc.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	// DecryptResult contains only the original plaintext.
	encoded, err := json.Marshal(dec)
	if err != nil {
		t.Fatalf("json.Marshal(DecryptResult): %v", err)
	}
	assertNoPEMHeaders(t, "DecryptResult", encoded)

	if !bytes.Equal(dec.Plaintext, plaintext) {
		t.Fatalf("wrong plaintext: want %q, got %q", plaintext, dec.Plaintext)
	}
}

func TestAdversarial_OpenBao_ListKeys_NoKeyMaterial(t *testing.T) {
	b := newIntegrationBackend(t)
	for _, alg := range []Algorithm{AlgorithmES256, AlgorithmEdDSA, AlgorithmAES256GCM} {
		kid := uniqueKeyID(t, fmt.Sprintf("adv-list-%s", alg))
		createKey(t, b, kid, alg)
	}

	metas, err := b.ListKeys(context.Background(), KeyScope{})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	for _, meta := range metas {
		encoded, err := json.Marshal(meta)
		if err != nil {
			t.Fatalf("json.Marshal(KeyMeta): %v", err)
		}
		assertNoPEMHeaders(t, fmt.Sprintf("KeyMeta[%s]", meta.KeyID), encoded)
	}
}

// ── 4. ADVERSARIAL — error messages contain no key material ──────────────────

func TestAdversarial_OpenBao_ErrorMessages_NoKeyMaterial(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "adv-err")
	createKey(t, b, keyID, AlgorithmES256)

	// Create an AES key to test sign-on-encryption-key error.
	aesKeyID := uniqueKeyID(t, "adv-err-aes")
	createKey(t, b, aesKeyID, AlgorithmAES256GCM)

	errorCases := []struct {
		name string
		fn   func() error
	}{
		{
			name: "Sign_KeyNotFound",
			fn: func() error {
				_, err := b.Sign(context.Background(), "does-not-exist-"+keyID, intTestHash("x"), AlgorithmES256)
				return err
			},
		},
		{
			name: "Sign_EmptyHash",
			fn: func() error {
				_, err := b.Sign(context.Background(), keyID, nil, AlgorithmES256)
				return err
			},
		},
		{
			name: "Sign_ShortHash",
			fn: func() error {
				_, err := b.Sign(context.Background(), keyID, []byte("tooshort"), AlgorithmES256)
				return err
			},
		},
		{
			name: "Encrypt_NilPlaintext",
			fn: func() error {
				_, err := b.Encrypt(context.Background(), keyID, nil)
				return err
			},
		},
		{
			name: "Decrypt_InvalidCiphertext",
			fn: func() error {
				_, err := b.Decrypt(context.Background(), aesKeyID, []byte("not-a-vault-ciphertext"))
				return err
			},
		},
		{
			name: "Decrypt_KeyNotFound",
			fn: func() error {
				// Need a valid vault: prefix ciphertext but wrong key.
				b2, _ := NewOpenBaoBackend(OpenBaoConfig{Address: globalEnv.addr, Token: globalEnv.token})
				enc, _ := b2.Encrypt(context.Background(), aesKeyID, []byte("test"))
				if enc == nil {
					return nil
				}
				_, err := b2.Decrypt(context.Background(), "no-such-key-"+keyID, enc.Ciphertext)
				return err
			},
		},
		{
			name: "RotateKey_NotFound",
			fn: func() error {
				_, err := b.RotateKey(context.Background(), "no-such-key-"+keyID)
				return err
			},
		},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				return
			}
			msg := err.Error()
			if strings.Contains(msg, "-----BEGIN") || strings.Contains(msg, "-----END") {
				t.Fatalf("ADVERSARIAL: error message contains PEM header: %q", msg)
			}
			// Error messages must not contain the vault: prefix ciphertext
			// (which could reveal encrypted data structure) beyond what's
			// needed for debugging.  We check that full base64 blobs are absent.
			if len(msg) > 4096 {
				t.Fatalf("ADVERSARIAL: error message unreasonably long (%d bytes) — may leak data",
					len(msg))
			}
		})
	}
}

// ── 4b. ADVERSARIAL — algorithm and key-type mismatch errors ────────────────

// TestOpenBao_Sign_AlgorithmMismatch verifies that Sign returns ErrAlgorithmMismatch
// when the requested algorithm does not match the key's actual algorithm.
// Previously this would silently return an ECDSA signature when EdDSA was requested,
// because Transit's EdDSA parameters (no prehashed/hash_algorithm) are a subset
// of ECDSA defaults.  The pre-fetch fix closes this silent mismatch.
func TestOpenBao_Sign_AlgorithmMismatch(t *testing.T) {
	b := newIntegrationBackend(t)
	// Create an ES256 (ecdsa-p256) key.
	keyID := uniqueKeyID(t, "alg-mismatch-es256")
	createKey(t, b, keyID, AlgorithmES256)

	// Attempt to sign with EdDSA — algorithm mismatch must be detected.
	_, err := b.Sign(context.Background(), keyID, intTestHash("mismatch"), AlgorithmEdDSA)
	if err == nil {
		t.Fatal("expected ErrAlgorithmMismatch for ES256 key with EdDSA request, got nil")
	}
	if !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("expected ErrAlgorithmMismatch, got: %v", err)
	}
}

// TestOpenBao_Sign_EncryptionKey_ReturnsKeyTypeMismatch verifies that Sign on
// an encryption key returns ErrKeyTypeMismatch.
func TestOpenBao_Sign_EncryptionKey_ReturnsKeyTypeMismatch(t *testing.T) {
	b := newIntegrationBackend(t)
	aesKeyID := uniqueKeyID(t, "sign-on-aes")
	createKey(t, b, aesKeyID, AlgorithmAES256GCM)

	_, err := b.Sign(context.Background(), aesKeyID, intTestHash("type-check"), AlgorithmES256)
	if err == nil {
		t.Fatal("expected ErrKeyTypeMismatch for Sign on encryption key, got nil")
	}
	if !errors.Is(err, ErrKeyTypeMismatch) {
		t.Fatalf("expected ErrKeyTypeMismatch, got: %v", err)
	}
}

// TestOpenBao_Encrypt_SigningKey_ReturnsKeyTypeMismatch verifies that Encrypt
// on a signing key returns ErrKeyTypeMismatch.
func TestOpenBao_Encrypt_SigningKey_ReturnsKeyTypeMismatch(t *testing.T) {
	b := newIntegrationBackend(t)
	esKeyID := uniqueKeyID(t, "enc-on-es256")
	createKey(t, b, esKeyID, AlgorithmES256)

	_, err := b.Encrypt(context.Background(), esKeyID, []byte("test plaintext"))
	if err == nil {
		t.Fatal("expected ErrKeyTypeMismatch for Encrypt on signing key, got nil")
	}
	if !errors.Is(err, ErrKeyTypeMismatch) {
		t.Fatalf("expected ErrKeyTypeMismatch, got: %v", err)
	}
}

// ── 5. Input validation ───────────────────────────────────────────────────────

func TestOpenBao_Sign_EmptyHash_ReturnsInvalidInput(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "val-hash")
	createKey(t, b, keyID, AlgorithmES256)

	_, err := b.Sign(context.Background(), keyID, nil, AlgorithmES256)
	if err == nil {
		t.Fatal("expected error for nil hash, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got: %v", err)
	}

	_, err = b.Sign(context.Background(), keyID, make([]byte, 31), AlgorithmES256)
	if err == nil {
		t.Fatal("expected error for 31-byte hash, got nil")
	}
}

func TestOpenBao_Sign_KeyNotFound_ReturnsSentinel(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "sign-notfound")
	_, err := b.Sign(context.Background(), keyID, intTestHash("x"), AlgorithmES256)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestOpenBao_Encrypt_NilPlaintext_ReturnsInvalidInput(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "val-enc-nil")
	createKey(t, b, keyID, AlgorithmAES256GCM)

	_, err := b.Encrypt(context.Background(), keyID, nil)
	if err == nil {
		t.Fatal("expected error for nil plaintext")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got: %v", err)
	}
}

func TestOpenBao_Encrypt_KeyNotFound_ReturnsSentinel(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "enc-notfound")
	_, err := b.Encrypt(context.Background(), keyID, []byte("data"))
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestOpenBao_Decrypt_InvalidCiphertext_ReturnsInvalidInput(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "val-dec-invalid")
	createKey(t, b, keyID, AlgorithmAES256GCM)

	// Ciphertext without vault: prefix — our guard catches this before Transit.
	_, err := b.Decrypt(context.Background(), keyID, []byte("not-vault-ciphertext"))
	if err == nil {
		t.Fatal("expected error for non-vault ciphertext")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got: %v", err)
	}
}

func TestOpenBao_Decrypt_EmptyCiphertext_ReturnsInvalidInput(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "val-dec-empty")
	createKey(t, b, keyID, AlgorithmAES256GCM)

	_, err := b.Decrypt(context.Background(), keyID, nil)
	if err == nil {
		t.Fatal("expected error for nil ciphertext")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got: %v", err)
	}
}

func TestOpenBao_RotateKey_NotFound_ReturnsSentinel(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "rotate-notfound")
	_, err := b.RotateKey(context.Background(), keyID)
	if err == nil {
		t.Fatal("expected ErrKeyNotFound")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestOpenBao_NewBackend_MissingAddress_ReturnsError(t *testing.T) {
	_, err := NewOpenBaoBackend(OpenBaoConfig{Token: "root"})
	if err == nil {
		t.Fatal("expected error for empty Address")
	}
}

func TestOpenBao_NewBackend_MissingToken_ReturnsError(t *testing.T) {
	_, err := NewOpenBaoBackend(OpenBaoConfig{Address: "http://127.0.0.1:8200"})
	if err == nil {
		t.Fatal("expected error for empty Token")
	}
}

// ── 6. Context cancellation ───────────────────────────────────────────────────

func TestOpenBao_Sign_CancelledContext(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "ctx-sign")
	createKey(t, b, keyID, AlgorithmES256)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.Sign(ctx, keyID, intTestHash("cancelled"), AlgorithmES256)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestOpenBao_Encrypt_CancelledContext(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "ctx-enc")
	createKey(t, b, keyID, AlgorithmAES256GCM)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.Encrypt(ctx, keyID, []byte("data"))
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestOpenBao_Decrypt_CancelledContext(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "ctx-dec")
	createKey(t, b, keyID, AlgorithmAES256GCM)

	// Encrypt with a live context first to get valid ciphertext.
	enc, err := b.Encrypt(context.Background(), keyID, []byte("cancel test"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = b.Decrypt(ctx, keyID, enc.Ciphertext)
	if err == nil {
		t.Fatal("expected error for cancelled context on Decrypt")
	}
}

func TestOpenBao_ListKeys_CancelledContext(t *testing.T) {
	b := newIntegrationBackend(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.ListKeys(ctx, KeyScope{})
	if err == nil {
		t.Fatal("expected error for cancelled context on ListKeys")
	}
}

func TestOpenBao_RotateKey_CancelledContext(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "ctx-rotate")
	createKey(t, b, keyID, AlgorithmES256)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.RotateKey(ctx, keyID)
	if err == nil {
		t.Fatal("expected error for cancelled context on RotateKey")
	}
}

// ── 7. Concurrency ───────────────────────────────────────────────────────────────────

func TestOpenBao_Concurrent_Sign(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "conc-sign")
	createKey(t, b, keyID, AlgorithmES256)

	hash := intTestHash("concurrent sign")
	const goroutines = 20
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := b.Sign(context.Background(), keyID, hash, AlgorithmES256)
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: Sign error: %v", i, err)
		}
	}
}

func TestOpenBao_Concurrent_EncryptDecrypt(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "conc-enc")
	createKey(t, b, keyID, AlgorithmAES256GCM)

	plaintext := []byte("concurrent encrypt/decrypt test")
	const goroutines = 20
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			enc, err := b.Encrypt(context.Background(), keyID, plaintext)
			if err != nil {
				errs[idx] = fmt.Errorf("Encrypt: %w", err)
				return
			}
			dec, err := b.Decrypt(context.Background(), keyID, enc.Ciphertext)
			if err != nil {
				errs[idx] = fmt.Errorf("Decrypt: %w", err)
				return
			}
			if !bytes.Equal(dec.Plaintext, plaintext) {
				errs[idx] = fmt.Errorf("plaintext mismatch")
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}

// ── 8. ListKeys / RotateKey metadata ─────────────────────────────────────────

func TestOpenBao_ListKeys_PrefixScope(t *testing.T) {
	b := newIntegrationBackend(t)

	prefix := uniqueKeyID(t, "list-prefix")
	keyA := prefix + "-payments-sign"
	keyB := prefix + "-payments-enc"
	keyC := prefix + "-infra-sign"

	createKey(t, b, keyA, AlgorithmES256)
	createKey(t, b, keyB, AlgorithmAES256GCM)
	createKey(t, b, keyC, AlgorithmES256)

	metas, err := b.ListKeys(context.Background(), KeyScope{Prefix: prefix + "-payments"})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	// Must find at least the two payments keys (there may be other keys from
	// other tests running in parallel).
	found := make(map[string]bool)
	for _, m := range metas {
		found[m.KeyID] = true
		if !strings.HasPrefix(m.KeyID, prefix+"-payments") {
			t.Errorf("key %q does not match prefix filter", m.KeyID)
		}
	}
	if !found[keyA] {
		t.Errorf("expected key %q in results", keyA)
	}
	if !found[keyB] {
		t.Errorf("expected key %q in results", keyB)
	}
	if found[keyC] {
		t.Errorf("key %q should have been excluded by prefix filter", keyC)
	}
}

func TestOpenBao_ListKeys_TeamIDScope(t *testing.T) {
	// TODO(#1): skip until 2026-09-01 — OpenBao 1.20.x Transit silently drops
	// custom_metadata in the key config endpoint ("Endpoint ignored these
	// unrecognised parameters: [custom_metadata]"). TeamID scope filtering
	// relies on custom_metadata["team_id"]; until the engine version supports
	// it, use a KV metadata sidecar or upgrade OpenBao.
	// TODO(#1): skip until 2027-01-01 — OpenBao Transit custom_metadata not supported in 1.20.x
	t.Skipf("OpenBao %s does not support Transit custom_metadata — TeamID scope filter not functional",
		globalEnv.version)

	b := newIntegrationBackend(t)

	// Vault Transit key names cannot contain forward slashes (they are URL path
	// separators).  The {teamID}/{keyName} convention used by the Backend interface
	// must be mapped to a flat Transit name externally.  For the scope filter test
	// we rely on custom_metadata["team_id"] which is set by CreateTransitKey.
	keyA := uniqueKeyID(t, "team-alpha-sign")
	keyB := uniqueKeyID(t, "team-beta-sign")

	if err := b.CreateTransitKey(context.Background(), keyA, AlgorithmES256, "team-alpha"); err != nil {
		t.Fatalf("CreateTransitKey teamA: %v", err)
	}
	t.Cleanup(func() { deleteTransitKey(globalEnv.addr, globalEnv.token, keyA) }) //nolint:errcheck

	if err := b.CreateTransitKey(context.Background(), keyB, AlgorithmES256, "team-beta"); err != nil {
		t.Fatalf("CreateTransitKey teamB: %v", err)
	}
	t.Cleanup(func() { deleteTransitKey(globalEnv.addr, globalEnv.token, keyB) }) //nolint:errcheck

	metas, err := b.ListKeys(context.Background(), KeyScope{TeamID: "team-alpha"})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	for _, m := range metas {
		if m.TeamID != "team-alpha" {
			t.Errorf("key %q has TeamID %q, expected team-alpha", m.KeyID, m.TeamID)
		}
	}

	found := false
	for _, m := range metas {
		if m.KeyID == keyA {
			found = true
		}
	}
	if !found {
		t.Errorf("expected key %q in team-alpha results", keyA)
	}
}

func TestOpenBao_RotateKey_MetadataCorrect(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "meta-rotate")
	createKey(t, b, keyID, AlgorithmEdDSA)

	meta1, err := b.RotateKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if meta1.Version != 2 {
		t.Fatalf("expected version 2, got %d", meta1.Version)
	}
	if meta1.RotatedAt == nil {
		t.Fatal("RotatedAt must not be nil after rotation")
	}
	if meta1.Algorithm != AlgorithmEdDSA {
		t.Fatalf("expected EdDSA, got %q", meta1.Algorithm)
	}
	if meta1.KeyID != keyID {
		t.Fatalf("KeyID mismatch: want %q, got %q", keyID, meta1.KeyID)
	}
}

func TestOpenBao_ListKeys_EmptyEngine_ReturnsNil(t *testing.T) {
	// Use a separate mount path that we control, ensuring it is empty.
	emptyMount := "transit-empty-test"
	if err := enableTransit(globalEnv.addr, globalEnv.token, emptyMount); err != nil {
		// Vault Enterprise or a specially configured OSS instance is required.
		// TODO(#1): skip until 2027-01-01 — replace with a dedicated integration environment.
		t.Skipf("cannot enable separate transit mount: %v", err)
	}
	t.Cleanup(func() {
		// Unmount after test.
		req, _ := http.NewRequest(http.MethodDelete,
			globalEnv.addr+"/v1/sys/mounts/"+emptyMount, nil)
		req.Header.Set("X-Vault-Token", globalEnv.token)
		http.DefaultClient.Do(req) //nolint:errcheck
	})

	b, err := NewOpenBaoBackend(OpenBaoConfig{
		Address:   globalEnv.addr,
		Token:     globalEnv.token,
		MountPath: emptyMount,
	})
	if err != nil {
		t.Fatalf("NewOpenBaoBackend: %v", err)
	}

	metas, err := b.ListKeys(context.Background(), KeyScope{})
	if err != nil {
		t.Fatalf("ListKeys on empty mount: %v", err)
	}
	if len(metas) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(metas))
	}
}

// ── 9. OpenBao-specific: CreateTransitKey flags ───────────────────────────────

// TestOpenBao_CreateTransitKey_Exportable_False verifies that keys created via
// CreateTransitKey have exportable=false, ensuring Transit never returns key
// material through the export endpoint.
func TestOpenBao_CreateTransitKey_Exportable_False(t *testing.T) {
	b := newIntegrationBackend(t)
	keyID := uniqueKeyID(t, "exportable-check")
	createKey(t, b, keyID, AlgorithmES256)

	// Attempt to export the key: Transit should reject with 403 because
	// the key was created with exportable=false.
	req, _ := http.NewRequest(http.MethodGet,
		globalEnv.addr+"/v1/transit/export/signing-key/"+keyID, nil)
	req.Header.Set("X-Vault-Token", globalEnv.token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("export request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusOK {
		t.Fatal("SECURITY: Transit export endpoint returned 200 — key is exportable, violating zero-key-exposure guarantee")
	}
	// 400 (key not exportable) or 403 is the expected response.
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusForbidden {
		t.Logf("export endpoint returned HTTP %d (expected 400 or 403)", resp.StatusCode)
	}
}

// TestOpenBao_CreateTransitKey_AllAlgorithms checks that all supported
// algorithms create successfully.
func TestOpenBao_CreateTransitKey_AllAlgorithms(t *testing.T) {
	b := newIntegrationBackend(t)
	algs := []Algorithm{AlgorithmES256, AlgorithmRS256, AlgorithmEdDSA, AlgorithmAES256GCM}

	for _, alg := range algs {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			keyID := uniqueKeyID(t, "create-"+string(alg))
			if err := b.CreateTransitKey(context.Background(), keyID, alg, "test-team"); err != nil {
				t.Fatalf("CreateTransitKey(%q): %v", alg, err)
			}
			t.Cleanup(func() {
				deleteTransitKey(globalEnv.addr, globalEnv.token, keyID) //nolint:errcheck
			})

			// Verify key exists and metadata is correct.
			meta, err := b.getKeyMeta(context.Background(), keyID)
			if err != nil {
				t.Fatalf("getKeyMeta: %v", err)
			}
			if meta.Algorithm != alg {
				t.Fatalf("expected algorithm %q, got %q", alg, meta.Algorithm)
			}
			if meta.Version != 1 {
				t.Fatalf("expected version 1 for new key, got %d", meta.Version)
			}
			if meta.RotatedAt != nil {
				t.Fatal("RotatedAt should be nil for a new key")
			}
		})
	}
}

// ── Helpers for public key extraction ────────────────────────────────────────

// getTransitPublicKeyPEM fetches the PEM-encoded public key for a specific
// key version from Transit.  Used in signature verification tests.
// This is the ONLY legitimate use of the Transit keys/ metadata endpoint
// that returns a public key; private keys are never involved.
func getTransitPublicKeyPEM(t *testing.T, addr, token, keyID string, version int) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/v1/transit/keys/%s", addr, keyID), nil)
	req.Header.Set("X-Vault-Token", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetch key metadata: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	var env struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode key metadata: %v", err)
	}
	key := env.Data.Keys[fmt.Sprintf("%d", version)]
	return key.PublicKey
}

func getECPublicKey(t *testing.T, b *OpenBaoBackend, keyID string, version int) *ecdsa.PublicKey {
	t.Helper()
	der := getTransitPublicKeyDER(t, b.cfg.Address, b.cfg.Token, keyID, version)
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey (EC): %v", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	return ec
}

func getRSAPublicKey(t *testing.T, b *OpenBaoBackend, keyID string, version int) *rsa.PublicKey {
	t.Helper()
	der := getTransitPublicKeyDER(t, b.cfg.Address, b.cfg.Token, keyID, version)
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey (RSA): %v", err)
	}
	rk, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
	return rk
}

func getEdPublicKey(t *testing.T, b *OpenBaoBackend, keyID string, version int) ed25519.PublicKey {
	t.Helper()
	// Vault Transit returns Ed25519 public keys as raw base64 (32 bytes), NOT PEM-wrapped.
	// ECDSA and RSA keys use PEM PKIX format; Ed25519 uses raw base64.
	pemOrB64 := getTransitPublicKeyPEM(t, b.cfg.Address, b.cfg.Token, keyID, version)

	// Try PEM path first (future Vault versions may wrap it).
	if block, _ := pem.Decode([]byte(pemOrB64)); block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("ParsePKIXPublicKey (Ed25519 via PEM): %v", err)
		}
		ek, ok := pub.(ed25519.PublicKey)
		if !ok {
			t.Fatalf("expected ed25519.PublicKey from PEM, got %T", pub)
		}
		return ek
	}

	// Raw base64 fallback (Vault 1.21 behavior).
	raw, err := base64.StdEncoding.DecodeString(pemOrB64)
	if err != nil {
		t.Fatalf("base64 decode Ed25519 public key: %v (raw=%q)", err, pemOrB64)
	}
	if len(raw) != ed25519.PublicKeySize {
		t.Fatalf("expected %d-byte Ed25519 public key, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw)
}

// getTransitPublicKeyDER fetches the DER-encoded public key for a specific
// key version from Transit and decodes the PEM wrapper.
func getTransitPublicKeyDER(t *testing.T, addr, token, keyID string, version int) []byte {
	t.Helper()
	pemStr := getTransitPublicKeyPEM(t, addr, token, keyID, version)
	if pemStr == "" {
		t.Fatalf("getTransitPublicKeyDER: empty PEM string for key %q v%d", keyID, version)
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("getTransitPublicKeyDER: PEM decode failed for key %q v%d (pem=%q)",
			keyID, version, pemStr)
	}
	return block.Bytes
}

// ── Assertion helpers ─────────────────────────────────────────────────────────

// assertNoPEMHeaders fails the test if data contains PEM header markers.
// Key material in PEM form is the canonical way it would leak into responses.
func assertNoPEMHeaders(t *testing.T, label string, data []byte) {
	t.Helper()
	if bytes.Contains(data, []byte("-----BEGIN")) || bytes.Contains(data, []byte("-----END")) {
		t.Fatalf("ADVERSARIAL: %s contains PEM headers — possible key material leak", label)
	}
}

// assertNoVaultPrefix fails if data contains a raw "vault:v" prefix string.
// Signatures returned by the Backend interface must have this prefix stripped.
func assertNoVaultPrefix(t *testing.T, label string, data []byte) {
	t.Helper()
	// In JSON the vault: prefix would appear as "vault:v (base64-encoded in Signature field).
	// The Signature field is []byte → base64 in JSON; not the raw vault: string.
	// We verify the raw JSON doesn't contain the literal "vault:v" as a string value.
	if bytes.Contains(data, []byte(`"vault:v`)) {
		t.Fatalf("ADVERSARIAL: %s JSON contains raw vault:v prefix — signature was not decoded", label)
	}
}
