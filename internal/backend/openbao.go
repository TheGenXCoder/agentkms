// Package backend — OpenBao / Vault Transit backend implementation.
//
// B-01: Implements the Backend interface against the OpenBao (or HashiCorp
// Vault) Transit secrets engine.  The Transit engine holds all key material;
// AgentKMS never receives raw key bytes from any Transit API response.
//
// Dependency rationale: This file uses only the Go standard library
// (net/http, encoding/json, encoding/base64, etc.).  No external HTTP client
// or Vault SDK is imported.  The Transit HTTP API is simple enough that a
// thin bespoke client is safer than adding a large SDK to the supply chain.
//
// Authentication: Vault Token (X-Vault-Token header).  AppRole and Kubernetes
// auth are planned for T2 and configured outside this package.
//
// SECURITY INVARIANTS (same as the Backend interface contract):
//   - No method returns, logs, or stores key material.
//   - Transit API responses that contain key material (e.g. export-key, which
//     is a separate, disabled endpoint) are NEVER called by this backend.
//   - Error messages contain only key IDs and HTTP status codes, never
//     key bytes or decrypted payloads.
//   - The "exportable" and "allow_plaintext_backup" flags are always false
//     when this backend creates keys via CreateTransitKey.
package backend

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ── Configuration ─────────────────────────────────────────────────────────────

// OpenBaoConfig holds all configuration required to connect to an OpenBao or
// HashiCorp Vault instance.
type OpenBaoConfig struct {
	// Address is the base URL of the OpenBao/Vault server.
	// Example: "http://127.0.0.1:8200" (dev) or "https://vault.internal:8200" (prod).
	// Required.
	Address string

	// Token is the Vault token used to authenticate all requests.
	// The token must have a policy granting transit/* capabilities on MountPath.
	// For production deployments prefer AppRole or Kubernetes auth; this token
	// is for bootstrapping and integration tests.
	// Required.
	Token string

	// MountPath is the path at which the Transit secrets engine is mounted.
	// Defaults to "transit" if empty.
	MountPath string

	// Namespace is the Vault Enterprise namespace.
	// Leave empty for OpenBao or HashiCorp Vault OSS.
	Namespace string

	// HTTPClient overrides the default http.Client used for all requests.
	// Inject a client configured with mTLS for production deployments.
	// If nil, http.DefaultClient is used (suitable for dev/test only).
	HTTPClient *http.Client
}

// mountPath returns the normalised mount path (no leading/trailing slashes).
func (c *OpenBaoConfig) mountPath() string {
	mp := c.MountPath
	if mp == "" {
		mp = "transit"
	}
	return strings.Trim(mp, "/")
}

// ── Backend struct ────────────────────────────────────────────────────────────

// OpenBaoBackend implements Backend against the OpenBao/Vault Transit secrets
// engine.  All cryptographic operations are delegated to Transit; this struct
// holds no key material.
//
// Concurrency: all exported methods are safe for concurrent use.
type OpenBaoBackend struct {
	cfg    OpenBaoConfig
	client *http.Client
	mount  string // normalised mount path
}

// NewOpenBaoBackend constructs and validates an OpenBaoBackend from cfg.
// It does NOT verify connectivity — use a Ping or Sign-list call to do that.
func NewOpenBaoBackend(cfg OpenBaoConfig) (*OpenBaoBackend, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("openbao: Address must not be empty")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("openbao: Token must not be empty")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	return &OpenBaoBackend{
		cfg:    cfg,
		client: client,
		mount:  cfg.mountPath(),
	}, nil
}

// ── Backend interface implementation ──────────────────────────────────────────

// Sign computes a signature over payloadHash using the Transit key identified
// by keyID.  payloadHash must be exactly 32 bytes (SHA-256).
//
// Transit algorithm → AgentKMS algorithm mapping:
//
//	ecdsa-p256 → ES256   (prehashed=true, hash_algorithm=sha2-256)
//	rsa-2048   → RS256   (prehashed=true, hash_algorithm=sha2-256, signature_algorithm=pkcs1v15)
//	ed25519    → EdDSA   (prehashed not supported; input treated as message by Transit)
//
// The Ed25519 / prehashed note:
// Vault/OpenBao Transit does not accept prehashed=true for ed25519 keys.
// We send payloadHash as the message directly.  Because Go's ed25519.Sign and
// Transit both apply SHA-512 to the message internally, signatures produced
// here verify correctly with ed25519.Verify(pubKey, payloadHash, sig).
func (b *OpenBaoBackend) Sign(ctx context.Context, keyID string, payloadHash []byte, alg Algorithm) (*SignResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(payloadHash) != 32 {
		return nil, fmt.Errorf("%w: payloadHash must be exactly 32 bytes (SHA-256), got %d",
			ErrInvalidInput, len(payloadHash))
	}
	if keyID == "" {
		return nil, fmt.Errorf("%w: keyID must not be empty", ErrInvalidInput)
	}

	// Validate algorithm is a signing algorithm before calling Transit.
	if !alg.IsSigningAlgorithm() {
		return nil, fmt.Errorf("%w: algorithm %q is not a signing algorithm", ErrKeyTypeMismatch, alg)
	}

	// Pre-fetch key metadata to verify the key exists and its algorithm matches
	// the requested alg.  This mirrors the pre-check in Encrypt() and satisfies
	// the interface contract: "Returns ErrAlgorithmMismatch if alg does not
	// match the key's algorithm."
	//
	// Without this check, Transit would silently produce a signature with the
	// key's actual algorithm (e.g. ECDSA) when the caller requested a different
	// algorithm (e.g. EdDSA), because Transit parameters for EdDSA (no
	// prehashed, no hash_algorithm) are a subset of the ECDSA defaults.
	meta, err := b.getKeyMeta(ctx, keyID)
	if err != nil {
		return nil, err // already wrapped as ErrKeyNotFound if missing
	}
	if !meta.Algorithm.IsSigningAlgorithm() {
		return nil, fmt.Errorf("%w: key %q has algorithm %q (encryption key), cannot sign",
			ErrKeyTypeMismatch, keyID, meta.Algorithm)
	}
	if meta.Algorithm != alg {
		return nil, fmt.Errorf("%w: key %q uses %q, caller requested %q",
			ErrAlgorithmMismatch, keyID, meta.Algorithm, alg)
	}

	req := transitSignRequest{
		Input: base64.StdEncoding.EncodeToString(payloadHash),
	}
	switch alg {
	case AlgorithmES256:
		req.Prehashed = true
		req.HashAlgorithm = "sha2-256"
	case AlgorithmRS256:
		req.Prehashed = true
		req.HashAlgorithm = "sha2-256"
		req.SignatureAlgorithm = "pkcs1v15"
	case AlgorithmEdDSA:
		// prehashed is not supported for ed25519 in Transit; omit it.
		// payloadHash is sent as the message.
	}

	path := fmt.Sprintf("%s/sign/%s", b.mount, keyID)
	var data transitSignData
	if err := b.doJSON(ctx, http.MethodPost, path, &req, &data); err != nil {
		return nil, mapTransitError(err, keyID)
	}

	// Validate the Transit algorithm matches what was requested, using the
	// key_version to gate a metadata fetch if needed.
	sigBytes, err := decodeVaultSignature(data.Signature)
	if err != nil {
		// Do not include raw signature bytes in this error.
		return nil, fmt.Errorf("openbao: Sign(%q): malformed signature response: %w", keyID, err)
	}

	return &SignResult{
		Signature:  sigBytes,
		KeyVersion: data.KeyVersion,
	}, nil
}

// Encrypt encrypts plaintext using the Transit key identified by keyID.
// The returned ciphertext is an opaque blob containing the Transit ciphertext
// string (format: "vault:vN:base64") encoded as UTF-8 bytes.  Callers MUST
// pass it unmodified to Decrypt.
//
// Pre-check note: Vault Transit's encrypt endpoint auto-creates a key when
// called with a privileged token if the key does not exist, which would
// violate the ErrKeyNotFound contract.  We perform an explicit existence check
// before issuing the encrypt request.
func (b *OpenBaoBackend) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if plaintext == nil {
		return nil, fmt.Errorf("%w: plaintext must not be nil", ErrInvalidInput)
	}
	if keyID == "" {
		return nil, fmt.Errorf("%w: keyID must not be empty", ErrInvalidInput)
	}

	// Verify the key exists and is an encryption key before calling Transit.
	meta, err := b.getKeyMeta(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if !meta.Algorithm.IsEncryptionAlgorithm() {
		return nil, fmt.Errorf("%w: key %q has algorithm %q (signing key), cannot encrypt",
			ErrKeyTypeMismatch, keyID, meta.Algorithm)
	}

	req := transitEncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}

	path := fmt.Sprintf("%s/encrypt/%s", b.mount, keyID)
	var data transitEncryptData
	if err := b.doJSON(ctx, http.MethodPost, path, &req, &data); err != nil {
		return nil, mapTransitError(err, keyID)
	}

	if data.Ciphertext == "" {
		return nil, fmt.Errorf("openbao: Encrypt(%q): empty ciphertext in response", keyID)
	}

	return &EncryptResult{
		// Store the Transit ciphertext string as UTF-8 bytes.
		// Decrypt will convert it back to a string.
		Ciphertext: []byte(data.Ciphertext),
		KeyVersion: data.KeyVersion,
	}, nil
}

// Decrypt decrypts ciphertext produced by Encrypt.  ciphertext must be the
// opaque blob returned by Encrypt (the Transit ciphertext string as bytes).
func (b *OpenBaoBackend) Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*DecryptResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("%w: ciphertext must not be empty", ErrInvalidInput)
	}
	if keyID == "" {
		return nil, fmt.Errorf("%w: keyID must not be empty", ErrInvalidInput)
	}

	// The ciphertext is the Transit ciphertext string stored as bytes.
	ctStr := string(ciphertext)
	if !strings.HasPrefix(ctStr, "vault:") {
		return nil, fmt.Errorf("%w: ciphertext does not have expected vault: prefix — "+
			"was this produced by OpenBaoBackend.Encrypt?", ErrInvalidInput)
	}

	req := transitDecryptRequest{
		Ciphertext: ctStr,
	}

	path := fmt.Sprintf("%s/decrypt/%s", b.mount, keyID)
	var data transitDecryptData
	if err := b.doJSON(ctx, http.MethodPost, path, &req, &data); err != nil {
		return nil, mapTransitError(err, keyID)
	}

	plaintext, err := base64.StdEncoding.DecodeString(data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("openbao: Decrypt(%q): base64 decode plaintext: %w", keyID, err)
	}

	return &DecryptResult{Plaintext: plaintext}, nil
}

// ListKeys returns metadata for all Transit keys whose names match scope.
// It issues a LIST request to get key names, then fetches each key's metadata
// individually.  No key material is included in any response.
//
// Prefix filtering is applied to the key name string.
// TeamID filtering checks the key's custom_metadata["team_id"] field first;
// if absent, falls back to treating the first path segment of the key name
// as the team ID (e.g. "payments/signing-key" → team "payments").
func (b *OpenBaoBackend) ListKeys(ctx context.Context, scope KeyScope) ([]*KeyMeta, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// LIST /v1/{mount}/keys — returns key names.
	path := fmt.Sprintf("%s/keys", b.mount)
	var listData transitListData
	if err := b.doJSON(ctx, "LIST", path, nil, &listData); err != nil {
		// A 404 here means no keys exist yet (empty engine), not an error.
		var vErr *vaultAPIError
		if asVaultError(err, &vErr) && vErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("openbao: ListKeys: %w", err)
	}

	var result []*KeyMeta
	for _, name := range listData.Keys {
		// Apply prefix scope filter early to avoid unnecessary metadata fetches.
		if scope.Prefix != "" && !strings.HasPrefix(name, scope.Prefix) {
			continue
		}

		meta, err := b.getKeyMeta(ctx, name)
		if err != nil {
			// Key deleted between the LIST and this GET: skip rather than fail.
			// In a system with concurrent key rotation/deletion this is normal
			// and expected; propagating ErrKeyNotFound here would make ListKeys
			// non-atomic in an unreliable way.
			if errors.Is(err, ErrKeyNotFound) {
				continue
			}
			return nil, fmt.Errorf("openbao: ListKeys: get metadata for key %q: %w", name, err)
		}

		// Apply TeamID scope filter.
		if scope.TeamID != "" && meta.TeamID != scope.TeamID {
			continue
		}

		result = append(result, meta)
	}

	return result, nil
}

// RotateKey creates a new key version in Transit for the given key, making it
// the active version for all subsequent Sign and Encrypt operations.  Historical
// versions are retained for decryption and signature verification.
//
// Pre-check note: Vault Transit's rotate endpoint auto-creates a key when called
// with a root token if the key does not exist, bypassing the expected
// ErrKeyNotFound behaviour.  We therefore perform an explicit existence check
// before issuing the rotate request to guarantee the correct sentinel is returned.
func (b *OpenBaoBackend) RotateKey(ctx context.Context, keyID string) (*KeyMeta, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if keyID == "" {
		return nil, fmt.Errorf("%w: keyID must not be empty", ErrInvalidInput)
	}

	// Verify the key exists before rotating to prevent auto-creation.
	if _, err := b.getKeyMeta(ctx, keyID); err != nil {
		return nil, err // already a mapped sentinel error
	}

	path := fmt.Sprintf("%s/keys/%s/rotate", b.mount, keyID)
	// The rotate endpoint returns an empty body on success (HTTP 204).
	if err := b.doJSON(ctx, http.MethodPost, path, nil, nil); err != nil {
		return nil, mapTransitError(err, keyID)
	}

	// Fetch the updated key metadata to return the new version.
	meta, err := b.getKeyMeta(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("openbao: RotateKey(%q): fetch metadata after rotation: %w", keyID, err)
	}
	return meta, nil
}

// ── Admin helper (not part of Backend interface) ───────────────────────────────

// CreateTransitKey creates a new key in the Transit secrets engine.
// This is an admin/setup operation not part of the Backend interface.
// Used by integration tests and the agentkms-dev setup tooling.
//
// The key is created with:
//   - exportable = false (key material never leaves Transit)
//   - allow_plaintext_backup = false
//   - custom_metadata["team_id"] = teamID (if teamID != ""), set via /config
//
// Note: Vault 1.21 Transit ignores custom_metadata in the create request
// body ("Endpoint ignored these unrecognized parameters: [custom_metadata]").
// We set it in a separate POST /{mount}/keys/{name}/config call instead.
func (b *OpenBaoBackend) CreateTransitKey(ctx context.Context, keyID string, alg Algorithm, teamID string) error {
	if keyID == "" {
		return fmt.Errorf("%w: keyID must not be empty", ErrInvalidInput)
	}

	keyType, err := algorithmToTransitType(alg)
	if err != nil {
		return fmt.Errorf("openbao: CreateTransitKey(%q): %w", keyID, err)
	}

	// Step 1: create the key.
	req := transitCreateKeyRequest{
		Type:                 keyType,
		Exportable:           false,
		AllowPlaintextBackup: false,
	}
	path := fmt.Sprintf("%s/keys/%s", b.mount, keyID)
	if err := b.doJSON(ctx, http.MethodPost, path, &req, nil); err != nil {
		return fmt.Errorf("openbao: CreateTransitKey(%q): %w", keyID, err)
	}

	// Step 2: if a teamID is provided, set custom_metadata via the config
	// endpoint (the create endpoint ignores custom_metadata in Vault 1.21+).
	if teamID != "" {
		configPath := fmt.Sprintf("%s/keys/%s/config", b.mount, keyID)
		configReq := map[string]interface{}{
			"custom_metadata": map[string]string{"team_id": teamID},
		}
		if err := b.doJSON(ctx, http.MethodPost, configPath, &configReq, nil); err != nil {
			return fmt.Errorf("openbao: CreateTransitKey(%q): set custom_metadata: %w", keyID, err)
		}
	}
	return nil
}

// ── Internal HTTP helpers ──────────────────────────────────────────────────────

// doJSON executes an authenticated request against the Vault HTTP API.
//
// method: HTTP method ("GET", "POST", "LIST", etc.)
// path:   path relative to /v1/ (e.g. "transit/sign/my-key")
// reqBody: JSON-serialisable request body, or nil for no body
// respData: pointer to a struct that will receive data.* from the response,
//           or nil if the response body is ignored (e.g. rotate returns 204)
//
// Returns a *vaultAPIError if the server returns an HTTP error status or a
// Vault error payload.  Callers must NOT include request body contents in
// error messages they surface.
func (b *OpenBaoBackend) doJSON(ctx context.Context, method, path string, reqBody, respData any) error {
	url := strings.TrimRight(b.cfg.Address, "/") + "/v1/" + path

	var bodyReader io.Reader
	if reqBody != nil {
		enc, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("openbao: marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(enc)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("openbao: build request: %w", err)
	}

	req.Header.Set("X-Vault-Token", b.cfg.Token)
	if b.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", b.cfg.Namespace)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("openbao: HTTP %s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort

	// Read limited body to guard against oversized responses.
	const maxBody = 1 << 20 // 1 MiB
	limitedBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("openbao: read response body: %w", err)
	}

	// 200 and 204 are success.  Parse data field if respData is set.
	if resp.StatusCode == http.StatusOK {
		if respData == nil {
			return nil
		}
		// Response envelope: {"data": {...}, "errors": [...], ...}
		var envelope vaultEnvelope
		if err := json.Unmarshal(limitedBody, &envelope); err != nil {
			return fmt.Errorf("openbao: unmarshal response envelope: %w", err)
		}
		if len(envelope.Errors) > 0 {
			return &vaultAPIError{
				StatusCode: resp.StatusCode,
				Messages:   envelope.Errors,
			}
		}
		if envelope.Data != nil {
			if err := json.Unmarshal(envelope.Data, respData); err != nil {
				return fmt.Errorf("openbao: unmarshal response data: %w", err)
			}
		}
		return nil
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	// Error response: extract Vault error messages.
	var errEnv vaultEnvelope
	if json.Unmarshal(limitedBody, &errEnv) == nil && len(errEnv.Errors) > 0 {
		return &vaultAPIError{
			StatusCode: resp.StatusCode,
			Messages:   errEnv.Errors,
		}
	}
	return &vaultAPIError{
		StatusCode: resp.StatusCode,
		Messages:   []string{fmt.Sprintf("HTTP %d", resp.StatusCode)},
	}
}

// getKeyMeta fetches and returns metadata for a single Transit key.
// No key material is included in the response from Transit.
func (b *OpenBaoBackend) getKeyMeta(ctx context.Context, keyID string) (*KeyMeta, error) {
	path := fmt.Sprintf("%s/keys/%s", b.mount, keyID)
	var data transitKeyData
	if err := b.doJSON(ctx, http.MethodGet, path, nil, &data); err != nil {
		return nil, mapTransitError(err, keyID)
	}
	return transitKeyDataToMeta(keyID, &data)
}

// ── Response type mapping ──────────────────────────────────────────────────────

// transitKeyDataToMeta converts a Transit key metadata response into a KeyMeta.
// No key material fields exist in transitKeyData; this function cannot leak.
func transitKeyDataToMeta(keyID string, d *transitKeyData) (*KeyMeta, error) {
	alg, err := transitTypeToAlgorithm(d.Type)
	if err != nil {
		return nil, fmt.Errorf("openbao: unsupported key type %q for key %q: %w", d.Type, keyID, err)
	}

	meta := &KeyMeta{
		KeyID:     keyID,
		Algorithm: alg,
		Version:   d.LatestVersion,
	}

	// Extract TeamID from custom_metadata first; fall back to key name prefix.
	if tid, ok := d.CustomMetadata["team_id"]; ok && tid != "" {
		meta.TeamID = tid
	} else if idx := strings.Index(keyID, "/"); idx > 0 {
		meta.TeamID = keyID[:idx]
	}

	// Determine CreatedAt from version 1's creation time.
	if v1Raw, ok := d.Keys["1"]; ok {
		v1, err := decodeTransitKeyVersion(v1Raw)
		if err == nil {
			meta.CreatedAt = v1.CreationTime
		}
	}

	// Determine RotatedAt from the latest version's creation time (if > 1).
	if d.LatestVersion > 1 {
		latestKey := strconv.Itoa(d.LatestVersion)
		if vLatestRaw, ok := d.Keys[latestKey]; ok {
			vLatest, err := decodeTransitKeyVersion(vLatestRaw)
			if err == nil {
				t := vLatest.CreationTime
				meta.RotatedAt = &t
			}
		}
	}

	return meta, nil
}

// ── Error handling ─────────────────────────────────────────────────────────────

// mapTransitError translates a vaultAPIError to the appropriate Backend
// sentinel error.  Non-vaultAPIError values are returned unchanged.
// Key material is NEVER included in error messages.
func mapTransitError(err error, keyID string) error {
	var vErr *vaultAPIError
	if !asVaultError(err, &vErr) {
		return err
	}

	switch vErr.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("%w: %q", ErrKeyNotFound, keyID)

	case http.StatusBadRequest:
		// Vault returns 400 for algorithm mismatches, invalid inputs, AND for
		// some "key not found" cases (e.g. sign/encrypt on a missing key).
		// Classify based on the error message content.
		msg := strings.ToLower(strings.Join(vErr.Messages, " "))
		switch {
		case strings.Contains(msg, "key not found") ||
			strings.Contains(msg, "signing key not found") ||
			strings.Contains(msg, "encryption key not found"):
			return fmt.Errorf("%w: %q", ErrKeyNotFound, keyID)
		case strings.Contains(msg, "algorithm") ||
			strings.Contains(msg, "key type") ||
			(strings.Contains(msg, "not supported") && strings.Contains(msg, "sign")):
			return fmt.Errorf("%w: key %q: %s", ErrAlgorithmMismatch, keyID, vErr.safeMessage())
		default:
			return fmt.Errorf("%w: key %q: %s", ErrInvalidInput, keyID, vErr.safeMessage())
		}

	case http.StatusUnprocessableEntity:
		// 422 from Transit typically means wrong key type for operation.
		return fmt.Errorf("%w: key %q: %s", ErrKeyTypeMismatch, keyID, vErr.safeMessage())

	default:
		return fmt.Errorf("openbao: operation on key %q failed (HTTP %d): %s",
			keyID, vErr.StatusCode, vErr.safeMessage())
	}
}

// ── Algorithm / key-type conversions ──────────────────────────────────────────

// transitTypeToAlgorithm maps a Vault Transit key type string to an Algorithm.
func transitTypeToAlgorithm(keyType string) (Algorithm, error) {
	switch keyType {
	case "ecdsa-p256":
		return AlgorithmES256, nil
	case "rsa-2048":
		return AlgorithmRS256, nil
	case "ed25519":
		return AlgorithmEdDSA, nil
	case "aes256-gcm96":
		return AlgorithmAES256GCM, nil
	default:
		return "", fmt.Errorf("unsupported transit key type %q", keyType)
	}
}

// algorithmToTransitType maps an Algorithm to the Vault Transit key type string.
//
// Note on AlgorithmRSAOAEPSHA256: Vault Transit uses the same "rsa-2048" key
// type for both RS256 signing and RSA-OAEP encryption, distinguishing them
// only by the endpoint called (sign vs encrypt).  OpenBaoBackend always maps
// "rsa-2048" keys to AlgorithmRS256 (the signing algorithm) in
// transitTypeToAlgorithm, which means Encrypt()'s pre-check will reject an
// rsa-2048 key with ErrKeyTypeMismatch.  AlgorithmRSAOAEPSHA256 is therefore
// not usable through this backend.  Use AlgorithmAES256GCM for symmetric
// encryption, or target an AWS KMS / Azure Key Vault backend for RSA-OAEP.
func algorithmToTransitType(alg Algorithm) (string, error) {
	switch alg {
	case AlgorithmES256:
		return "ecdsa-p256", nil
	case AlgorithmRS256:
		return "rsa-2048", nil
	case AlgorithmEdDSA:
		return "ed25519", nil
	case AlgorithmAES256GCM:
		return "aes256-gcm96", nil
	default:
		return "", fmt.Errorf("%w: unsupported algorithm %q for transit backend", ErrInvalidInput, alg)
	}
}

// ── Signature parsing ──────────────────────────────────────────────────────────

// decodeVaultSignature decodes a Transit signature string of the form
// "vault:vN:base64encodedSignature" into the raw signature bytes.
//
// The key version embedded in the prefix is cross-checked in the caller
// against the explicit key_version field from the response.
//
// SECURITY: this function never returns the original signature string in
// error messages — only structural information (prefix, length).
func decodeVaultSignature(sig string) ([]byte, error) {
	const prefix = "vault:v"
	if !strings.HasPrefix(sig, prefix) {
		return nil, fmt.Errorf("unexpected signature prefix (len=%d)", len(sig))
	}

	rest := sig[len(prefix):] // "N:base64..."
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil, fmt.Errorf("malformed vault signature: missing colon after version")
	}
	b64 := rest[colonIdx+1:]

	sigBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Try URL-safe base64 (some vault versions use this).
		sigBytes, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed (len=%d)", len(b64))
		}
	}
	return sigBytes, nil
}

// ── Vault API error type ───────────────────────────────────────────────────────

// vaultAPIError is returned when the Vault HTTP API responds with an error
// status.  It carries the HTTP status code and Vault error messages.
type vaultAPIError struct {
	StatusCode int
	Messages   []string
}

func (e *vaultAPIError) Error() string {
	return fmt.Sprintf("vault API error (HTTP %d): %s", e.StatusCode, e.safeMessage())
}

// safeMessage returns a joined, sanitised error string from Vault's error
// messages.  These are controlled by the Vault server, not by key material,
// so they are safe to include in error messages.
func (e *vaultAPIError) safeMessage() string {
	return strings.Join(e.Messages, "; ")
}

// asVaultError sets *target to the first *vaultAPIError in err's chain,
// returning true.  Uses errors.As so it works even when the *vaultAPIError
// is wrapped with fmt.Errorf("%w", ...).
func asVaultError(err error, target **vaultAPIError) bool {
	if err == nil {
		return false
	}
	return errors.As(err, target)
}

// ── Vault API request / response structs ──────────────────────────────────────

// vaultEnvelope is the top-level JSON envelope returned by all Vault API
// responses.  The Data field is the operation-specific payload.
type vaultEnvelope struct {
	Data     json.RawMessage `json:"data"`
	Errors   []string        `json:"errors"`
	Warnings []string        `json:"warnings"`
}

// transitSignRequest is the body sent to POST /v1/{mount}/sign/{key}.
type transitSignRequest struct {
	Input              string `json:"input"`                          // base64-encoded payload hash
	Prehashed          bool   `json:"prehashed,omitempty"`             // true for ES256, RS256
	HashAlgorithm      string `json:"hash_algorithm,omitempty"`        // "sha2-256" for ES256/RS256
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`   // "pkcs1v15" for RS256
}

// transitSignData is the data field in the POST /v1/{mount}/sign/{key} response.
type transitSignData struct {
	Signature  string `json:"signature"`   // "vault:vN:base64..."
	KeyVersion int    `json:"key_version"`
}

// transitEncryptRequest is the body sent to POST /v1/{mount}/encrypt/{key}.
type transitEncryptRequest struct {
	Plaintext string `json:"plaintext"` // base64-encoded plaintext
}

// transitEncryptData is the data field in the POST /v1/{mount}/encrypt/{key} response.
type transitEncryptData struct {
	Ciphertext string `json:"ciphertext"` // "vault:vN:base64..."
	KeyVersion int    `json:"key_version"`
}

// transitDecryptRequest is the body sent to POST /v1/{mount}/decrypt/{key}.
type transitDecryptRequest struct {
	Ciphertext string `json:"ciphertext"` // "vault:vN:base64..."
}

// transitDecryptData is the data field in the POST /v1/{mount}/decrypt/{key} response.
type transitDecryptData struct {
	Plaintext string `json:"plaintext"` // base64-encoded plaintext
}

// transitListData is the data field in the LIST /v1/{mount}/keys response.
type transitListData struct {
	Keys []string `json:"keys"`
}

// transitKeyData is the data field in the GET /v1/{mount}/keys/{name} response.
// No field in this struct can hold key material; the Transit API never
// returns key material in this endpoint (exportable=false enforced in CreateTransitKey).
type transitKeyData struct {
	Name           string                       `json:"name"`
	Type           string                       `json:"type"`           // "ecdsa-p256", "rsa-2048", etc.
	LatestVersion  int                          `json:"latest_version"`
	Keys           map[string]json.RawMessage   `json:"keys"`           // version number → version metadata (polymorphic)
	CustomMetadata map[string]string            `json:"custom_metadata"`
}

// transitKeyVersion holds per-version metadata for a Transit key.
// No key material: public keys are included in Transit responses for asymmetric
// keys, but are not surfaced in KeyMeta (they are not needed by AgentKMS).
//
// Vault returns two different JSON shapes depending on the key type:
//   - Asymmetric keys: {"creation_time": "...", "public_key": "..."}
//   - Symmetric keys: a Unix timestamp integer (e.g. 1704067200)
//
// We use json.RawMessage at the caller side and parse with
// decodeTransitKeyVersion to handle both.
type transitKeyVersion struct {
	CreationTime time.Time
	// Public key omitted deliberately — KeyMeta has no public key field.
	// AgentKMS callers verify signatures using keys obtained out-of-band.
}

// decodeTransitKeyVersion parses a raw JSON value from the Transit keys map.
// Vault returns either:
//   - an object: {"creation_time": "2024-01-01T00:00:00Z", ...}
//   - an integer: Unix timestamp in seconds (for symmetric/AES keys)
func decodeTransitKeyVersion(raw json.RawMessage) (transitKeyVersion, error) {
	// Try object form first (asymmetric keys).
	var obj struct {
		CreationTime time.Time `json:"creation_time"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return transitKeyVersion{CreationTime: obj.CreationTime}, nil
	}

	// Fall back to integer Unix timestamp (symmetric/AES keys).
	var ts json.Number
	if err := json.Unmarshal(raw, &ts); err != nil {
		// Do not include raw in the error: for asymmetric keys it contains a
		// public_key PEM blob that is unnecessarily verbose in error messages.
		return transitKeyVersion{}, fmt.Errorf("parse key version: unexpected JSON type (len=%d): %w", len(raw), err)
	}
	secs, err := ts.Float64()
	if err != nil {
		return transitKeyVersion{}, fmt.Errorf("parse key version timestamp: %w", err)
	}
	// Guard against extreme values that would produce nonsensical timestamps
	// (negative, or past year 9999).  A legitimate Transit timestamp is a
	// Unix second count in the range [0, ~32503680000] (year 3000 ceiling).
	const (
		minUnixSec = 0           // 1970-01-01
		maxUnixSec = 32503680000 // year ~3001
	)
	if secs < minUnixSec || secs > maxUnixSec {
		return transitKeyVersion{}, fmt.Errorf(
			"parse key version: timestamp %e is out of acceptable range [%d, %d]",
			secs, int64(minUnixSec), int64(maxUnixSec))
	}
	wholeSecs := int64(math.Trunc(secs))
	return transitKeyVersion{
		CreationTime: time.Unix(wholeSecs, 0).UTC(),
	}, nil
}

// transitCreateKeyRequest is the body sent to POST /v1/{mount}/keys/{name}.
type transitCreateKeyRequest struct {
	Type                 string            `json:"type"`
	Exportable           bool              `json:"exportable"`            // always false
	AllowPlaintextBackup bool              `json:"allow_plaintext_backup"` // always false
	CustomMetadata       map[string]string `json:"custom_metadata,omitempty"`
}
