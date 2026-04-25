package credentials

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenBaoKV implements KVReader and KVWriter against an OpenBao/Vault KV v2
// engine.
//
// It calls the Vault HTTP API directly using only the Go standard library —
// no external dependencies.
//
// Path conventions: callers pass logical paths of the form
// "{mount}/data/{key}" (e.g. "kv/data/secrets/svc/name").  The OpenBao KV v2
// API uses the same "data" sub-path for reads and writes, and the "metadata"
// sub-path for metadata operations (list, delete-all-versions).  This struct
// translates between the two as needed.
type OpenBaoKV struct {
	address    string
	token      string
	httpClient *http.Client
}

// NewOpenBaoKV constructs an OpenBaoKV reader.
// address is the OpenBao base URL (e.g. "http://openbao:8200").
// token is the Vault token with read access to the KV mount.
func NewOpenBaoKV(address, token string, tlsConfig *tls.Config) *OpenBaoKV {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &OpenBaoKV{
		address: strings.TrimRight(address, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
	}
}

// kvv2Response is the Vault KV v2 GET response envelope.
type kvv2Response struct {
	Data struct {
		Data map[string]string `json:"data"`
	} `json:"data"`
}

// kvv2ListResponse is the Vault KV v2 LIST response envelope.
type kvv2ListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

// GetSecret retrieves a KV v2 secret by its full API path.
// path must be the data path: "{mount}/data/{key}" (not "{mount}/{key}").
func (k *OpenBaoKV) GetSecret(ctx context.Context, path string) (map[string]string, error) {
	url := fmt.Sprintf("%s/v1/%s", k.address, strings.TrimPrefix(path, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("credentials: building KV request: %w", err)
	}
	// SECURITY: the token is passed in a header, not a query param or URL.
	req.Header.Set("X-Vault-Token", k.token)
	req.Header.Set("Accept", "application/json")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("credentials: KV request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("credentials: reading KV response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: path %q not found in KV", ErrCredentialNotFound, path)
	}
	if resp.StatusCode != http.StatusOK {
		// Do not include the response body — it may contain token info.
		return nil, fmt.Errorf("credentials: KV returned HTTP %d for path %q", resp.StatusCode, path)
	}

	var kv kvv2Response
	if err := json.Unmarshal(body, &kv); err != nil {
		return nil, fmt.Errorf("credentials: parsing KV response: %w", err)
	}
	if kv.Data.Data == nil {
		return nil, fmt.Errorf("%w: %q (KV data envelope is empty)", ErrCredentialNotFound, path)
	}
	return kv.Data.Data, nil
}

// ── KVWriter implementation ────────────────────────────────────────────────────

// SetSecret implements KVWriter.
//
// path must be the KV v2 data path: "{mount}/data/{key}"
// (e.g. "kv/data/secrets/svc/name").  The fields are written as the secret's
// "data" payload via POST /v1/{mount}/data/{key}.
//
// HTTP 4xx errors (except 404) are treated as permanent failures.
// HTTP 5xx errors are surfaced as transient failures.
func (k *OpenBaoKV) SetSecret(ctx context.Context, path string, fields map[string]string) error {
	url := fmt.Sprintf("%s/v1/%s", k.address, strings.TrimPrefix(path, "/"))

	payload := map[string]interface{}{
		"data": fields,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("credentials: marshalling KV write body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("credentials: building KV write request: %w", err)
	}
	req.Header.Set("X-Vault-Token", k.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("credentials: KV write request failed: %w", err)
	}
	defer resp.Body.Close()

	// Drain body to allow connection reuse; limit to avoid unbounded reads.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))

	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent:
		return nil
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		// SECURITY: do not include body — it may contain token details.
		return fmt.Errorf("credentials: KV write forbidden (HTTP %d) for path %q — check token policy", resp.StatusCode, path)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("credentials: KV write permanent error (HTTP %d) for path %q", resp.StatusCode, path)
	default:
		return fmt.Errorf("credentials: KV write transient error (HTTP %d) for path %q", resp.StatusCode, path)
	}
}

// DeleteSecret implements KVWriter.
//
// path must be the KV v2 data path: "{mount}/data/{key}".
// This issues DELETE against the metadata sub-path
// ("{mount}/metadata/{key}"), which removes all versions of the secret
// (a permanent, unrecoverable delete in KV v2 terminology).
//
// This matches the semantics of the dev and encrypted backends: a delete
// operation completely removes the secret and cannot be undone by the caller.
func (k *OpenBaoKV) DeleteSecret(ctx context.Context, path string) error {
	// Translate "{mount}/data/{key}" → "{mount}/metadata/{key}".
	metaPath, err := dataPathToMetaPath(path)
	if err != nil {
		return fmt.Errorf("credentials: DeleteSecret: %w", err)
	}

	url := fmt.Sprintf("%s/v1/%s", k.address, strings.TrimPrefix(metaPath, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("credentials: building KV delete request: %w", err)
	}
	req.Header.Set("X-Vault-Token", k.token)

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("credentials: KV delete request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))

	switch {
	case resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		// Already absent — treat as success (idempotent delete).
		return nil
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("credentials: KV delete forbidden (HTTP %d) for path %q — check token policy", resp.StatusCode, path)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("credentials: KV delete permanent error (HTTP %d) for path %q", resp.StatusCode, path)
	default:
		return fmt.Errorf("credentials: KV delete transient error (HTTP %d) for path %q", resp.StatusCode, path)
	}
}

// ListPaths implements KVWriter.
//
// Returns all secret paths (full "{mount}/data/{key}" forms) stored under the
// KV mount.  Internally, it issues a LIST against the metadata sub-path of the
// mount root (e.g. "kv/metadata/") and translates the returned keys back to
// data paths.
//
// A 404 response (no secrets yet) is treated as an empty list, not an error.
func (k *OpenBaoKV) ListPaths(ctx context.Context) ([]string, error) {
	// The list is issued against "kv/metadata/" to enumerate all top-level keys.
	// The caller's paths all live under {mount}/data/ so we list {mount}/metadata/.
	// We use a fixed root for the LIST and then prefix-match on the returned keys
	// to reconstruct the full data paths.
	//
	// OpenBao KV v2: LIST /v1/{mount}/metadata/ returns all keys recursively
	// (non-recursive by default — OpenBao returns immediate children only and
	// uses a trailing "/" to indicate directories).  We flatten all returned
	// paths, skipping directory markers (paths ending in "/").

	// We need to issue multiple LIST calls if there are nested directories.
	// For the v0.1 use-case the depth is bounded, but we recurse defensively.
	var allPaths []string
	if err := k.listRecursive(ctx, "kv/metadata/", &allPaths); err != nil {
		return nil, err
	}
	return allPaths, nil
}

// listRecursive performs a recursive LIST starting from metaPrefix (a
// "{mount}/metadata/{prefix}" path with trailing slash).
func (k *OpenBaoKV) listRecursive(ctx context.Context, metaPrefix string, out *[]string) error {
	url := fmt.Sprintf("%s/v1/%s", k.address, strings.TrimPrefix(metaPrefix, "/"))

	req, err := http.NewRequestWithContext(ctx, "LIST", url, nil)
	if err != nil {
		return fmt.Errorf("credentials: building KV list request: %w", err)
	}
	req.Header.Set("X-Vault-Token", k.token)
	req.Header.Set("Accept", "application/json")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("credentials: KV list request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("credentials: reading KV list response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		// No secrets at this prefix — empty list is fine.
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("credentials: KV list returned HTTP %d for prefix %q", resp.StatusCode, metaPrefix)
	}

	var listResp kvv2ListResponse
	if err := json.Unmarshal(body, &listResp); err != nil {
		return fmt.Errorf("credentials: parsing KV list response: %w", err)
	}

	for _, key := range listResp.Data.Keys {
		// Strip the metaPrefix prefix to get the relative key.
		// metaPrefix has form "{mount}/metadata/{relative-prefix}/".
		// key is relative to that prefix.
		fullMetaPath := metaPrefix + key

		if strings.HasSuffix(key, "/") {
			// Directory — recurse.
			if err := k.listRecursive(ctx, fullMetaPath, out); err != nil {
				return err
			}
			continue
		}

		// Translate "{mount}/metadata/{key}" → "{mount}/data/{key}".
		dataPath, err := metaPathToDataPath(fullMetaPath)
		if err != nil {
			// Skip paths we can't translate (shouldn't happen with our layout).
			continue
		}
		*out = append(*out, dataPath)
	}
	return nil
}

// ── Path translation helpers ───────────────────────────────────────────────────

// dataPathToMetaPath translates a KV v2 data path to its metadata counterpart.
//
// "{mount}/data/{key}" → "{mount}/metadata/{key}"
//
// Example: "kv/data/secrets/svc/name" → "kv/metadata/secrets/svc/name"
//
// Fail-fast assertions:
//   - empty path → error
//   - path does not contain "/data/" → error
//   - path is the prefix with nothing after it (e.g. "kv/data/") → error
func dataPathToMetaPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("credentials: dataPathToMetaPath: path must not be empty")
	}
	const dataInfix = "/data/"
	idx := strings.Index(path, dataInfix)
	if idx < 0 {
		return "", fmt.Errorf("credentials: dataPathToMetaPath: path %q does not contain %q — expected {mount}/data/{key} form", path, dataInfix)
	}
	key := path[idx+len(dataInfix):]
	if key == "" {
		return "", fmt.Errorf("credentials: dataPathToMetaPath: path %q has nothing after %q — expected {mount}/data/{key} form", path, dataInfix)
	}
	return path[:idx] + "/metadata/" + key, nil
}

// metaPathToDataPath is the inverse of dataPathToMetaPath.
//
// "{mount}/metadata/{key}" → "{mount}/data/{key}"
//
// Fail-fast assertions:
//   - empty path → error
//   - path does not contain "/metadata/" → error
//   - path is the prefix with nothing after it (e.g. "kv/metadata/") → error
func metaPathToDataPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("credentials: metaPathToDataPath: path must not be empty")
	}
	const metaInfix = "/metadata/"
	idx := strings.Index(path, metaInfix)
	if idx < 0 {
		return "", fmt.Errorf("credentials: metaPathToDataPath: path %q does not contain %q — expected {mount}/metadata/{key} form", path, metaInfix)
	}
	key := path[idx+len(metaInfix):]
	if key == "" {
		return "", fmt.Errorf("credentials: metaPathToDataPath: path %q has nothing after %q — expected {mount}/metadata/{key} form", path, metaInfix)
	}
	return path[:idx] + "/data/" + key, nil
}
