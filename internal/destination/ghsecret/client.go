package ghsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// githubBaseURL is the GitHub REST API base. Tests override this per-client.
	githubBaseURL = "https://api.github.com"

	// ghAPIVersion is the GitHub API version header value required as of 2022.
	ghAPIVersion = "2022-11-28"
)

// publicKeyResponse is the JSON shape returned by
// GET /repos/{owner}/{repo}/actions/secrets/public-key
type publicKeyResponse struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"` // base64-encoded Curve25519 public key
}

// ghClient wraps the GitHub REST API for secret delivery operations.
// It holds a writer token and an http.Client; the base URL is overridable
// for httptest-based testing.
//
// ghClient is intentionally not safe for concurrent use on its own; thread
// safety is managed by the pubkeyCache (which holds the mutex) and the
// deliverer (which constructs a new client per-call or reuses one safely
// because http.Client is safe for concurrent use).
type ghClient struct {
	baseURL     string
	writerToken string
	httpClient  *http.Client
}

// newGHClient creates a new GitHub API client.
//
//   - baseURL: the GitHub API base URL (use githubBaseURL for production;
//     override with an httptest.Server URL in tests).
//   - writerToken: PAT or installation access token with secrets:write.
//   - hc: the HTTP client to use. Pass nil to use a sensible default.
func newGHClient(baseURL, writerToken string, hc *http.Client) *ghClient {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &ghClient{
		baseURL:     strings.TrimRight(baseURL, "/"),
		writerToken: writerToken,
		httpClient:  hc,
	}
}

// FetchPublicKey retrieves the Actions secrets encryption public key for the
// given repository. Returns the key ID and the base64-encoded Curve25519 key.
//
// Error classification:
//   - 404: permanent TARGET_NOT_FOUND
//   - 401/403: permanent PERMISSION_DENIED
//   - 5xx / network: transient
func (c *ghClient) FetchPublicKey(ctx context.Context, owner, repo string) (keyID, base64Key string, err error) {
	url := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/public-key", c.baseURL, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", fmt.Errorf("ghsecret: build public-key request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("ghsecret: [transient] FetchPublicKey HTTP error: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("ghsecret: [transient] FetchPublicKey reading body: %w", err)
	}

	if err := c.checkError(resp, body, "FetchPublicKey"); err != nil {
		return "", "", err
	}

	var pk publicKeyResponse
	if err := json.Unmarshal(body, &pk); err != nil {
		return "", "", fmt.Errorf("ghsecret: [transient] FetchPublicKey parse: %w", err)
	}
	if pk.KeyID == "" || pk.Key == "" {
		return "", "", fmt.Errorf("ghsecret: [transient] FetchPublicKey: incomplete response (key_id=%q, key=%q)", pk.KeyID, pk.Key)
	}

	return pk.KeyID, pk.Key, nil
}

// putSecretBody is the JSON body sent to PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}.
type putSecretBody struct {
	EncryptedValue string `json:"encrypted_value"`
	KeyID          string `json:"key_id"`
}

// PutSecret writes an encrypted secret value to the given repository. The
// encrypted value must be a base64-encoded sealed-box ciphertext. keyID must
// match the key used for encryption (from FetchPublicKey).
//
// Error classification:
//   - 404: permanent TARGET_NOT_FOUND
//   - 401/403: permanent PERMISSION_DENIED
//   - 422: transient (stale key_id; caller should re-fetch and retry)
//   - 429: transient (rate limited)
//   - 5xx / network: transient
func (c *ghClient) PutSecret(ctx context.Context, owner, repo, name, encryptedBase64, keyID string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/%s", c.baseURL, owner, repo, name)

	bodyData := putSecretBody{
		EncryptedValue: encryptedBase64,
		KeyID:          keyID,
	}
	bodyBytes, err := json.Marshal(bodyData)
	if err != nil {
		return fmt.Errorf("ghsecret: [permanent] PutSecret marshal body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("ghsecret: build PutSecret request: %w", err)
	}
	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ghsecret: [transient] PutSecret HTTP error: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("ghsecret: [transient] PutSecret reading body: %w", err)
	}

	return c.checkError(resp, body, "PutSecret")
}

// DeleteSecret removes the named secret from the repository.
// Returns nil on 404 (already absent — idempotent revoke contract).
//
// Error classification:
//   - 404: success (already absent)
//   - 401/403: permanent PERMISSION_DENIED
//   - 5xx / network: transient
func (c *ghClient) DeleteSecret(ctx context.Context, owner, repo, name string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/%s", c.baseURL, owner, repo, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("ghsecret: build DeleteSecret request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ghsecret: [transient] DeleteSecret HTTP error: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// 404 on delete = already absent; treat as success (idempotent revoke).
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}

	return c.checkError(resp, body, "DeleteSecret")
}

// Ping performs a lightweight liveness check against the GitHub API.
// Uses GET /zen which returns a short aphorism string.
func (c *ghClient) Ping(ctx context.Context) (latencyMS int64, err error) {
	url := c.baseURL + "/zen"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("ghsecret: build Ping request: %w", err)
	}
	c.setHeaders(req)

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	latencyMS = time.Since(start).Milliseconds()
	if err != nil {
		return 0, fmt.Errorf("ghsecret: [transient] Ping HTTP error: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck // discard health response body

	if resp.StatusCode != http.StatusOK {
		return latencyMS, fmt.Errorf("ghsecret: [transient] Ping: unexpected status %d", resp.StatusCode)
	}
	return latencyMS, nil
}

// setHeaders sets the standard GitHub API request headers.
func (c *ghClient) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.writerToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", ghAPIVersion)
}

// checkError maps HTTP status codes to classified errors.
// op is used in error messages for context.
func (c *ghClient) checkError(resp *http.Response, body []byte, op string) error {
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return nil
	}

	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 200 {
		snippet = snippet[:200]
	}

	switch resp.StatusCode {
	case http.StatusNotFound:
		return &ghError{op: op, status: resp.StatusCode, body: snippet, permanent: true, code: errCodeTargetNotFound}
	case http.StatusUnauthorized, http.StatusForbidden:
		return &ghError{op: op, status: resp.StatusCode, body: snippet, permanent: true, code: errCodePermissionDenied}
	case http.StatusUnprocessableEntity:
		// 422 usually means stale key_id; caller should re-fetch and retry → transient.
		return &ghError{op: op, status: resp.StatusCode, body: snippet, permanent: false, code: errCodeTransient}
	case http.StatusTooManyRequests:
		return &ghError{op: op, status: resp.StatusCode, body: snippet, permanent: false, code: errCodeTransient}
	}
	if resp.StatusCode >= 500 {
		return &ghError{op: op, status: resp.StatusCode, body: snippet, permanent: false, code: errCodeTransient}
	}
	// 400, 409, etc. — treat as permanent (misconfiguration).
	return &ghError{op: op, status: resp.StatusCode, body: snippet, permanent: true, code: errCodePermanent}
}

// ── Error type ────────────────────────────────────────────────────────────────

type errCodeType int

const (
	errCodePermanent       errCodeType = iota
	errCodeTransient       errCodeType = iota
	errCodeTargetNotFound  errCodeType = iota
	errCodePermissionDenied errCodeType = iota
)

// ghError is a classified GitHub API error.
//
// It implements Unwrap() to return the package-level sentinel error that
// corresponds to its error code, enabling errors.Is classification by callers
// (including the subprocess binary) without requiring them to type-assert the
// unexported *ghError type.
type ghError struct {
	op        string
	status    int
	body      string
	permanent bool
	code      errCodeType
}

func (e *ghError) Error() string {
	permanence := "transient"
	if e.permanent {
		permanence = "permanent"
	}
	return fmt.Sprintf("ghsecret: [%s] %s: HTTP %d: %s", permanence, e.op, e.status, e.body)
}

// Unwrap returns the sentinel error corresponding to this error's code, so
// that errors.Is(err, ghsecret.ErrTargetNotFound) etc. work correctly when
// the *ghError is wrapped further (e.g. with fmt.Errorf("...: %w", ghErr)).
func (e *ghError) Unwrap() error {
	switch e.code {
	case errCodeTargetNotFound:
		return ErrTargetNotFound
	case errCodePermissionDenied:
		return ErrPermissionDenied
	case errCodeTransient:
		return ErrTransient
	default:
		return ErrPermanent
	}
}

// IsTargetNotFound returns true if this error represents a 404 from the GitHub API.
//
// Deprecated: prefer errors.Is(err, ErrTargetNotFound) which works correctly
// through error wrapping chains.
func IsTargetNotFound(err error) bool {
	return errors.Is(err, ErrTargetNotFound)
}

// IsPermissionDenied returns true if this error represents a 401/403 from the GitHub API.
//
// Deprecated: prefer errors.Is(err, ErrPermissionDenied) which works correctly
// through error wrapping chains.
func IsPermissionDenied(err error) bool {
	return errors.Is(err, ErrPermissionDenied)
}

// IsPermanent returns true if this error represents a permanent failure
// (no retry will help).
func IsPermanent(err error) bool {
	if e, ok := err.(*ghError); ok {
		return e.permanent
	}
	// Fall back to sentinel check: ErrTargetNotFound and ErrPermissionDenied
	// are both permanent; ErrTransient is not.
	if errors.Is(err, ErrTargetNotFound) || errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrPermanent) {
		return true
	}
	return false
}
