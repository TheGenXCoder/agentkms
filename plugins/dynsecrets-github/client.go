// Package github implements the Dynamic Secrets plugin for GitHub App
// ephemeral installation access tokens (Kind="github-pat").
package github

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// githubBaseURL is the GitHub REST API base. Tests override this per-client.
const githubBaseURL = "https://api.github.com"

// tokenExpiryBuffer is how far before expiry we treat a cached token as stale.
const tokenExpiryBuffer = 5 * time.Minute

// installationTokenResponse is the JSON shape returned by
// POST /app/installations/{id}/access_tokens.
type installationTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AppInfo is a snapshot of a registered App's metadata.
type AppInfo struct {
	Name           string
	AppID          int64
	InstallationID int64
}

// githubAppClient holds per-App state and handles JWT signing, token minting,
// token caching, and suspension for a single GitHub App.
type githubAppClient struct {
	mu             sync.Mutex
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey

	// token cache
	cachedToken    string
	tokenExpiresAt time.Time

	// rate-limit state (informational; updated after each API response)
	rateLimitRemaining int
	rateLimitResetAt   time.Time

	// httpClient is the HTTP client to use.  Overridable in tests.
	httpClient *http.Client

	// baseURL is the GitHub API base URL.  Overridable in tests.
	baseURL string

	// nowFunc returns the current time.  Overridable in tests.
	nowFunc func() time.Time
}

// newGitHubAppClient creates a client for a single GitHub App.
func newGitHubAppClient(appID, installationID int64, key *rsa.PrivateKey) *githubAppClient {
	return &githubAppClient{
		appID:          appID,
		installationID: installationID,
		privateKey:     key,
		httpClient:     &http.Client{Timeout: 15 * time.Second},
		baseURL:        githubBaseURL,
		nowFunc:        func() time.Time { return time.Now().UTC() },
	}
}

// signJWT builds and signs a GitHub App JWT valid for up to 10 minutes.
func (c *githubAppClient) signJWT() (string, error) {
	now := c.nowFunc()
	claims := jwt.MapClaims{
		"iss": fmt.Sprintf("%d", c.appID),
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(c.privateKey)
	if err != nil {
		return "", fmt.Errorf("github client: JWT signing failed for app %d: %w", c.appID, err)
	}
	return signed, nil
}

// MintToken returns a valid installation access token, using the cache when
// the cached token is not within tokenExpiryBuffer of its expiry.
func (c *githubAppClient) MintToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.nowFunc()
	if c.cachedToken != "" && now.Before(c.tokenExpiresAt.Add(-tokenExpiryBuffer)) {
		return c.cachedToken, nil
	}

	signed, err := c.signJWT()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.baseURL, c.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("github client: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github client: [transient] HTTP error minting token for installation %d: %w", c.installationID, err)
	}
	defer resp.Body.Close()

	c.updateRateLimit(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("github client: [transient] reading response body: %w", err)
	}

	if err := c.checkResponseError(resp, body); err != nil {
		return "", err
	}

	var tokenResp installationTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("github client: [transient] parsing token response: %w", err)
	}
	if tokenResp.Token == "" {
		return "", fmt.Errorf("github client: [permanent] empty token in response")
	}

	c.cachedToken = tokenResp.Token
	c.tokenExpiresAt = tokenResp.ExpiresAt.UTC()
	return c.cachedToken, nil
}

// Suspend calls PUT /app/installations/{id}/suspended.
func (c *githubAppClient) Suspend(ctx context.Context) error {
	return c.suspendOp(ctx, http.MethodPut)
}

// Unsuspend calls DELETE /app/installations/{id}/suspended.
func (c *githubAppClient) Unsuspend(ctx context.Context) error {
	return c.suspendOp(ctx, http.MethodDelete)
}

func (c *githubAppClient) suspendOp(ctx context.Context, method string) error {
	signed, err := c.signJWT()
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/app/installations/%d/suspended", c.baseURL, c.installationID)
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return fmt.Errorf("github client: build suspend request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("github client: [transient] HTTP error during suspension op: %w", err)
	}
	defer resp.Body.Close()

	c.updateRateLimit(resp)

	body, _ := io.ReadAll(resp.Body)
	return c.checkResponseError(resp, body)
}

// updateRateLimit stores rate-limit state from response headers.
func (c *githubAppClient) updateRateLimit(resp *http.Response) {
	// We intentionally tolerate parse failures — rate-limit tracking is
	// best-effort and should never cause a vend to fail.
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	reset := resp.Header.Get("X-RateLimit-Reset")

	if remaining != "" {
		var r int
		if _, err := fmt.Sscanf(remaining, "%d", &r); err == nil {
			c.rateLimitRemaining = r
		}
	}
	if reset != "" {
		var epoch int64
		if _, err := fmt.Sscanf(reset, "%d", &epoch); err == nil {
			c.rateLimitResetAt = time.Unix(epoch, 0).UTC()
		}
	}
}

// checkResponseError returns a typed error based on the HTTP response.
// 204 No Content (suspension ops) is treated as success.
func (c *githubAppClient) checkResponseError(resp *http.Response, body []byte) error {
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent {
		return nil
	}

	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 200 {
		snippet = snippet[:200]
	}

	// Rate limit exhausted — transient.
	if resp.StatusCode == http.StatusForbidden && c.rateLimitRemaining == 0 {
		retryAfter := time.Until(c.rateLimitResetAt).Round(time.Second)
		return fmt.Errorf("github client: [transient] rate limit exhausted for installation %d; retry after %v: %s",
			c.installationID, retryAfter, snippet)
	}

	// Auth failures — permanent.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("github client: [permanent] auth error %d for installation %d: %s",
			resp.StatusCode, c.installationID, snippet)
	}

	// Server errors — transient.
	if resp.StatusCode >= 500 {
		return fmt.Errorf("github client: [transient] server error %d for installation %d: %s",
			resp.StatusCode, c.installationID, snippet)
	}

	// Everything else — permanent (bad request, not found, etc.).
	return fmt.Errorf("github client: [permanent] unexpected status %d for installation %d: %s",
		resp.StatusCode, c.installationID, snippet)
}
