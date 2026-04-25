package ghsecret

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/agentkms/agentkms/internal/destination"
)

const (
	ghSecretKind    = "github-secret"
	validateTimeout = 10 * time.Second
	healthTimeout   = 5 * time.Second
)

// Ensure Deliverer implements DestinationDeliverer at compile time.
var _ destination.DestinationDeliverer = (*Deliverer)(nil)

// Deliverer delivers credential values to GitHub Actions repository secrets.
//
// # Concurrency
//
// Deliverer is safe for concurrent use. The generation regression guard and the
// idempotent delivery cache are protected by an internal mutex. The pubkeyCache
// has its own mutex. The http.Client is safe for concurrent use.
//
// # Encryption
//
// GitHub Actions secrets use libsodium sealed boxes (Curve25519 +
// XSalsa20-Poly1305). See encrypt.go / docs/specs/2026-04-26-T4-gh-secret-design.md.
//
// # Authentication
//
// params["writer_token"] must be a GitHub PAT or installation token with
// secrets:write on the target repository. Passed as Bearer token per request.
// The token is per-Deliver (stateless); it is not cached between calls.
type Deliverer struct {
	// baseURL is the GitHub API base URL. Overridable in tests.
	baseURL string

	// httpClient is shared for all HTTP requests. Override in tests.
	httpClient *http.Client

	// pkCache is the public key cache, shared across Deliver calls for the same
	// (owner, repo).
	pkCache *pubkeyCache

	// mu protects lastGen and deliveryCache.
	mu sync.Mutex

	// lastGen tracks the last successfully delivered generation per target_id,
	// enforcing the GENERATION_REGRESSION contract.
	lastGen map[string]uint64

	// deliveryCache maps delivery_id → (isPermanent, err string) for
	// idempotent in-flight retry detection. In-memory only; not durable across
	// subprocess restarts (acceptable per spec OQ-6).
	deliveryCache map[string]deliveryResult
}

// deliveryResult is the cached outcome of a completed Deliver call.
type deliveryResult struct {
	isPermanent bool
	errMsg      string // empty = success
}

// NewDeliverer creates a new GitHub Secret Deliverer ready for use.
//
//   - baseURL: GitHub API base URL. Pass empty string or githubBaseURL for
//     production. Override with an httptest server URL in tests.
//   - hc: HTTP client. Pass nil to use a default client with 15s timeout.
func NewDeliverer(baseURL string, hc *http.Client) *Deliverer {
	if baseURL == "" {
		baseURL = githubBaseURL
	}
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &Deliverer{
		baseURL:       baseURL,
		httpClient:    hc,
		pkCache:       newPubkeyCache(),
		lastGen:       make(map[string]uint64),
		deliveryCache: make(map[string]deliveryResult),
	}
}

// Kind returns the destination kind discriminator.
func (d *Deliverer) Kind() string { return ghSecretKind }

// Capabilities returns the feature tokens this deliverer supports.
func (d *Deliverer) Capabilities() []string { return []string{"health", "revoke"} }

// Validate performs a pre-flight connectivity and permission check.
//
// Checks:
//  1. params["writer_token"] is present and non-empty.
//  2. The GitHub API is reachable (GET /user with a short timeout).
//
// Does not write any secret material.
func (d *Deliverer) Validate(ctx context.Context, params map[string]any) error {
	p, err := parseParams(params)
	if err != nil {
		return err // already tagged [permanent]
	}

	vCtx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()

	client := newGHClient(d.baseURL, p.writerToken, d.httpClient)

	// Probe the GitHub API. GET /user verifies the token is valid.
	url := client.baseURL + "/user"
	req, err := http.NewRequestWithContext(vCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("ghsecret: Validate: build request: %w", err)
	}
	client.setHeaders(req)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ghsecret: [transient] Validate: cannot reach GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("ghsecret: [permanent] Validate: token rejected by GitHub API (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ghsecret: [transient] Validate: unexpected GitHub API status %d", resp.StatusCode)
	}
	return nil
}

// Deliver writes the credential value to the GitHub Actions secret identified
// by req.TargetID.
//
// # Idempotency
//
// Multiple calls with the same DeliveryID return the same result without
// re-contacting the GitHub API (in-memory cache). Multiple calls with the same
// Generation but a different DeliveryID re-execute the PUT unconditionally
// (full overwrite semantics).
//
// # Generation regression
//
// Returns (true, GENERATION_REGRESSION) if req.Generation < last successfully
// delivered generation for this TargetID.
//
// # Error classification
//
//   - GH 404: permanent TARGET_NOT_FOUND
//   - GH 401/403: permanent PERMISSION_DENIED
//   - GH 5xx / timeout: transient
//   - GH 422 (stale key): plugin re-fetches pubkey and retries once → transient
//     if the retry also fails
//   - GH 429 rate-limit: transient
func (d *Deliverer) Deliver(ctx context.Context, req destination.DeliverRequest) (bool, error) {
	if req.Generation == 0 {
		return true, fmt.Errorf("ghsecret: [permanent] generation 0 is invalid")
	}

	// --- Idempotent delivery cache check ---
	if req.DeliveryID != "" {
		d.mu.Lock()
		if cached, ok := d.deliveryCache[req.DeliveryID]; ok {
			d.mu.Unlock()
			if cached.errMsg == "" {
				return false, nil
			}
			return cached.isPermanent, fmt.Errorf("%s", cached.errMsg)
		}
		d.mu.Unlock()
	}

	// --- Generation regression check ---
	d.mu.Lock()
	if last, ok := d.lastGen[req.TargetID]; ok && req.Generation < last {
		d.mu.Unlock()
		return true, fmt.Errorf(
			"ghsecret: [permanent] GENERATION_REGRESSION: got %d, last delivered %d for target %q: %w",
			req.Generation, last, req.TargetID, ErrGenerationRegression,
		)
	}
	d.mu.Unlock()

	// --- Parse target_id ---
	owner, repo, secretName, err := parseTargetID(req.TargetID)
	if err != nil {
		return d.cacheAndReturn(req.DeliveryID, true, err)
	}

	// --- Parse params ---
	p, err := parseParams(req.Params)
	if err != nil {
		return d.cacheAndReturn(req.DeliveryID, true, err)
	}

	client := newGHClient(d.baseURL, p.writerToken, d.httpClient)

	// --- Fetch/cache public key, encrypt, PUT ---
	isPerm, err := d.deliverWithRetry(ctx, client, owner, repo, secretName, req.CredentialValue)
	if err != nil {
		return d.cacheAndReturn(req.DeliveryID, isPerm, err)
	}

	// --- Update last-gen on success ---
	d.mu.Lock()
	d.lastGen[req.TargetID] = req.Generation
	d.mu.Unlock()

	return d.cacheAndReturn(req.DeliveryID, false, nil)
}

// deliverWithRetry fetches the public key (from cache or API), encrypts, and
// PUTs the secret. On 422 (stale key) it invalidates the cache and retries once.
func (d *Deliverer) deliverWithRetry(
	ctx context.Context,
	client *ghClient,
	owner, repo, secretName string,
	plaintext []byte,
) (isPermanent bool, err error) {
	keyID, base64Key, err := d.fetchKey(ctx, client, owner, repo)
	if err != nil {
		return IsPermanent(err), err
	}

	encryptedB64, err := SealBase64(plaintext, base64Key)
	if err != nil {
		return true, fmt.Errorf("ghsecret: [permanent] encrypt: %w", err)
	}

	putErr := client.PutSecret(ctx, owner, repo, secretName, encryptedB64, keyID)
	if putErr == nil {
		return false, nil
	}

	// On 422 (stale key_id), invalidate cache and retry once.
	if ghErr, ok := putErr.(*ghError); ok && ghErr.status == 422 {
		d.pkCache.Invalidate(owner, repo)

		keyID, base64Key, err = d.fetchKey(ctx, client, owner, repo)
		if err != nil {
			return IsPermanent(err), err
		}
		encryptedB64, err = SealBase64(plaintext, base64Key)
		if err != nil {
			return true, fmt.Errorf("ghsecret: [permanent] encrypt (retry): %w", err)
		}
		putErr = client.PutSecret(ctx, owner, repo, secretName, encryptedB64, keyID)
		if putErr == nil {
			return false, nil
		}
	}

	return IsPermanent(putErr), putErr
}

// fetchKey returns the (keyID, base64Key) for (owner, repo), using the cache
// when available, fetching from GitHub when not.
func (d *Deliverer) fetchKey(ctx context.Context, client *ghClient, owner, repo string) (keyID, base64Key string, err error) {
	if kid, b64k, ok := d.pkCache.Get(owner, repo); ok {
		return kid, b64k, nil
	}
	kid, b64k, err := client.FetchPublicKey(ctx, owner, repo)
	if err != nil {
		return "", "", err
	}
	d.pkCache.Set(owner, repo, kid, b64k)
	return kid, b64k, nil
}

// cacheAndReturn stores the delivery result in the idempotent cache (if
// DeliveryID is non-empty) and returns the values to the caller.
func (d *Deliverer) cacheAndReturn(deliveryID string, isPermanent bool, err error) (bool, error) {
	if deliveryID != "" {
		result := deliveryResult{isPermanent: isPermanent}
		if err != nil {
			result.errMsg = err.Error()
		}
		d.mu.Lock()
		d.deliveryCache[deliveryID] = result
		d.mu.Unlock()
	}
	return isPermanent, err
}

// Revoke removes the named secret from the target repository.
//
// Idempotent: 404 from GitHub (secret already absent) is treated as success.
//
// Returns (false, nil) on success. Returns (true, err) for permanent errors.
func (d *Deliverer) Revoke(ctx context.Context, targetID string, _ uint64, params map[string]any) (bool, error) {
	owner, repo, secretName, err := parseTargetID(targetID)
	if err != nil {
		return true, err
	}

	p, err := parseParams(params)
	if err != nil {
		return true, err
	}

	client := newGHClient(d.baseURL, p.writerToken, d.httpClient)

	delErr := client.DeleteSecret(ctx, owner, repo, secretName)
	if delErr == nil {
		return false, nil
	}
	return IsPermanent(delErr), delErr
}

// Health verifies that the GitHub API is reachable.
//
// Uses GET /zen which is lightweight and unauthenticated. Must complete within
// 5 seconds.
func (d *Deliverer) Health(ctx context.Context) error {
	hCtx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()

	// Use a minimal client with no token (GET /zen is public).
	client := newGHClient(d.baseURL, "", d.httpClient)
	_, err := client.Ping(hCtx)
	return err
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// parseTargetID parses a GitHub secret target_id of the form "owner/repo:SECRET_NAME".
//
// Returns permanent errors for any invalid format.
func parseTargetID(targetID string) (owner, repo, secretName string, err error) {
	// Split on the last colon.
	colonIdx := strings.LastIndex(targetID, ":")
	if colonIdx < 0 {
		return "", "", "", fmt.Errorf("ghsecret: [permanent] invalid target_id %q: missing colon separator (expected \"owner/repo:SECRET_NAME\")", targetID)
	}

	repoPath := targetID[:colonIdx]
	secretName = targetID[colonIdx+1:]

	if repoPath == "" {
		return "", "", "", fmt.Errorf("ghsecret: [permanent] invalid target_id %q: empty repo path", targetID)
	}
	if secretName == "" {
		return "", "", "", fmt.Errorf("ghsecret: [permanent] invalid target_id %q: empty secret name", targetID)
	}

	slashIdx := strings.Index(repoPath, "/")
	if slashIdx < 0 {
		return "", "", "", fmt.Errorf("ghsecret: [permanent] invalid target_id %q: repo path %q has no slash (expected \"owner/repo\")", targetID, repoPath)
	}

	owner = repoPath[:slashIdx]
	repo = repoPath[slashIdx+1:]

	if owner == "" {
		return "", "", "", fmt.Errorf("ghsecret: [permanent] invalid target_id %q: empty owner", targetID)
	}
	if repo == "" {
		return "", "", "", fmt.Errorf("ghsecret: [permanent] invalid target_id %q: empty repo name", targetID)
	}

	return owner, repo, secretName, nil
}
