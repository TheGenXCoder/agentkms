# T2 Multi-App GitHub Plugin Design
**Date:** 2026-04-25
**Track:** T2 — dynsecrets-github multi-App support
**Status:** Approved for implementation

---

## 1. Current Single-App Model

The `github` dynsecrets plugin (`internal/dynsecrets/github/plugin.go`) today holds a single set of GitHub App credentials as struct fields: `appID int64`, `installationID int64`, and `privateKey *rsa.PrivateKey`. These are injected at plugin construction via `New(appID, privateKey, installationID)` and are fixed for the plugin's lifetime.

The plugin implements `credentials.ScopeValidator` (Validate + Narrow), covering scope structural checks and policy intersection. It does not yet call GitHub's REST API to mint tokens — the `CredentialVender` interface (`Vend`) is absent. The single-App shape means there is a 1:1 relationship between a running plugin instance and a GitHub App; an operator needing tokens for N Apps must run N plugin instances, which is operationally untenable.

---

## 2. New Multi-App Data Model

### App Registry

The plugin holds a map of named App clients:

```
apps: map[string]*githubAppClient
```

The map key is `app_name` — a human-readable identifier (e.g. `"ci-runner"`, `"release-bot"`) chosen by the operator at registration time. The orchestrator (T5) passes `app_name` in the `Scope.Params["app_name"]` field of every vend request, allowing the plugin to dispatch to the correct App without any global singleton state.

Each `githubAppClient` holds:

- `appID int64` — the numeric GitHub App ID from the App's settings page
- `installationID int64` — the installation ID for the target org/user
- `privateKey *rsa.PrivateKey` — the RSA-2048+ private key loaded from credential storage (see §3)
- `cachedToken string` — the last minted installation access token (empty until first mint)
- `tokenExpiresAt time.Time` — when `cachedToken` expires per GitHub's response `expires_at`
- `rateLimitRemaining int` — last observed `X-RateLimit-Remaining` header from GH API responses (informational; not a blocker)
- `rateLimitResetAt time.Time` — last observed `X-RateLimit-Reset` (unix epoch, converted)

### App Lookup per Request

When `Vend(ctx, scope)` is called, the plugin extracts `scope.Params["app_name"].(string)`, looks it up in the registry, and dispatches. An unknown `app_name` returns a permanent (non-retryable) error immediately without contacting GitHub. This makes misconfiguration fail-fast and distinct from transient API errors.

### Registration

Apps are registered at startup via `RegisterApp(name string, appID, installationID int64, privateKeyPEM []byte) error`. This is the only mutation path on the registry. The function is not concurrency-safe during initialization; callers must complete all registrations before the plugin starts serving requests. After startup, the registry is read-only (protected by `sync.RWMutex` for concurrent Vend calls in production).

---

## 3. Private Key Storage

Private keys are **externally provisioned** — the GitHub web UI is the only source (see recon doc §Q1). The operator imports each App's PEM-encoded private key into AgentKMS via `kpm akms-app import <app-name> <path-to-key.pem>`. KPM writes the key into the existing AgentKMS KV credential store at path `kv/data/github-apps/<app-name>/private_key`.

At plugin startup, `RegisterApp` receives the raw PEM bytes that the caller has already fetched from KV. The plugin never reads KV directly — key fetching is the responsibility of the startup/init layer. This preserves the existing KVReader abstraction and keeps the plugin free of KV dependencies.

AgentKMS never generates new GitHub App private keys (no API exists for that). The import flow is the only path. This is a documented human-in-the-loop step, not a limitation of this plugin.

---

## 4. JWT Signing

JWT signing uses `github.com/golang-jwt/jwt/v5`, which is already present in `go.mod` as an indirect dependency (`v5.3.1`). No new dependency is required.

Each App signs its own JWTs independently using its own `*rsa.PrivateKey`. Claims follow the GitHub spec (recon doc §Q5):

| Claim | Value |
|-------|-------|
| `iss` | `app_id` as string |
| `iat` | `now - 60s` (clock-drift buffer) |
| `exp` | `iat + 10min` |

Algorithm: RS256. JWTs are generated fresh for each token-mint call (they are short-lived and not cached). Token caching (§5) avoids re-signing unnecessarily, but whenever the cache misses, a new JWT is generated, used for one API call, and discarded.

---

## 5. Installation Token Caching

Each `githubAppClient` caches its current installation token in memory. Cache policy:

- **Hit:** if `cachedToken != ""` and `time.Now().Before(tokenExpiresAt.Add(-5*time.Minute))` → return cached token (no API call, no JWT signing)
- **Miss:** mint new token via `POST /app/installations/{installation_id}/access_tokens`, update `cachedToken` and `tokenExpiresAt` from response `expires_at`
- **TTL:** GitHub fixes installation tokens at 1 hour. The 5-minute pre-expiry buffer prevents callers from receiving a token that would expire mid-operation.

Cache is per-App. App A's token never affects App B.

---

## 6. Suspension

`Suspend(ctx, appName string) error` and `Unsuspend(ctx, appName string) error` are new methods on the plugin. They look up the App by name, sign a JWT, and call:

- Suspend: `PUT /app/installations/{installation_id}/suspended`
- Unsuspend: `DELETE /app/installations/{installation_id}/suspended`

These are intentionally low-ceremony — no complex state machine. The CLI surface (`kpm akms-app suspend <app-name>`) is owned by T3; this task only exposes the underlying method.

---

## 7. Per-App Rate Limit Awareness

GitHub's secondary limit is 2,000 token-mint calls/hour across all Apps (recon doc §Q6). At 30 Apps × 1 mint/hour = 30 requests, this is not a practical concern. However, each App client tracks `X-RateLimit-Remaining` and `X-RateLimit-Reset` from every GH API response.

When a response returns HTTP 403 with `X-RateLimit-Remaining: 0`, the plugin returns a transient error (not a permanent failure) with a `Retry-After` hint derived from `X-RateLimit-Reset`. The caller can retry after the reset window. This is distinct from hard errors (invalid JWT, 401) which are permanent.

---

## 8. Error Model

| Condition | Error Class | Behavior |
|-----------|-------------|----------|
| Unknown `app_name` | Permanent | Return immediately, no API call |
| Invalid private key at registration | Permanent | `RegisterApp` returns error |
| HTTP 401/403 (bad JWT, wrong App) | Permanent | Return error, caller must investigate |
| HTTP 403 + rate limit exhausted | Transient | Return error with retry-after hint |
| HTTP 5xx from GitHub | Transient | Return wrapped error; caller may retry |
| Network timeout | Transient | Context error propagated as-is |
| Token cache hit | n/a | Returns token, no error |

Transient vs. permanent is not encoded in a sentinel type today (the existing plugin has no error taxonomy). For now, the error message includes `[transient]` or `[permanent]` prefix so callers can pattern-match until a typed error system lands in a later track.

---

## 9. App Enumeration

`ListApps(ctx) ([]AppInfo, error)` returns a snapshot of registered Apps with their names, App IDs, installation IDs, and current suspension state. Suspension state is not tracked locally — this method calls `GET /app/installations` and cross-references. This is a diagnostic/admin surface, not a hot path.
