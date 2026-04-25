# GitHub App API Reconnaissance
**Date:** 2026-04-25
**Purpose:** Establish API-driven vs. web-UI-only boundaries before committing to automated rotation orchestrator architecture.

---

## Blockers (Human-in-the-Loop Requirements)

| # | Blocker | Impact |
|---|---------|--------|
| 1 | **Private key CREATE is web-UI only** | Cannot generate new keys programmatically. Orchestrator must use keys provisioned by a human. Key rotation (generate new → distribute → delete old) requires a human touch for the "generate" step. |
| 2 | **App registration (manifest flow) requires browser** | Creating net-new GitHub Apps requires a human to click through GitHub's web UI. Orchestrator cannot self-provision Apps. |
| 3 | **App metadata changes (permissions, webhook URL) are web-UI only** | No REST endpoint exists to modify an existing App's registered permissions or settings programmatically. |

Everything else in the desired flow (mint token → distribute → revoke → suspend) is fully API-driven.

---

## Q1 — Private Key CREATE via API

**Verdict: No API exists for key creation.**

GitHub's docs cover only web-UI steps for generating a private key: navigate to App settings → generate → download PEM. The REST surface for private keys is:

- `GET /app/installations` — list installations (does not touch keys)
- `POST /app-manifests/{code}/conversions` — returns the PEM for a *newly created* app as a one-time response during the manifest handshake; this is not key rotation

There is no `POST /apps/{app_slug}/keys` or equivalent. DELETE for existing keys is referenced as available but no creation endpoint is documented.

**Sources:**
- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps
- https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28

---

## Q2 — Auth Model for App Metadata Operations

**Verdict: JWT (authenticating as the App) covers token minting and installation management. App metadata changes require the App owner's credentials via web UI — no API path exists at all, JWT or otherwise.**

JWT (signed with App private key, RS256) is the authentication method for:
- `POST /app/installations/{installation_id}/access_tokens` — mint installation token
- `PUT /app/installations/{installation_id}/suspended` — suspend
- `DELETE /app/installations/{installation_id}/suspended` — unsuspend
- `GET /app`, `GET /app/installations` — read App metadata

No REST endpoints exist for modifying App registration (permissions, webhook, settings), making the JWT-vs-PAT question moot for those operations — they are web-UI-only regardless.

**Sources:**
- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app
- https://docs.github.com/en/apps/maintaining-github-apps/modifying-a-github-app-registration

---

## Q3 — Audit Log Actor Identity per App

**Verdict: Partially documented.** GitHub audit logs distinguish App-initiated actions via:

- `actor_is_bot: true` field on entries triggered by Apps
- `oauth_application_id` field identifying the specific App on relevant events (e.g., `hook.create`, `environment.create_actions_secret`, `integration_installation.*`)
- `application_client_id` on integration events
- Event category prefix `integration_installation.*` for App installation events

The exact `actor_login` format for App bots (e.g., whether it's `appname[bot]`) is **not explicitly documented** in the pages reviewed. GitHub Enterprise audit logs do include `oauth_application_id` which provides unambiguous per-App identity. Distinguishing 30 Apps in logs by `oauth_application_id` should be reliable; `actor_login` format is unknown.

**Sources:**
- https://docs.github.com/en/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise

---

## Q4 — App Suspension/Unsuspension Endpoints

**Verdict: Fully API-driven.**

- **Suspend:** `PUT /app/installations/{installation_id}/suspended`
- **Unsuspend:** `DELETE /app/installations/{installation_id}/suspended`

Both authenticate with JWT. These operate on the *installation*, not the App registration itself.

**Source:** https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28

---

## Q5 — Installation Token Minting: Spec and Response

**Endpoint:** `POST /app/installations/{installation_id}/access_tokens`
**Auth:** JWT (RS256, signed with App private key)

**JWT claims:**
| Claim | Value |
|-------|-------|
| `iss` | App's Client ID (or App ID) |
| `iat` | `now - 60s` (clock drift buffer) |
| `exp` | `iat + 10min` maximum |
| `alg` | RS256 (header) |

**Response shape:**
```json
{
  "token": "ghs_...",
  "expires_at": "2026-04-25T15:00:00Z",
  "permissions": { "contents": "read", ... },
  "repository_selection": "all" | "selected"
}
```

Token TTL: **1 hour** (fixed, non-configurable). Request can scope to specific repos (`repositories` or `repository_ids` arrays, max 500) and can narrow permissions below the App's grants.

**Sources:**
- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
- https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app

---

## Q6 — Rate Limits for Token Minting (~30 Apps, Hourly Rotation)

**Verdict: Not a concern for 30-App hourly rotation.**

The documented secondary rate limit is: **no more than 2,000 OAuth/installation token creation requests per hour** across all Apps and OAuth apps for an account. At 30 Apps × 1 mint/hour = 30 requests/hour — well under the 2,000 limit.

Once minted, each installation token carries a rate limit of **5,000 API requests/hour** (15,000 on GitHub Enterprise Cloud), scaling up with repository/user counts.

No per-App or per-installation limit on token minting frequency was documented beyond the 2,000/hour secondary limit.

**Source:** https://docs.github.com/en/rest/overview/rate-limits-for-the-rest-api

---

## Q7 — User-Owned vs. Org-Owned Apps: API Differences

**Verdict: No meaningful API surface difference documented.**

GitHub's docs do not enumerate capability differences between user-owned and org-owned Apps. The REST endpoints (installation management, token minting, suspension) are the same regardless of ownership. `TheGenXCoder` owning Apps personally is architecturally equivalent to org ownership for the operations this orchestrator needs.

One practical distinction: if the Apps are installed on an org, `GET /orgs/{org}/installation` retrieves the installation ID for that org — this works regardless of whether the App itself is user- or org-owned.

**Sources:**
- https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-github-apps
- https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28

---

## Q8 — App Manifest Flow: Programmatic or Browser Required?

**Verdict: Human in browser required.**

The manifest flow is a three-step OAuth-style handshake:
1. **Human** visits a URL embedding the manifest JSON and clicks "Create GitHub App" on GitHub's web UI
2. GitHub redirects back to `redirect_url` with a temporary `code`
3. Backend exchanges `code` via `POST /app-manifests/{code}/conversions` → receives App ID, client secret, webhook secret, and PEM (private key)

Step 1 is inescapably browser-based. There is no headless/server-side way to complete App registration.

**Source:** https://docs.github.com/en/developers/apps/building-github-apps/creating-a-github-app-from-a-manifest

---

## Summary Table

| Capability | API-Driven | Notes |
|------------|------------|-------|
| Mint installation token | Yes | `POST /app/installations/{id}/access_tokens` |
| Revoke installation token | Yes | `DELETE /installation/token` |
| Suspend/unsuspend installation | Yes | `PUT/DELETE /app/installations/{id}/suspended` |
| Delete existing private key | Yes | Documented as available |
| **Create new private key** | **No** | Web UI only — primary blocker |
| **Register new App** | **No** | Manifest flow requires browser |
| **Modify App permissions/metadata** | **No** | Web UI only |
| Read App info / list installations | Yes | JWT auth |
| Per-App audit identity | Partial | `oauth_application_id` reliable; `actor_login` format unknown |
