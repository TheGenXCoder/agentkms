# T4 Design — `destination-gh-secret` Plugin

**Date:** 2026-04-26
**Status:** Approved — implementation follows from this doc
**Track:** Sprint Day 2, automated credential rotation

---

## 1. GitHub Actions Secrets API Surface

Three REST endpoints are used. All operate on repository secrets (organization
secrets are a v2 concern; `target_id` documents the extended format when
relevant).

### 1.1 Fetch repo encryption public key

```
GET /repos/{owner}/{repo}/actions/secrets/public-key
```

Returns `key_id` (string) and `key` (base64-encoded Curve25519 public key).
This key must be used to encrypt the secret value before calling `PUT`. The key
is repo-specific and rotates occasionally; the plugin caches it with a 1-hour
TTL.

Reference: https://docs.github.com/en/rest/actions/secrets#get-a-repository-public-key

### 1.2 Write (create or update) an encrypted secret

```
PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}
```

Body (JSON):
```json
{
  "encrypted_value": "<base64(sealed_ciphertext)>",
  "key_id": "<key_id from GET public-key>"
}
```

Returns 201 (created) or 204 (updated). The request body must contain the
ciphertext sealed with the repo's Curve25519 public key using libsodium sealed
boxes. The `key_id` field ties the ciphertext to the specific key generation
that was used for encryption; GitHub uses it to select the corresponding private
key for decryption.

Reference: https://docs.github.com/en/rest/actions/secrets#create-or-update-a-repository-secret

### 1.3 Delete a secret

```
DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}
```

Returns 204 on success. Returns 404 if the secret does not exist — the plugin
treats this as a success (idempotent revoke contract).

Reference: https://docs.github.com/en/rest/actions/secrets#delete-a-repository-secret

---

## 2. Encryption Library Choice

### Decision: `golang.org/x/crypto/nacl/box.SealAnonymous`

GitHub Actions secrets use **libsodium sealed boxes**, which are:
- Curve25519 key agreement (sender ephemeral keypair + recipient static key)
- XSalsa20-Poly1305 symmetric encryption
- Ephemeral sender public key prepended to ciphertext

The Go standard library does not include sealed boxes. Two options were evaluated:

**Option A — `github.com/jamesruan/sodium`**
- CGo wrapper around the libsodium C library
- Requires libsodium to be installed at build time (`brew install libsodium`)
- Adds a CGo dependency — violates the zero-CGo policy for the plugin layer
- Incompatible with cross-compilation and static binary builds
- **Rejected**

**Option B — `golang.org/x/crypto/nacl/box.SealAnonymous` (CHOSEN)**
- Pure Go implementation; no CGo, no C dependencies
- Already in `go.mod` as a transitive dependency of `golang.org/x/crypto v0.49.0`
- `SealAnonymous` implements the exact libsodium sealed-box construction:
  ephemeral keypair generated per-call, recipient public key used for key
  agreement, ciphertext = `ephemeral_pubkey || box(message, nonce, shared_key)`
- Interoperable with libsodium by design (documented in the package)
- No new dependency needed — `go.mod` and `go.sum` are not modified by T4

**No go.mod or go.sum changes are required.** `golang.org/x/crypto` is already
a direct dependency (line 6 of `go.mod`).

---

## 3. Authentication

The `writer_token` parameter in `params` is an opaque Bearer token string.
For v1 the plugin accepts any token string — either a Personal Access Token
(PAT, classic or fine-grained) or a GitHub App installation access token. The
token is never logged and is passed directly as `Authorization: Bearer <token>`.

Required token scope for PAT: `repo` (which includes
`secrets:write` on the target repository).

Required permission for App token: `secrets: write` on the installation.

**v2 plan (Pro track, out of scope for T4):** The orchestrator's `dynsecrets`
module (`internal/dynsecrets/github`) already implements GitHub App installation
token minting. In v2, the orchestrator mints a short-lived installation token
and injects it into `params["writer_token"]` per `Deliver` call. The plugin
remains stateless with respect to authentication — it always consumes the token
from params. No plugin-side changes are needed for v2; the upgrade is purely
orchestrator-side.

---

## 4. `target_id` Format

Per spec §7.3:

```
owner/repo:SECRET_NAME
```

The colon is the unique delimiter between the repository path and the secret
name. Parse rules:

- Split on the **last** colon in the string.
- Left side: `owner/repo` — must contain exactly one `/`, both parts non-empty.
- Right side: `SECRET_NAME` — must be non-empty; GitHub allows `[A-Z0-9_]`
  (uppercase; the plugin does not enforce casing but validates non-empty).

Invalid forms rejected with a permanent error:
- `"foo"` — no colon
- `"foo/bar"` — no colon  
- `":SECRET"` — empty repo path
- `"a/b:"` — empty secret name
- `"org"` — no slash in repo path (incomplete)

Organization secrets (`org/ORG_NAME:SECRET_NAME`) are not supported in v1;
the plugin uses the repository endpoint only. An attempt to target an org
secret will receive a 404 from GitHub and return `TARGET_NOT_FOUND`.

---

## 5. Public Key Cache

**Cache key:** `(owner, repo)` string pair.

**TTL:** 1 hour from fetch time. GitHub rotates public keys infrequently (on
key compromise or rollover), but caching indefinitely creates a window where a
rotated key causes silent encryption failures. 1 hour balances API call volume
against stale-key risk.

**Cache invariant:**
- On first `Deliver` for a `(owner, repo)` pair, fetch and cache.
- On subsequent `Deliver` within TTL, use cached value.
- On `Deliver` after TTL expiry, re-fetch and update cache.
- If `PutSecret` returns 422 (Unprocessable Entity — GH rejects the encrypted
  value, usually because the `key_id` is stale), invalidate the cache entry and
  retry the fetch+encrypt+put cycle once before returning a transient error.
  (422 handling: mark transient so the orchestrator retries; the re-fetch
  happens inside the single `Deliver` call before returning.)
- If `FetchPublicKey` returns 404, the repository does not exist: return
  permanent `TARGET_NOT_FOUND`.

**Thread safety:** `sync.RWMutex` protecting the cache map; read lock for hits,
write lock for misses and invalidation.

---

## 6. Capabilities

The plugin declares:

```go
[]string{"health", "revoke"}
```

- `"health"`: implements `Health()` with a real connectivity probe (GET `/zen`).
- `"revoke"`: implements `Revoke()` with DELETE; treats 404 as success.
- No `"expiry-metadata"`: GitHub Actions secrets do not store expiry timestamps
  alongside the secret value, so the plugin has nothing to write for
  `expires_at` / `ttl_seconds` hints.
