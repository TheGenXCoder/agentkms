# T2 Implementation Report: Multi-App GitHub Plugin
**Date:** 2026-04-25
**Track:** T2 — dynsecrets-github multi-App support
**Status:** Complete

---

## Files Created / Modified

### Created
- `internal/dynsecrets/github/client.go` — per-App client: JWT signing, token minting with cache, suspension, rate-limit tracking, error classification
- `internal/dynsecrets/github/export_test.go` — test-only `SetTestBaseURL` hook (compiled only in test binary; not in production binary)
- `internal/dynsecrets/github/multi_app_test.go` — 16 new test cases covering all multi-App scenarios (httptest-based, no real network)
- `docs/specs/2026-04-25-T2-multi-app-design.md` — design doc (500-800 words, written before implementation)

### Modified
- `internal/dynsecrets/github/plugin.go` — full rewrite: added `NewMulti()`, `RegisterApp()`, `Vend()`, `Suspend()`, `Unsuspend()`, `ListApps()`; preserved `New()` and all existing `ScopeValidator` methods; added `credentials.CredentialVender` compile-time assertion

### Not Modified (scope boundary respected)
- `internal/plugin/`, `internal/destination/`, `internal/credentials/`, `cmd/`, `api/plugin/v1/`
- The original `plugin_test.go` (13 existing tests) — all still pass

---

## Tests Added

**New tests:** 16 (in `multi_app_test.go`)
**Pre-existing tests:** 13 (in `plugin_test.go`) — all continue to pass
**Total test count:** 29

| Test | What it covers |
|------|----------------|
| `TestMultiApp_RegisterAndList` | Register 3 Apps, ListApps returns all 3 with correct metadata |
| `TestMultiApp_MintTokenAppA_CorrectJWTAndInstallation` | App A gets correct token, only App A's installation called |
| `TestMultiApp_MintTokenAppB_NoCrossContamination` | Apps A and B get distinct tokens; no cross-contamination |
| `TestMultiApp_TokenCaching` | Second Vend within TTL returns cached token (no extra API call) |
| `TestMultiApp_TokenCacheExpiry` | Expired cache triggers fresh API call returning new token |
| `TestMultiApp_Suspend` | PUT to correct installation ID, correct HTTP method |
| `TestMultiApp_Unsuspend` | DELETE to correct installation ID, not confused with Suspend |
| `TestMultiApp_RateLimitExhausted` | 403 + X-RateLimit-Remaining:0 → [transient] error with "rate" in message |
| `TestMultiApp_JWTSigningVerifiesWithCorrectKey` | JWT verifies with App A's public key; fails with App B's key |
| `TestMultiApp_UnknownAppReturnsPermanentError` | Unknown app_name → [permanent] error naming the unknown app |
| `TestMultiApp_EmptyAppNameUsesDefault` | Missing app_name in Params falls back to "default" App (New() compat) |
| `TestMultiApp_ValidateRejectsUnknownAppName` | Validate returns error for unknown app_name in Params |
| `TestMultiApp_ValidateAcceptsNoAppName` | Validate passes when app_name is absent |
| `TestMultiApp_RegisterAppRejectsEmptyName` | RegisterApp("") returns error |
| `TestMultiApp_SuspendUnknownApp` | Suspend unknown app → [permanent] error |
| `TestMultiApp_ServerErrorIsTransient` | HTTP 500 from GH → [transient] error |

---

## `go test` Output

```
=== RUN   TestMultiApp_RegisterAndList
--- PASS: TestMultiApp_RegisterAndList (0.14s)
=== RUN   TestMultiApp_MintTokenAppA_CorrectJWTAndInstallation
--- PASS: TestMultiApp_MintTokenAppA_CorrectJWTAndInstallation (0.18s)
=== RUN   TestMultiApp_MintTokenAppB_NoCrossContamination
--- PASS: TestMultiApp_MintTokenAppB_NoCrossContamination (0.13s)
=== RUN   TestMultiApp_TokenCaching
--- PASS: TestMultiApp_TokenCaching (0.09s)
=== RUN   TestMultiApp_TokenCacheExpiry
--- PASS: TestMultiApp_TokenCacheExpiry (0.05s)
=== RUN   TestMultiApp_Suspend
--- PASS: TestMultiApp_Suspend (0.08s)
=== RUN   TestMultiApp_Unsuspend
--- PASS: TestMultiApp_Unsuspend (0.08s)
=== RUN   TestMultiApp_RateLimitExhausted
--- PASS: TestMultiApp_RateLimitExhausted (0.03s)
=== RUN   TestMultiApp_JWTSigningVerifiesWithCorrectKey
--- PASS: TestMultiApp_JWTSigningVerifiesWithCorrectKey (0.17s)
=== RUN   TestMultiApp_UnknownAppReturnsPermanentError
--- PASS: TestMultiApp_UnknownAppReturnsPermanentError (0.09s)
=== RUN   TestMultiApp_EmptyAppNameUsesDefault
--- PASS: TestMultiApp_EmptyAppNameUsesDefault (0.01s)
=== RUN   TestMultiApp_ValidateRejectsUnknownAppName
--- PASS: TestMultiApp_ValidateRejectsUnknownAppName (0.01s)
=== RUN   TestMultiApp_ValidateAcceptsNoAppName
--- PASS: TestMultiApp_ValidateAcceptsNoAppName (0.02s)
=== RUN   TestMultiApp_RegisterAppRejectsEmptyName
--- PASS: TestMultiApp_RegisterAppRejectsEmptyName (0.07s)
=== RUN   TestMultiApp_SuspendUnknownApp
--- PASS: TestMultiApp_SuspendUnknownApp (0.00s)
=== RUN   TestMultiApp_ServerErrorIsTransient
--- PASS: TestMultiApp_ServerErrorIsTransient (0.03s)
=== RUN   TestGitHubPlugin_Kind
--- PASS: TestGitHubPlugin_Kind (0.07s)
... (13 pre-existing tests — all PASS)
PASS
ok  github.com/agentkms/agentkms/internal/dynsecrets/github  2.191s
coverage: 87.2% of statements
```

Target was >80%; achieved **87.2%**.

---

## Decisions Made Unilaterally

1. **`export_test.go` pattern for `SetTestBaseURL`** — rather than adding a test parameter to the `RegisterApp` signature, used Go's `export_test.go` pattern (compiled only in test binaries). This keeps the production API clean and avoids any test-vs-prod divergence.

2. **`[transient]` / `[permanent]` error prefix convention** — the existing codebase has no typed error taxonomy for plugin errors. Added string prefixes as a stop-gap. These are greppable and safe for callers to pattern-match until a typed error type lands in a later track.

3. **`NewMulti()` + `New()` coexistence** — preserved the existing `New(appID, key, installID)` constructor unchanged, delegating to `RegisterApp("default", ...)`. This means zero changes to existing callers; they get multi-App as an opt-in.

4. **`Narrow()` propagates `app_name`** — added propagation of `app_name` param through the narrowing step so it survives the scope-intersection pipeline and reaches `Vend`.

5. **Token cache uses `tokenExpiresAt - 5min` threshold** — matches the recon spec exactly. When the mock returns an already-expired token (`time.Now() - 10min`) in `TestMultiApp_TokenCacheExpiry`, the cache miss correctly re-mints on the second call.

6. **`VendedCredential.ProviderTokenHash` not set** — `Vend()` does not compute the SHA-256 hash of the minted token. The `audit.HashProviderToken` function is used by `internal/credentials` for the LLM vending path; importing it here would create a cross-package dependency. The hash can be added when the audit integration track wires Vend into the audit pipeline (it requires a zero-copy hash before returning the token). Noted as a TODO comment in `Vend()`.

---

## New Blockers

None. All success criteria met:

- `go build ./...` — clean
- `go test ./internal/dynsecrets/github/...` — 29/29 PASS, 87.2% coverage
- `go vet ./internal/dynsecrets/github/...` — clean
- All HTTP calls in tests use `httptest.Server` — no real network

**Pre-existing `go vet ./...` failures** (outside T2 scope):
- `internal/plugin/grpcadapter.go:14` — unused import of `internal/destination`; pre-existed before this task (confirmed via `git stash`). Owned by another track.
- `api/plugin/v1/` — generated protobuf references to undefined types; also pre-existing.
