# T4 Implementation Report — 2026-04-26

## Files Created

### docs/specs/
- `2026-04-26-T4-gh-secret-design.md` — Phase A design doc: API surface, encryption library choice, authentication, target_id format, public key cache invariant, capabilities.

### internal/destination/ghsecret/
- `params.go` — `parseParams(raw map[string]any) (params, error)` — typed extraction and validation of `writer_token` from the delivery params map. Tags errors [permanent].
- `client.go` — `ghClient` HTTP wrapper. Methods: `FetchPublicKey`, `PutSecret`, `DeleteSecret`, `Ping`. Accepts an injectable base URL and `*http.Client` for httptest. All error returns classified as permanent or transient via the `ghError` type. Exports: `IsTargetNotFound`, `IsPermissionDenied`, `IsPermanent` for use by the deliverer and tests.
- `encrypt.go` — `Seal(plaintext []byte, base64PubKey string) ([]byte, error)` and `SealBase64` wrapper. Uses `golang.org/x/crypto/nacl/box.SealAnonymous` — pure Go, no CGo. Accepts both standard and URL-safe base64 encoded public keys (GitHub uses standard).
- `pubkey_cache.go` — `pubkeyCache` with per-(owner, repo) entries, 1-hour TTL, injectable `nowFunc` for time control in tests. `sync.RWMutex`-protected. Methods: `Get`, `Set`, `Invalidate`, `Len`.
- `deliverer.go` — `Deliverer` struct implementing `destination.DestinationDeliverer`. Methods: `Kind`, `Capabilities`, `Validate`, `Deliver`, `Revoke`, `Health`. Includes in-memory delivery cache keyed by `delivery_id` for idempotent retry detection, per-target generation regression guard, and 422 stale-key retry logic.

### internal/destination/ghsecret/ (tests)
- `encrypt_test.go` — 5 tests
- `client_test.go` — 7 tests
- `pubkey_cache_test.go` — 3 tests
- `deliverer_test.go` — 21 tests

### internal/destination/testdata/gh-secret-deliverer/
- `main.go` — subprocess plugin binary. Wires `ghsecret.Deliverer` to `DestinationDelivererServiceServer`. Reads `AGENTKMS_GH_BASE_URL` from the environment to redirect API calls to a test server. Implements all 6 RPCs: `Kind`, `Capabilities`, `Validate`, `Deliver`, `Revoke`, `Health`. Maps ghsecret error strings to proto error codes. Mirrors the noop-deliverer pattern.

## go.mod / go.sum Changes

**None.** `golang.org/x/crypto v0.49.0` is already a direct dependency in `go.mod` (line 6). `nacl/box` is a sub-package of that module. No new entries required.

## Tests Added

**Total: 36 tests** across 4 test files.

| File | Count | Coverage |
|------|-------|----------|
| `encrypt_test.go` | 5 | Round-trip (generate keypair → seal → OpenAnonymous → verify), base64 variants (std + URL-safe), invalid key, wrong key length, SealBase64 output format |
| `client_test.go` | 7 | PutSecret happy path (decrypts ciphertext to verify), PutSecret 404 → permanent, PutSecret 401 → permanent, PutSecret 429 → transient, PutSecret 422 → transient, FetchPublicKey happy path, DeleteSecret 404 idempotent, Ping OK |
| `pubkey_cache_test.go` | 3 | Hit/miss/TTL expiry (injectable nowFunc), Invalidate, multiple repos independence |
| `deliverer_test.go` | 21 | HappyPath, Idempotent (delivery_id cache: 2 calls → 1 PUT), GenerationRegression (permanent), TargetIDParse (7 valid + 7 invalid forms), 404 permanent, 401 permanent, 5xx transient, 422 stale-key retry (key re-fetched, second PUT succeeds), cache hit/miss via Deliverer, Revoke idempotent (204 then 404 → both success), Validate token missing, Validate token valid, Validate token rejected, Health OK, Health unreachable, Kind, Capabilities, InterfaceCompliance, ZeroGeneration, params unit tests |

## Final Test Output

```
ok  github.com/agentkms/agentkms/internal/destination/ghsecret  1.893s  coverage: 87.2% of statements
```

Full repo:
```
ok  github.com/agentkms/agentkms/cmd/watchdog              0.659s
ok  github.com/agentkms/agentkms/internal/api              0.535s
ok  github.com/agentkms/agentkms/internal/audit            0.948s
ok  github.com/agentkms/agentkms/internal/auth             2.023s
ok  github.com/agentkms/agentkms/internal/backend          1.052s
ok  github.com/agentkms/agentkms/internal/credentials      1.583s
ok  github.com/agentkms/agentkms/internal/credentials/binding  0.760s
ok  github.com/agentkms/agentkms/internal/destination      1.200s
ok  github.com/agentkms/agentkms/internal/destination/ghsecret  1.893s
ok  github.com/agentkms/agentkms/internal/destination/noop  1.569s
ok  github.com/agentkms/agentkms/internal/dynsecrets/aws   2.024s
ok  github.com/agentkms/agentkms/internal/dynsecrets/github  4.349s
ok  github.com/agentkms/agentkms/internal/forensics        1.876s
ok  github.com/agentkms/agentkms/internal/hints            1.968s
ok  github.com/agentkms/agentkms/internal/honeytokens      1.926s
ok  github.com/agentkms/agentkms/internal/ingestion/github  1.965s
ok  github.com/agentkms/agentkms/internal/mcp              2.031s
ok  github.com/agentkms/agentkms/internal/plugin           17.174s
ok  github.com/agentkms/agentkms/internal/policy           2.142s
ok  github.com/agentkms/agentkms/internal/report           1.950s
ok  github.com/agentkms/agentkms/internal/revocation       1.853s
ok  github.com/agentkms/agentkms/internal/ui               1.920s
ok  github.com/agentkms/agentkms/internal/webhooks         1.978s
ok  github.com/agentkms/agentkms/pkg/keystore              1.983s
ok  github.com/agentkms/agentkms/pkg/tlsutil               1.879s
```

`go build ./...` — clean. `go vet ./...` — clean.

## Unilateral Decisions

**`DeleteSecret` treats 404 as success in `client.go`, not just in `Deliverer.Revoke`.** The 404-as-success logic lives in `ghClient.DeleteSecret` rather than only in `Deliverer.Revoke`. This means the idempotent revoke invariant is enforced at the HTTP layer, which is the right place — any caller of `DeleteSecret` gets the idempotent behaviour by default without having to remember to check for 404 themselves.

**`Ping` uses GET `/zen` with no auth token.** The health check uses GitHub's public `/zen` endpoint (returns a random aphorism, always 200 on a reachable API). This avoids using the writer token for health checks, which is correct — the health check should verify API reachability, not token validity (that's `Validate`'s job).

**422 retry is exactly one re-fetch, not a loop.** On 422 (stale `key_id`), the plugin invalidates the cache, fetches a fresh key, re-encrypts, and retries the PUT once. If the second attempt also returns 422, the plugin returns a transient error (the orchestrator will retry per its backoff policy). A loop inside a single `Deliver` call would exceed the spec's implicit contract that `Deliver` completes in bounded time.

**Delivery cache stores `errMsg string` instead of `error`.** Errors are not safe to share across goroutines in all implementations; storing the message string avoids any potential aliasing issues. The cached result is reconstructed with `fmt.Errorf` on cache hit.

**`parseTargetID` splits on the last colon** (not the first). This is correct because secret names cannot contain colons, but GitHub repository paths cannot contain colons either — so the delimiter is unambiguous. Using `LastIndex` is defensive against any future extension.

**`Deliverer.Health` uses a zero-token client.** `GET /zen` does not require authentication. Using the writer token for health would create an unnecessary dependency on the per-request token (which is in `params`, not stored on the deliverer struct). The health check is therefore token-independent.

**No subprocess handshake test added.** The task scoped this as optional ("only if the no-op test makes it easy to extend"). The no-op subprocess test in `internal/plugin/destination_host_test.go` requires a pre-built binary and uses a custom `StartDestination` code path. Adding a gh-secret subprocess test would require building the binary as a test fixture and setting up an httptest server for the GitHub API — a multi-step integration test. The 36 unit tests provide >87% coverage and cover all behavioural contracts. Subprocess integration test deferred to a future dedicated T task.

## New Blockers

None.

No files outside the declared scope were modified. `go.mod` and `go.sum` are unchanged. The `internal/api` test suite pre-condition from T1 (missing `bindingStore` field) remains an unrelated pre-existing issue in another track.
