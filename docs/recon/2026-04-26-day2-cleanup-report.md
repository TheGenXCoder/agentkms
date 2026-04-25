# Day 2 Cleanup Report

**Date:** 2026-04-26  
**Scope:** Two SHOULD-FIX items from `docs/recon/2026-04-26-review-report.md`  
**SHOULD-FIX #1 (deliveryCache unbounded growth):** Intentionally deferred — NOT addressed.  
**SHOULD-FIX #2 (path validation):** Done.  
**SHOULD-FIX #3 (sentinel errors):** Done.

---

## Fix #2 — OpenBao KV path validation

### Files modified

- `internal/credentials/openbao_kv.go` — `dataPathToMetaPath` and `metaPathToDataPath` both received fail-fast validation
- `internal/credentials/openbao_kv_test.go` — three new test functions added

### What changed in `openbao_kv.go`

Both helpers now validate input before any string manipulation:

1. **Empty path** → `return "", fmt.Errorf("...: path must not be empty")`
2. **Missing infix** (`/data/` or `/metadata/`) → `return "", fmt.Errorf("...: does not contain ...")`
3. **Prefix-only with no key after infix** (e.g. `"kv/data/"`) → `return "", fmt.Errorf("...: has nothing after ...")`

Error messages are prefixed with `credentials:` and include the function name for traceability. The error propagates up through `DeleteSecret` (the only public caller of `dataPathToMetaPath`) and through `listRecursive` (caller of `metaPathToDataPath`), where the existing `continue` on error for untranslatable paths is preserved.

### Tests added

| Test | What it exercises |
|---|---|
| `TestDataPathToMetaPath_Validation` | Three subtests: empty path, missing `/data/` infix, prefix-only `kv/data/`. All trigger errors via `DeleteSecret`. |
| `TestDataPathToMetaPath_HappyPath` | Valid path round-trips correctly; DELETE reaches the server at the right metadata path. |
| `TestMetaPathToDataPath_Validation` | `listRecursive` survives a valid key returned by LIST; translates `kv/metadata/valid-key` → `kv/data/valid-key` without error or panic. |

---

## Fix #3 — Structured sentinel errors in ghsecret

### Files created

- `internal/destination/ghsecret/errors.go` — defines five package-level sentinel vars

### Files modified

- `internal/destination/ghsecret/client.go` — `ghError` gains `Unwrap()` returning its sentinel; `IsTargetNotFound` / `IsPermissionDenied` reimplemented via `errors.Is`; `IsPermanent` updated to fall back to sentinel check; `errors` import added
- `internal/destination/ghsecret/deliverer.go` — generation regression error now wraps `ErrGenerationRegression` via `%w`
- `internal/destination/ghsecret/client_test.go` — six new `TestSentinel_*` functions; `errors` import added
- `internal/destination/ghsecret/deliverer_test.go` — `TestDeliverer_GenerationRegression` now also asserts `errors.Is(err, ErrGenerationRegression)`; `errors` import added
- `internal/destination/testdata/gh-secret-deliverer/main.go` — string-matching helpers removed; `classifyError()` added using `errors.Is`; `net/http` import removed, `errors` import added

### Design: `ghError.Unwrap()`

Rather than changing all `checkError` call sites, `*ghError` now implements `Unwrap()` returning its sentinel based on `errCodeType`. This means:

```
errors.Is(err, ErrTargetNotFound)  // true for any *ghError with errCodeTargetNotFound
```

The mapping is:

| HTTP status | `errCodeType` | Sentinel returned by `Unwrap()` |
|---|---|---|
| 404 | `errCodeTargetNotFound` | `ErrTargetNotFound` |
| 401 / 403 | `errCodePermissionDenied` | `ErrPermissionDenied` |
| 422 / 429 / 5xx | `errCodeTransient` | `ErrTransient` |
| 400 / 409 / other 4xx | `errCodePermanent` | `ErrPermanent` |

### Subprocess `classifyError()`

Replaces four string-matching helper functions (`isTargetNotFound`, `isPermissionDenied`, `isGenerationRegression`, `containsTag`/`findSubstring`/`isGHErrWith`) with a single `classifyError(err error, isPerm bool) pluginv1.DestinationErrorCode` using a `switch errors.Is(...)` chain. The order matches precedence: specific sentinels (`ErrTargetNotFound`, `ErrPermissionDenied`, `ErrGenerationRegression`, `ErrTransient`) before the `isPerm` fallback.

### Tests added / modified

**New in `client_test.go`:**

| Test | Asserts |
|---|---|
| `TestSentinel_404_IsTargetNotFound` | `errors.Is(err, ErrTargetNotFound)` true; `ErrPermissionDenied`/`ErrTransient` false |
| `TestSentinel_401_IsPermissionDenied` | `errors.Is(err, ErrPermissionDenied)` true; `ErrTargetNotFound` false |
| `TestSentinel_403_IsPermissionDenied` | Same as 401 |
| `TestSentinel_500_IsTransient` | `errors.Is(err, ErrTransient)` true; `ErrPermanent` false |
| `TestSentinel_422_IsTransient` | `errors.Is(err, ErrTransient)` true |
| `TestSentinel_FetchPublicKey_404` | `FetchPublicKey` 404 → `ErrTargetNotFound` |

**Modified in `deliverer_test.go`:**

- `TestDeliverer_GenerationRegression` — added `errors.Is(err, ErrGenerationRegression)` assertion alongside existing `strings.Contains` check (both now required)

---

## Validation output

### `go build ./...`

```
(no output — clean build)
```

### `go vet ./...`

```
(no output — clean vet)
```

### `go test ./...` (full repo)

```
ok  github.com/agentkms/agentkms/cmd/watchdog            (cached)
ok  github.com/agentkms/agentkms/internal/api             0.956s
ok  github.com/agentkms/agentkms/internal/audit           (cached)
ok  github.com/agentkms/agentkms/internal/auth            (cached)
ok  github.com/agentkms/agentkms/internal/backend         (cached)
ok  github.com/agentkms/agentkms/internal/credentials     0.604s
ok  github.com/agentkms/agentkms/internal/credentials/binding  0.220s
ok  github.com/agentkms/agentkms/internal/destination     (cached)
ok  github.com/agentkms/agentkms/internal/destination/ghsecret  0.878s
ok  github.com/agentkms/agentkms/internal/destination/noop  (cached)
ok  github.com/agentkms/agentkms/internal/dynsecrets/aws  (cached)
ok  github.com/agentkms/agentkms/internal/dynsecrets/github  (cached)
ok  github.com/agentkms/agentkms/internal/forensics       (cached)
ok  github.com/agentkms/agentkms/internal/hints           (cached)
ok  github.com/agentkms/agentkms/internal/honeytokens     (cached)
ok  github.com/agentkms/agentkms/internal/ingestion/github  (cached)
ok  github.com/agentkms/agentkms/internal/mcp             (cached)
ok  github.com/agentkms/agentkms/internal/plugin          (cached)
ok  github.com/agentkms/agentkms/internal/policy          (cached)
ok  github.com/agentkms/agentkms/internal/report          (cached)
ok  github.com/agentkms/agentkms/internal/revocation      (cached)
ok  github.com/agentkms/agentkms/internal/ui              (cached)
ok  github.com/agentkms/agentkms/internal/webhooks        (cached)
ok  github.com/agentkms/agentkms/pkg/keystore             (cached)
ok  github.com/agentkms/agentkms/pkg/tlsutil              (cached)
```

### `go test ./internal/destination/ghsecret/... -v` (all PASS)

47 tests total. All new sentinel tests:

```
--- PASS: TestSentinel_404_IsTargetNotFound (0.00s)
--- PASS: TestSentinel_401_IsPermissionDenied (0.00s)
--- PASS: TestSentinel_403_IsPermissionDenied (0.00s)
--- PASS: TestSentinel_500_IsTransient (0.00s)
--- PASS: TestSentinel_422_IsTransient (0.00s)
--- PASS: TestSentinel_FetchPublicKey_404 (0.00s)
--- PASS: TestDeliverer_GenerationRegression (0.00s)
ok  github.com/agentkms/agentkms/internal/destination/ghsecret  0.878s
```

### `go test ./internal/credentials/... -run "TestDataPath|TestMetaPath"` (all PASS)

```
--- PASS: TestDataPathToMetaPath_Validation (0.00s)
    --- PASS: TestDataPathToMetaPath_Validation/empty_path (0.00s)
    --- PASS: TestDataPathToMetaPath_Validation/missing_/data/_infix (0.00s)
    --- PASS: TestDataPathToMetaPath_Validation/prefix_only_—_nothing_after_/data/ (0.00s)
--- PASS: TestDataPathToMetaPath_HappyPath (0.00s)
--- PASS: TestMetaPathToDataPath_Validation (0.00s)
ok  github.com/agentkms/agentkms/internal/credentials  0.349s
```

---

## New BLOCKERS

None.
