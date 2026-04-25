# Review Report — Day 2 Sprint (T4 + OpenBao Writer)

**Date:** 2026-04-26  
**Scope:** Read-only security and correctness review of two Day 2 tracks  
**Code Status:** All tests passing; no changes to go.mod/go.sum

## Summary

- **Files reviewed:** 13 (ghsecret: 9 Go files + 3 tests; OpenBao: 1 impl + 1 test file + wiring)
- **Test coverage:** 36 unit tests (T4 ghsecret) + 9 new tests (OpenBao KVWriter); all passing
- **MUST-FIX findings:** 0
- **SHOULD-FIX findings:** 3 (all low-severity, non-blocking)
- **NICE-TO-HAVE findings:** 2 (style/clarity only)

Both implementations are **production-ready** with respect to security, correctness, and contract compliance. The three SHOULD-FIX items are clarifications rather than bugs.

---

## MUST-FIX

**None.** No security risks, data loss risks, or contract violations detected.

---

## SHOULD-FIX

### 1. Delivery cache (T4: `deliverer.go`) grows unbounded with long-running plugins

**File:** `internal/destination/ghsecret/deliverer.go`, lines 59–62, 279–286  
**What:** The `deliveryCache map[string]deliveryResult` stores one entry per unique `delivery_id`. In a long-running plugin subprocess, this map has no eviction policy and grows indefinitely if the orchestrator generates new `delivery_id` values across many rotation cycles.  
**Why it matters:** In production, a plugin subprocess may run for weeks or months. If rotations happen frequently (e.g., hourly), the cache could accumulate thousands of entries and consume unbounded memory (each entry is ~50 bytes; 1M rotations = ~50MB, but still drift).  
**Spec alignment:** T1 spec §1 (Idempotency) says "In-memory only; not durable across subprocess restarts (acceptable per spec OQ-6)." It does not explicitly forbid eviction. The spec treats this as a known limitation ("plugin restarts lose idempotency state, but that's acceptable").  
**Suggested fix:** Add a simple TTL-based or LRU eviction to `pubkeyCache.go`'s cache pattern (1-hour TTL from last access). Alternatively, document the trade-off: "Unbounded cache is acceptable because (a) subprocess lifetime is typically <24h in Kubernetes, (b) memory footprint is small per entry, (c) eviction adds locking overhead for a rare edge case." Choose one and update the code comment on line 61.  
**Severity:** SHOULD-FIX, not MUST-FIX, because orchestrator-enforced subprocess timeouts (standard in Kubernetes) mitigate the risk.

---

### 2. OpenBao KV path translation does not validate input (openbao_kv.go)

**File:** `internal/credentials/openbao_kv.go`, lines 297–316  
**What:** `dataPathToMetaPath` and `metaPathToDataPath` translate paths by string replacement. If a caller passes a malformed path (e.g., `"kv/data/data/foo"` with duplicate `data`), the helpers may produce unexpected output. Example: `dataPathToMetaPath("kv/data/data/foo")` → `"kv/metadata/data/foo"` (correct) but `"kv/metadata/data/foo"` is not the intended metadata path.  
**Why it matters:** The contract is implicit: callers must pass paths in the correct form. If a caller constructs paths incorrectly, these helpers silently produce plausible-but-wrong paths rather than failing fast.  
**Spec alignment:** The spec assumes well-formed paths. T3 (binding store) and OpenBao reader/writer tests all use correct paths. However, a future caller (e.g., a new provider) might not.  
**Suggested fix:** Add assertions: `dataPathToMetaPath` should verify the input contains exactly one `"/data/"` and return an error if not. Same for `metaPathToDataPath` with `"/metadata/"`. Alternatively, clarify the contract with a comment: "Callers must pass paths in {mount}/data/{key} or {mount}/metadata/{key} form; malformed input will produce unexpected output (not validated)."  
**Severity:** SHOULD-FIX; this is a correctness improvement, not a bug in the current usage (all callers within the codebase pass correct paths).

---

### 3. T4 error signal helpers in plugin subprocess use string matching

**File:** `internal/destination/testdata/gh-secret-deliverer/main.go`, lines 201–228  
**What:** The `isTargetNotFound`, `isPermissionDenied`, `isGenerationRegression` helpers detect error conditions by searching the error message for tags like `"TARGET_NOT_FOUND"` and `"HTTP 404"`. These use string matching (`strings.Contains`, custom `findSubstring` function) rather than structured error checking.  
**Why it matters:** String-based error detection is fragile and couples the plugin binary's error parsing logic to the ghsecret package's error message format. If the error message format changes, the plugin's error classification breaks silently.  
**Why it was done this way:** The `ghError` type in `ghsecret/client.go` is unexported; the plugin binary cannot import and type-assert it. The string matching is a workaround to avoid CGo dependencies or extra marshalling.  
**Spec alignment:** The spec does not forbid string matching; this is an implementation detail. The orchestrator receives the error code correctly because the proto conversion (lines 82–96) maps the string-detected code to a proto enum.  
**Suggested fix:** Export a helper from ghsecret (e.g., `ClassifyError(err error) ErrorCode`) that returns an enum instead of using separate `isTargetNotFound`, `isPermissionDenied` functions. Or: add a comment explaining why string matching is used and list the exact tag formats that must remain stable.  
**Severity:** SHOULD-FIX; low risk because error message format is stable (it's in version control), but design clarity would be better.

---

## NICE-TO-HAVE

### 1. Encryption test verifies round-trip but not `SealAnonymous` primitive directly

**File:** `internal/destination/ghsecret/encrypt_test.go`  
**What:** The test `TestEncrypt_RoundTrip` encrypts, then decrypts with `box.OpenAnonymous`, verifying the result matches the plaintext. This is correct and sufficient. However, it does not explicitly verify that the ciphertext format matches libsodium's sealed-box structure (48-byte ephemeral key prepended + nonce + ciphertext + tag).  
**Why it doesn't matter:** The test uses the same `box.OpenAnonymous` to decrypt; if the format were wrong, decryption would fail. Checking the format separately adds no new validation. The test is adequate.  
**Nice improvement:** A comment in the test could clarify: "SealAnonymous is libsodium-compatible sealed-box construction; the round-trip test verifies interoperability."

---

### 2. OpenBao LIST response parsing does not handle directory recursion explicitly

**File:** `internal/credentials/openbao_kv.go`, lines 209–227  
**What:** `ListPaths` calls `listRecursive` to traverse nested directories. The recursion is correct, but the code assumes OpenBao's LIST returns immediate children only with trailing `/` for directories. If OpenBao's behavior changes or a custom KV v2 backend behaves differently, the recursion could misbehave.  
**Why it works:** The fake vault in tests stores flat data; real OpenBao KV v2 returns directories with `/`. The code is correct for the current setup.  
**Nice improvement:** A comment explaining the OpenBao KV v2 LIST contract would help: "OpenBao KV v2 LIST returns immediate children only; directories end with '/'. We recurse to flatten the full tree."

---

## What Looked Good

### Encryption & Cryptography (T4)

- **`encrypt.go`** — Excellent choice of `nacl/box.SealAnonymous` for pure-Go, libsodium-compatible sealed-box encryption. No CGo, already in `go.mod`. The dual base64 decoder (std + URL-safe) shows attention to GitHub's API quirks. The fixed 32-byte key validation is correct.
- **Test coverage** — Round-trip encryption, base64 variants, invalid key, wrong key length all tested. 87.2% coverage in ghsecret package.

### GitHub API Integration (T4)

- **Error classification** — Comprehensive error mapping: 404→permanent TARGET_NOT_FOUND, 401/403→permanent PERMISSION_DENIED, 422→transient (stale key), 429→transient (rate limit), 5xx→transient. Matches T1 spec §6.
- **422 retry logic** — On stale key, the plugin invalidates the cache and retries fetch+encrypt+put once (hard cap, not unbounded loop). The test verifies 2 fetches and 2 PUTs. Correct.
- **Idempotency** — `delivery_id` cache with dual keys (cache hit + generation regression check) prevents re-delivery. Test `TestDeliverer_Idempotent` verifies only 1 PUT on 2 calls with same delivery_id.
- **Public key cache** — 1-hour TTL, RWMutex-protected, explicit invalidation on 422. No lock-release bugs detected (all critical paths use `defer`).
- **Health endpoint** — GET /zen with zero-token client is lightweight and requires no authentication. Correct for health, not token validation.
- **Token handling** — Writer token is extracted from params, passed as Bearer header, never logged. Spot-checks of error messages confirm no token leakage in error strings.

### OpenBao KVWriter (T4+OpenBao)

- **Separated metadata invariant** — Test `TestOpenBaoKV_SeparatedMetadata` explicitly verifies that writing to `kv/data/secrets/X` and `kv/data/metadata/X` stores to different paths, and listing metadata does not leak secrets. Security-critical invariant is enforced.
- **Idempotent DELETE** — 404 on DELETE is treated as success (already absent). Correct for the idempotent revoke contract.
- **Path translation** — `dataPathToMetaPath` and `metaPathToDataPath` correctly translate between KV v2 data and metadata sub-paths. Tests verify end-to-end (Set → Get → List → Delete).
- **Error classification** — 401/403→permanent, 5xx→transient. 4xx errors (except 404) are permanent (misconfiguration). Matches the vender pattern.
- **No sensitive data in errors** — Response bodies are never included in 401/403 error messages (security mindset).

### Production Server Wiring

- **`cmd/server/main.go` lines 316–323** — Clean integration: `SetVender`, `SetRegistryWriter`, `SetBindingStore` all called when `AGENTKMS_VAULT_ADDR` is set. Gated properly so dev path (no vault) does not break.
- **Binding store initialization** — `binding.NewKVBindingStore(kv)` reuses the same OpenBaoKV instance, avoiding redundant connections.

### Testing

- **No subprocess test added for T4** — The report justifies this: 36 unit tests provide >87% coverage; subprocess integration test deferred. Reasonable trade-off.
- **Fake vault for OpenBao tests** — Minimal httptest-based fake server handles GET/POST/DELETE/LIST verbs. All tests isolated (no real network).
- **Interface compliance** — Compile-time `var _ credentials.KVWriter = (*credentials.OpenBaoKV)(nil)` confirms interface satisfaction.

### Documentation & Comments

- **Package-level docs** — `ghsecret/params.go` (lines 1–27) explains target format, auth, encryption. Clear.
- **Field-level security comments** — `writerToken` field (line 36 of params.go) marked SECURITY. Error handling (line 91 of client.go) notes body is not included to avoid token leakage.
- **Retry logic explanation** — `deliverer.go` line 219 explains 422 handling: "On 422 (stale `key_id`), invalidate cache and retry once."

---

## Audit & Orchestrator Integration Notes

Per T1 spec §10, audit events should be emitted by the orchestrator (host), not the plugin. The code correctly avoids audit calls in the plugin layer. The orchestrator's responsibility is to call the destination registry and emit `OperationDestinationDeliver` / `OperationDestinationRevoke` for each call. **No changes needed in T4 or OpenBao code** — this is orchestrator-scope (T5, future).

Similarly, the spec notes that the orchestrator tracks `generation` and `delivery_id` in the audit log for recovery. The plugin correctly enforces the generation regression invariant (test `TestDeliverer_GenerationRegression` verifies this).

---

## Recommendations for Future Work

1. **T4 delivery cache eviction** (SHOULD-FIX) — Document or implement TTL-based eviction before large-scale production deployment with long-lived subprocesses.
2. **OpenBao path validation** (SHOULD-FIX) — Add explicit validation or improve contract documentation.
3. **Plugin error signals** (SHOULD-FIX) — Export a structured error classifier from ghsecret to replace string matching.
4. **Subprocess integration test** (NICE-TO-HAVE, future T task) — Add a test that launches the gh-secret-deliverer binary and exercises the full gRPC stack.

---

## Conclusion

Both Day 2 implementations are **solid and ready for merge**. No blockers. The three SHOULD-FIX items are clarifications and edge-case improvements, not bugs in the current usage. All 45 tests pass; encryption is correct; error handling is comprehensive; security invariants are enforced; and integration is clean.

**Recommended action:** Merge to main. File SHOULD-FIX items as GitHub issues for post-v0.3 refinement if desired.
