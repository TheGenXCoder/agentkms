# OpenBao KVWriter Implementation Report — 2026-04-26

## Summary

`OpenBaoKV` now implements the full `KVWriter` interface. The production
server (`cmd/server/main.go`) is fully wired: `SetRegistryWriter` and
`SetBindingStore` are both called against the live `OpenBaoKV` instance when
`AGENTKMS_VAULT_ADDR` is set.

---

## Files Modified

| File | Change |
|------|--------|
| `internal/credentials/openbao_kv.go` | Added `SetSecret`, `DeleteSecret`, `ListPaths` methods; added `kvv2ListResponse` struct; added `dataPathToMetaPath` and `metaPathToDataPath` path-translation helpers; added `bytes` import. |
| `internal/credentials/openbao_kv_test.go` | Rewrote `fakeVaultKV` to handle POST, DELETE, and LIST verbs in addition to GET; updated existing GET tests to use the new `newFakeVaultKV()` constructor; added 9 new writer tests (see below). |
| `cmd/server/main.go` | Added `binding` import; added `apiServer.SetRegistryWriter(kv)` and `apiServer.SetBindingStore(binding.NewKVBindingStore(kv))` immediately after `SetVender`. |

---

## Implementation Design

### Path model

The codebase stores secrets at logical paths of the form
`{mount}/data/{key}` (e.g. `kv/data/secrets/svc/name`).  These map directly
to the OpenBao KV v2 data endpoint: `POST /v1/kv/data/secrets/svc/name`.

For **delete** (purge all versions), OpenBao KV v2 requires targeting the
*metadata* sub-path: `DELETE /v1/kv/metadata/secrets/svc/name`.  The
`dataPathToMetaPath` helper translates `kv/data/X` → `kv/metadata/X` for
this call.

For **list**, OpenBao KV v2's `LIST /v1/{mount}/metadata/{prefix}` returns
immediate children only (directories have a trailing `/`).  `listRecursive`
traverses all levels and translates returned metadata keys back to data paths
via `metaPathToDataPath`.

### Security invariants preserved

- Metadata and secret values are written to **separate paths**
  (`kv/data/metadata/{key}` vs `kv/data/secrets/{key}`).  Listing metadata
  cannot reach secret value paths.
- `DeleteSecret` always targets the metadata endpoint (purges all versions,
  no soft-delete lingering).
- The token is passed as `X-Vault-Token` header only (never in URL or body).
- Error messages for 401/403 never include response body content.

### No new dependencies

The implementation uses only `net/http`, `encoding/json`, `bytes`, and
`strings` — all already imported or standard library.  No OpenBao SDK added.

---

## Tests Added

All tests live in `internal/credentials/openbao_kv_test.go` (no build tags —
default `go test` mode using `httptest` fake).

| Test | Coverage target |
|------|-----------------|
| `TestOpenBaoKV_SetSecret_HappyPath` | POST reaches correct data path; token header set; value stored |
| `TestOpenBaoKV_SetSecret_AuthFailure` | 403 response → permanent "forbidden" error |
| `TestOpenBaoKV_SetSecret_ServerError` | 500 response → transient error |
| `TestOpenBaoKV_DeleteSecret` | DELETE targets metadata path; key removed from store |
| `TestOpenBaoKV_DeleteSecret_Idempotent` | DELETE of non-existent key returns nil (idempotent) |
| `TestOpenBaoKV_ListPaths` | LIST returns data paths (not metadata paths); multiple namespaces |
| `TestOpenBaoKV_ListPaths_Empty` | Empty vault (404 on LIST) → empty slice, no error |
| `TestOpenBaoKV_RoundTrip` | Set → Get → List → Delete → verify gone end-to-end |
| `TestOpenBaoKV_SeparatedMetadata` | Security invariant: secret and metadata paths are distinct; metadata response contains no secret values |

Plus a compile-time interface assertion:

```go
var _ credentials.KVWriter = (*credentials.OpenBaoKV)(nil)
```

---

## go test output

### `internal/credentials/...`

```
ok  github.com/agentkms/agentkms/internal/credentials          1.143s
ok  github.com/agentkms/agentkms/internal/credentials/binding  1.162s
```

All 9 new tests pass. All pre-existing tests pass.

### Full repo

```
ok  github.com/agentkms/agentkms/internal/api          0.583s
ok  github.com/agentkms/agentkms/internal/audit         1.085s
ok  github.com/agentkms/agentkms/internal/auth          (cached)
ok  github.com/agentkms/agentkms/internal/backend       (cached)
ok  github.com/agentkms/agentkms/internal/credentials   1.143s
ok  github.com/agentkms/agentkms/internal/credentials/binding  1.162s
...all other packages pass...
```

`go build ./...` and `go vet ./...` both clean.

### Integration tests

`internal/backend/openbao_integration_test.go` uses `//go:build integration`
and requires a live OpenBao instance.  The new KV writer tests in
`internal/credentials/openbao_kv_test.go` do **not** have any build tag and
run under default `go test ./...`.  There is no separate integration test
file for the KV writer; all coverage is via httptest fake.

---

## Production server wiring status

`cmd/server/main.go` is **fully wired**:

```go
kv := credentials.NewOpenBaoKV(*vaultAddr, vaultToken, vaultTLS)
apiServer.SetVender(credentials.NewVender(kv, "kv"))
apiServer.SetRegistryWriter(kv)                             // NEW
apiServer.SetBindingStore(binding.NewKVBindingStore(kv))    // NEW
```

Both `SetRegistryWriter` and `SetBindingStore` are called when
`AGENTKMS_VAULT_ADDR` is set.  The "TODO: not wired in production" gap is
closed.

---

## Blockers

None.
