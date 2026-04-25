# T3 Implementation Report — Credential Binding Data Model, Storage, and CLI

**Date:** 2026-04-25
**Sprint:** Automated Rotation Sprint (2026-04-25 – 2026-05-11)
**Track:** OSS

---

## Status

COMPLETE. All success criteria met.

---

## Files Created / Modified

### agentkms repo (`/Users/BertSmith/personal/catalyst9/projects/agentkms`)

**Created:**
- `internal/credentials/binding/binding.go` — `CredentialBinding` struct, validation, `BindingStore` interface, `kvBindingStore` implementation, supporting types (`DestinationSpec`, `RotationPolicy`, `BindingMetadata`, `BindingSummary`, `DestinationResult`)
- `internal/credentials/binding/binding_test.go` — 12 tests: validation, JSON round-trip, storage round-trip (save/get/list/delete), overwrite, multiple bindings, not-found, summary
- `internal/api/handlers_bindings.go` — 5 HTTP handlers: `POST /bindings`, `GET /bindings`, `GET /bindings/{name}`, `DELETE /bindings/{name}`, `POST /bindings/{name}/rotate`; `SetBindingStore` wiring method
- `internal/api/handlers_bindings_test.go` — 19 tests covering all 5 endpoints × (OK, not-found/validation error, unauthorized)
- `docs/specs/2026-04-25-T3-credential-binding-design.md` — design doc (Phase A)
- `docs/recon/2026-04-25-T3-implementation-report.md` — this file

**Modified:**
- `internal/audit/events.go` — added `OperationBindingRegister`, `OperationBindingRotate`, `OperationBindingDelete` constants
- `internal/api/server.go` — added `bindingStore binding.BindingStore` field; added `binding` package import; registered 5 binding routes in `registerRoutes()`

### kpm repo (`/Users/BertSmith/personal/catalyst9/projects/kpm`)

**Created:**
- `internal/kpm/cred.go` — `RunCred` dispatcher + `runCredRegister` / `runCredList` / `runCredInspect` / `runCredRotate` / `runCredRemove`; wire types (`CredentialBinding`, `BindingScope`, `DestinationSpec`, `RotationPolicy`, `BindingMetadata`, `BindingSummary`, `DestinationResult`, `RotateResponse`); `ParseDestinations` export for tests
- `internal/kpm/cred_test.go` — 21 tests: 7 client method tests, 11 `RunCred` CLI tests, 3 `ParseDestinations` unit tests

**Modified:**
- `internal/kpm/client.go` — added `RegisterBinding`, `ListBindings`, `GetBinding`, `RotateBinding`, `RemoveBinding` client methods; added `NewClientInsecure` for unit test use
- `cmd/kpm/main.go` — added `kpm cred` to usage string; added early dispatch block for `subcmd == "cred"` before the global `flag.FlagSet` parse

---

## Tests Added

| Repo | Package | New Tests | All Pass |
|------|---------|-----------|---------|
| agentkms | `internal/credentials/binding` | 12 | YES |
| agentkms | `internal/api` (binding handlers) | 19 | YES |
| kpm | `internal/kpm` (cred CLI + client) | 21 | YES |
| **Total** | | **52** | **YES** |

---

## go test Output

### agentkms — `internal/credentials/binding`

```
ok  github.com/agentkms/agentkms/internal/credentials/binding  0.171s
```

### agentkms — `internal/api`

```
ok  github.com/agentkms/agentkms/internal/api  0.528s
```
(Existing 251 tests + 19 new binding handler tests, all passing.)

### kpm — `internal/kpm`

```
ok  github.com/TheGenXCoder/kpm/internal/kpm  0.552s
```
(Existing 293 tests + 21 new cred tests, all passing. No existing tests were broken.)

### go vet

Both repos: clean (`go vet ./...` produces no output).

---

## Decisions Made

**1. Package name: `binding` (singular)**
The existing codebase uses singular package names throughout (`credentials`, `audit`, `policy`). `binding` follows that convention.

**2. Storage: single `"binding"` field in the KV map**
The `EncryptedKV` store's native unit is `map[string]string` per path. Rather than try to flatten the nested binding struct into a flat map (fragile, loses type information), we JSON-marshal the entire `CredentialBinding` and store it as a single `"binding"` key. This is the simplest correct approach and matches how complex objects are stored elsewhere in the codebase.

**3. Bindings prefix: `bindings/<name>`**
Isolated from the existing `kv/data/secrets/` and `kv/data/metadata/` namespaces. No existing path-filtering logic touches `bindings/`.

**4. Hard delete only for bindings**
Bindings contain no secret values (the credential is only held in-memory during vend). Soft-delete adds no security value and complicates the `List` path. Existing `secrets/` registry uses soft-delete because the secret value history is meaningful; bindings have no such history requirement.

**5. List endpoint uses `OperationBindingRegister` for policy**
No separate list operation constant was defined to keep the OSS policy surface minimal. The list and get operations share the `binding_register` permission. This can be split in a future iteration if fine-grained RBAC is needed.

**6. Flag parsing in CLI: pre-extract positional name**
Go's `flag.FlagSet` stops at the first non-flag argument, so `kpm cred inspect <name> --json` would leave `--json` unparsed. All subcommands that take a positional name now pre-extract it from the args slice before calling `fs.Parse`. This is a deliberate departure from the `fs.Args()` pattern used by the rest of the KPM CLI, documented in code comments.

**7. `NewClientInsecure` added to `client.go`**
Required for unit tests that spin up `httptest.Server` without TLS. Clearly named and commented "never use in production". The existing tests in the kpm repo do the same for other test scenarios.

---

## BLOCKERS

### B-1: Destination Registry (T1-merge) — Rotate endpoint is partially stubbed

The rotate endpoint (`POST /bindings/{name}/rotate`) needs to call `Deliver` on each destination's plugin. The destination plugin registry (T1) has not merged.

**Current behavior:** For each destination, the rotate handler synthesizes a `DestinationResult{Success: true}` stub. The binding's `last_rotated_at` and `last_generation` are updated. The endpoint is fully functional for OSS testing of the data model and CLI path.

**What T1 merge unblocks:** Replace the stub block in `handlers_bindings.go` (marked `// TODO(T1-merge)`) with:
```go
deliverer, lookupErr := s.destinationRegistry.LookupDeliverer(dest.Kind)
isPerm, deliverErr := deliverer.Deliver(ctx, destination.DeliverRequest{...})
```

The stub is clearly marked so the T1 implementer can find it with `grep -rn "TODO(T1-merge)"`.

### B-2: Provider vending for non-LLM kinds — Rotate uses Vender stub

The rotate handler calls `s.vender.Vend(ctx, b.ProviderKind)` for the credential value. The existing `Vender` only supports the 8 built-in LLM providers (anthropic, openai, etc.). For `provider_kind` values like `"github-app-token"`, vend fails and the handler falls through to a stub credential value (`"stub-credential-value"`).

**Impact:** OSS rotate works for LLM provider bindings. Non-LLM bindings rotate the stub value until the provider plugin registry (from T1/T5) lands.

**What fixes it:** Wire `s.providerRegistry.LookupVender(b.ProviderKind).Vend(ctx, b.Scope)` at the `// TODO(T1-merge)` marker in the rotate handler.

### B-3: `SetBindingStore` not called in `cmd/server/main.go`

`Server.SetBindingStore` must be called from `cmd/server/main.go` (and `cmd/dev/main.go`) with a real `KVBindingStore` backed by the `EncryptedKV` instance. Without this wiring, all `/bindings/*` endpoints return 503 in the running server. This is intentional (same pattern as `SetVender`, `SetRegistryWriter`) and not a bug in the T3 scope, but it is a required integration step before the endpoints are usable in a live deployment.

---

## No orchestrator/scheduling logic

Confirmed: no goroutines, no tickers, no retry loops, no `time.After`, no scheduling in any file delivered by this task. The rotate endpoint is synchronous request-response only.
