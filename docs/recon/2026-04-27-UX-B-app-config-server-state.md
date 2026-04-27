# UX-B Recon: GitHub App Config → AgentKMS Server State

**Date:** 2026-04-27
**Status:** COMPLETE — all repos build, vet, and test green

---

## What Was Built

UX-B moves GitHub App private-key configuration out of `~/.agentkms/plugins/github-apps.yaml`
and into AgentKMS server-managed state backed by the existing `credentials.KVWriter` interface.

### New UX

```bash
# Register a GitHub App (PEM read from stdin — never written to disk or logs)
kpm get github/blog-audit-app/private-key | \
  kpm gh-app register agentkms-blog-audit-rotator \
    --app-id 3512662 \
    --installation-id 127321567 \
    --private-key -

kpm gh-app list
kpm gh-app inspect agentkms-blog-audit-rotator
kpm gh-app remove agentkms-blog-audit-rotator
```

---

## Architecture Overview

### Server side (agentkms)

**`internal/githubapp/`** — new package
- `types.go` — `GithubApp` struct (with PEM) and `Summary` struct (without PEM)
- `store.go` — `Store` interface (`Save/Get/List/Delete`) + `ErrNotFound` sentinel
- `kv_store.go` — `KVStore` implementation backed by `credentials.KVWriter`; KV path `github-apps/<name>`

**`internal/audit/events.go`** — added three operation constants:
`OperationGithubAppRegister`, `OperationGithubAppInspect`, `OperationGithubAppDelete`

**`internal/api/handlers_github_apps.go`** — four HTTP handlers:
- `POST /github-apps` — register
- `GET /github-apps` — list (no PEM in response)
- `GET /github-apps/{name}` — inspect (no PEM in response)
- `DELETE /github-apps/{name}` — remove

**`internal/api/server.go`** — added `githubAppStore` field, `SetGithubAppStore()` method, and four routes

**`api/plugin/v1/host.proto`** — added `GetGithubApp` RPC to `HostService`; regenerated `.pb.go` files

**`api/plugin/v1/plugin.proto`** — added `InitProvider` RPC to `CredentialVenderService` (backward-compat: Unimplemented = pre-UX-B plugin, treated as no-op); regenerated `.pb.go` files

**`internal/plugin/host_service.go`** — `GetGithubApp` RPC handler; `nil` store returns `HOST_NOT_FOUND`

**`internal/plugin/host.go`** — broker wiring: `GRPCBrokerMultiplex: true` on credential_vender client; start HostService broker for plugins that have a GithubAppStore; call `InitProvider` RPC after capability negotiation

**`cmd/dev/main.go`** — wired `SetGithubAppStore` + `GithubAppStore` in `HostServiceDeps`

**`cmd/server/main.go`** — wired `SetGithubAppStore` alongside `SetBindingStore` (OpenBao KV path)

### Plugin side (agentkms)

**`cmd/agentkms-plugin-github/main.go`** — full rewrite:
- Removed all YAML reading; emits deprecation warning if legacy file exists
- `InitProvider` RPC: dials HostService broker, stores `hostClient`
- `ensureApp(ctx, appName)`: 5-min TTL cache; fetches via `GetGithubApp` RPC on cache miss; calls `plugin.RegisterApp`
- `Vend`: extracts `app_name` from scope params, calls `ensureApp`, delegates to plugin

### Client side (kpm)

**`internal/kpm/client.go`** — added four methods: `RegisterGithubApp`, `ListGithubApps`, `GetGithubApp`, `RemoveGithubApp`

**`internal/kpm/ghapp.go`** — new file: `RunGhApp` dispatcher + `register/list/inspect/remove` subcommands; mirrors style of `cred.go`; `--private-key -` reads from stdin only (filesystem paths rejected)

**`cmd/kpm/main.go`** — added `gh-app` early-dispatch block (same pattern as `cred`); updated usage string

### Pro plugin (agentkms-pro)

**`api/plugin/v1/host.proto`** — mirrored `GetGithubApp` RPC + messages; regenerated

**`cmd/agentkms-plugin-orchestrator/main.go`** — fixed `RotateBinding` signature (`GetBindingRequest` → `RotateBindingRequest`) broken by proto regen

---

## Security Properties

- PEM bytes flow: KV store (encrypted at rest) → HostService `GetGithubApp` RPC (in-process broker) → plugin memory → GitHub API. Never in HTTP responses to external callers. Never in audit logs.
- `--private-key -` is the only accepted value; filesystem paths are rejected with a clear error.
- Legacy `github-apps.yaml`: plugin emits a deprecation warning and ignores the file. No data is read from it.

---

## Test Fixes (pre-existing test drift)

| File | Fix |
|------|-----|
| `internal/plugin/host_service_test.go` | 9 calls to `newHostServiceServer` lacked the new `githubAppStore` arg; added `nil` |
| `internal/plugin/orchestrator_health_loop_test.go` | `fakeOrchestratorClient.RotateBinding` used old `GetBindingRequest`/`TriggerRotationResponse`; updated to `RotateBindingRequest`/`RotateBindingResponse` |
| `agentkms-pro/cmd/agentkms-plugin-orchestrator/main_test.go` | 3 `RotateBinding` calls used `GetBindingRequest{Name:...}`; updated to `RotateBindingRequest{BindingName:...}` |

---

## Validation

```
agentkms:     go build ./... ✓   go vet ./... ✓   go test ./... ✓
agentkms-pro: go build ./... ✓   go vet ./... ✓   go test ./... ✓
kpm:          go build ./... ✓   go vet ./... ✓   go test ./... ✓
```

---

## Remaining / Out of Scope

- Tests for `internal/api/handlers_github_apps.go` (HTTP round-trip, audit events with PEM scrubbed) — post-ship
- Tests for `internal/githubapp/` (KV round-trip, List filtering) — post-ship
- Tests for github plugin (cache hit/miss, TTL refresh, YAML deprecation warning) — post-ship
- Slack/webhook notification on App registration events — v0.4
