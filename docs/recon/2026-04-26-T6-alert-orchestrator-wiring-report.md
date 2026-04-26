# T6 — AlertOrchestrator + RotationHook Wiring Report

**Date:** 2026-04-26
**Task:** Close the AlertOrchestrator + RotationHook wiring gap so webhook-triggered rotation works end-to-end for the T6 demo.
**Status:** Complete

---

## Problem Statement

After the T5 Part 2 fix (commit `c9dfb0a5`), the dev server discovered and Init'd the orchestrator plugin successfully, but the returned `*OrchestratorGRPC` adapter was discarded (`_ = orch`). Three things were missing:

1. `api.Server` had no `alertOrchestrator` field, no `SetAlertOrchestrator` method, no `SetRotationHook` method, and no registered route for the GitHub secret-scanning webhook.
2. `cmd/dev/main.go` did not construct an `AlertOrchestrator` and did not register the webhook HTTP handler.
3. `cmd/server/main.go` had the identical gap (production parity).

---

## Files Modified

### `internal/api/server.go`

**New field:**
```go
alertOrchestrator   *webhooks.AlertOrchestrator // nil until SetAlertOrchestrator is called
githubWebhookHandler *webhooks.GitHubWebhookHandler // nil until RegisterGitHubWebhookHandler is called
```

**New imports:** `log/slog`, `github.com/agentkms/agentkms/internal/webhooks`

**New methods on `api.Server`:**

- `SetAlertOrchestrator(orch *webhooks.AlertOrchestrator)` — stores the orchestrator for use by the webhook handler. Must be called before `RegisterGitHubWebhookHandler`.
- `SetRotationHook(hook webhooks.RotationHook)` — delegates to `s.alertOrchestrator.SetRotationHook(hook)`. If `alertOrchestrator` is nil, logs a WARN and returns (no-op, no panic).
- `RegisterGitHubWebhookHandler(webhookSecret string)` — constructs a `webhooks.GitHubWebhookHandler`, wires it to `s.alertOrchestrator` (if set), and registers it on the internal mux at `POST /webhooks/github/secret-scanning`. Route is registered without the `authMiddleware` chain — GitHub webhooks are authenticated by HMAC-SHA256 in the handler itself.

### `internal/webhooks/dev_audit_store.go` (NEW FILE)

An in-memory `AuditStore` implementation for dev and test use. Provides:
- `NewDevAuditStore()` — empty store.
- `Register(r CredentialRecord)` — seed records for the T6 demo or tests.
- `FindByTokenHash`, `UpdateInvalidatedAt` — implements the `AuditStore` interface with correct durable-store semantics (returns copies, not pointers to live slice elements).

This is used in both `cmd/dev/main.go` (dev mode) and `cmd/server/main.go` as a temporary store pending the T7 NDJSON-backed AuditStore implementation.

### `cmd/dev/main.go`

**New imports:** `github.com/agentkms/agentkms/internal/revocation`, `github.com/agentkms/agentkms/internal/webhooks`

**New flag:**
```
--webhook-secret  string  HMAC secret for GitHub secret-scanning webhooks
                          Also: AGENTKMS_WEBHOOK_SECRET env var
```

**New startup block (after apiServer construction):**
```go
alertOrch := webhooks.NewAlertOrchestrator(
    webhooks.NewDevAuditStore(),
    revocation.NewNoopRevoker(),
    auditor,
    webhooks.NewConsoleNotifier(),
)
apiServer.SetAlertOrchestrator(alertOrch)

if *webhookSecretFlag != "" {
    apiServer.RegisterGitHubWebhookHandler(*webhookSecretFlag)
    slog.Info("[webhook] GitHub secret-scanning handler registered", ...)
}
```

**Fixed `_ = orch` placeholder** in the orchestrator plugin discovery block:
```go
// Before (placeholder — no real wiring):
_ = orch

// After (real wiring):
rotationHook := pluginHost.RotationHookFor(orch)
apiServer.SetRotationHook(rotationHook)
slog.Info("[plugin] orchestrator registered as RotationHook")
```

**Ordering fix:** The orchestrator plugin discovery block was moved to AFTER `apiServer` construction and AlertOrchestrator wiring. Previously it ran before `apiServer` was defined, which would have caused a compile error once `apiServer.SetRotationHook` was added.

**New helper:** `envOrDev(key, fallback string) string` — local equivalent of `cmd/server/main.go`'s `envOr` helper (avoids a name collision).

### `cmd/server/main.go`

The production server had the identical gap. Fixed identically to the dev server:

**New imports:** `github.com/agentkms/agentkms/internal/revocation`, `github.com/agentkms/agentkms/internal/webhooks`

**New flag:** `--webhook-secret` / `AGENTKMS_WEBHOOK_SECRET`

**New startup block:** AlertOrchestrator construction with `ConsoleNotifier` + `NoopRevoker`, wired to `apiServer` via `SetAlertOrchestrator`. Webhook handler registered if `--webhook-secret` is set.

**Note on production TODO:** Two TODOs are left as inline comments in `cmd/server/main.go` for the T7 follow-on:
- Replace `webhooks.NewDevAuditStore()` with the NDJSON-backed AuditStore.
- Replace `revocation.NewNoopRevoker()` with `revocation.NewGitHubPATRevoker(...)` for live PAT revocation.

### `internal/api/server_test.go` (NEW FILE)

Five tests added in package `api_test`:

| Test | What it verifies |
|------|-----------------|
| `TestServer_SetRotationHook_NoAlertOrchestrator` | `SetRotationHook` with nil `alertOrchestrator` is a no-op (warns via slog, no panic). Server remains functional. |
| `TestServer_SetRotationHook_DelegatesToAlertOrchestrator` | After `SetAlertOrchestrator` + `SetRotationHook`, `ProcessAlert` on a live credential invokes the hook's `BindingForCredential`. Uses `supportsRevocationRevoker` to route to `LiveRevokedBranch` where hook dispatch occurs. |
| `TestServer_WebhookHandler_DispatchesToAlertOrchestrator` | POST to `/webhooks/github/secret-scanning` with valid HMAC signature causes `ProcessAlert` to be invoked (confirmed via store `FindByTokenHash` call count). Returns 2xx. |
| `TestServer_WebhookHandler_InvalidSignature_Returns401` | Invalid HMAC signature → 401. `ProcessAlert` not invoked. |
| `TestServer_WebhookHandler_NotRegistered_Returns404` | When `RegisterGitHubWebhookHandler` has not been called, the route does not exist. Non-200 response. |

---

## AlertOrchestrator Construction (Dev Mode Dependencies)

| Dependency | Dev choice | Rationale |
|-----------|------------|-----------|
| `AuditStore` | `webhooks.NewDevAuditStore()` | In-memory; pre-populated for T6 demo via `Register()`. Production uses NDJSON (T7). |
| `Revoker` | `revocation.NewNoopRevoker()` | No live credentials in dev. `SupportsRevocation() = false` routes to ManualRevokeBranch unless the Pro orchestrator hook takes over first. |
| `Auditor` | Same `auditor` used for all other server ops | Writes to `audit.ndjson` in dev dir. Forensic chain-of-custody maintained. |
| `Notifier` | `webhooks.NewConsoleNotifier()` | Logs structured lines to stderr. Slack integration is v0.4. |

---

## Webhook HTTP Handler Routing

Route: `POST /webhooks/github/secret-scanning`

Registered on `api.Server`'s internal mux WITHOUT the `authMiddleware` chain. GitHub webhooks are authenticated by HMAC-SHA256 in `GitHubWebhookHandler.ServeHTTP` (X-Hub-Signature-256 header), not by session tokens.

The route only exists after `RegisterGitHubWebhookHandler` is called. Without a `--webhook-secret` flag, the endpoint is not registered and requests return 404/405.

HMAC bypass / dev escape hatch: NOT added. Production code did not have a `?dev_skip_hmac=true` escape hatch, so none was added here. The demo uses a real HMAC secret.

---

## `pluginHost.RotationHookFor` — How the Adapter Is Exposed

`internal/plugin/host.go` already had `RotationHookFor(orchestrator *OrchestratorGRPC) webhooks.RotationHook` (added in T5 Part 2). This method wraps the `*OrchestratorGRPC` in an `orchestratorRotationHook` struct that implements `webhooks.RotationHook` by calling the gRPC RPCs `TriggerRotation` and `BindingForCredential`.

The dev server now calls:
```go
rotationHook := pluginHost.RotationHookFor(orch)
apiServer.SetRotationHook(rotationHook)
```

`apiServer.SetRotationHook` delegates to `alertOrch.SetRotationHook(hook)`.

---

## Whether `cmd/server/main.go` Had the Same Gap

**Yes, identical gap.** The production server did not construct `AlertOrchestrator`, did not register the webhook handler, and did not wire the orchestrator plugin's RotationHook. Fixed identically (same block structure, same dependency choices, same flag name, TODOs for T7 left inline).

---

## Final Test Output

```
go build ./...   — PASS (clean, no errors)
go vet ./...     — PASS (clean, no warnings)
go test ./...    — PASS (all packages pass, no regressions)
```

New tests (internal/api):
```
--- PASS: TestServer_SetRotationHook_NoAlertOrchestrator (0.00s)
--- PASS: TestServer_SetRotationHook_DelegatesToAlertOrchestrator (0.00s)
--- PASS: TestServer_WebhookHandler_DispatchesToAlertOrchestrator (0.00s)
--- PASS: TestServer_WebhookHandler_InvalidSignature_Returns401 (0.00s)
--- PASS: TestServer_WebhookHandler_NotRegistered_Returns404 (0.00s)
ok  github.com/agentkms/agentkms/internal/api  0.573s
```

---

## Expected Dev Server Startup Logs (Normal Path — Orchestrator Present)

With `--webhook-secret=<secret>` and orchestrator plugin binary in plugin dir:

```
[webhook] GitHub secret-scanning handler registered route=POST /webhooks/github/secret-scanning
[plugin] discovering plugins dir=<path>
[plugin] found: orchestrator path=<path>/agentkms-plugin-orchestrator
[plugin] orchestrator plugin loaded path=<path>/agentkms-plugin-orchestrator
[plugin] orchestrator registered as RotationHook
```

Without plugin (OSS-only path):

```
[webhook] GitHub secret-scanning handler registered route=POST /webhooks/github/secret-scanning
[plugin] no orchestrator plugin found — running OSS-only rotation path reason="plugin dir not present" dir=<path>
```

Without `--webhook-secret`:

```
[webhook] GitHub secret-scanning handler not registered (set --webhook-secret or AGENTKMS_WEBHOOK_SECRET to enable)
```

---

## BLOCKERS

None. All four wiring gaps are closed:

1. `api.Server` now has `SetAlertOrchestrator`, `SetRotationHook`, and `RegisterGitHubWebhookHandler`.
2. `cmd/dev/main.go` constructs `AlertOrchestrator`, wires it to `apiServer`, registers webhook handler, and replaces `_ = orch` with real `RotationHookFor` + `SetRotationHook`.
3. `cmd/server/main.go` wired identically.
4. `pluginHost.RotationHookFor` was already present in `internal/plugin/host.go` — no new adapter needed.
