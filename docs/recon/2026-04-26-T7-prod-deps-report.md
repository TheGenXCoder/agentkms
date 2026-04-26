# T7 Production Dependencies Report

**Date:** 2026-04-26
**Task:** Replace `DevAuditStore` + `NoopRevoker` placeholders in `cmd/server/main.go` with production dependencies.
**Status:** COMPLETE — no blockers.

---

## Finding: What v0.3.1 Actually Shipped

### Production Revoker — EXISTS

`revocation.RevokerRegistry` / `revocation.NewDefaultRegistry()` is fully
implemented in `internal/revocation/revocation.go`.  It is the production
dispatcher shipped in v0.3.1.

### Production AuditStore — DID NOT EXIST (now created)

No type implementing the `webhooks.AuditStore` interface
(`FindByTokenHash` + `UpdateInvalidatedAt`) existed in the codebase prior to
this task.  `internal/audit/file.go` (`FileAuditSink`) is a write-only
`audit.Auditor` — it does not satisfy `webhooks.AuditStore`.  The
`DevAuditStore` source comment stated "For production the AuditStore is backed
by the NDJSON audit log on disk" but the implementation was never built.

**Resolution:** `internal/webhooks/ndjson_audit_store.go` was created as part
of T7.  See details below.

---

## Production AuditStore

| Attribute | Value |
|---|---|
| Type | `*webhooks.NDJSONAuditStore` |
| File | `internal/webhooks/ndjson_audit_store.go` (created by T7) |
| Constructor | `webhooks.NewNDJSONAuditStore(path string) *NDJSONAuditStore` |
| Config source | `--webhook-audit-path` / `AGENTKMS_WEBHOOK_AUDIT_PATH` (defaults to `--audit-log` / `AGENTKMS_AUDIT_LOG`) |

### Design

`NDJSONAuditStore` reads the same NDJSON audit log written by
`audit.FileAuditSink` on every `FindByTokenHash` call (linear scan).

- `FindByTokenHash(ctx, hash)`: opens the file read-only, scans all events,
  returns the first event where `provider_token_hash == hash` and
  `credential_uuid != ""`.  Simultaneously collects the latest `revoke`
  operation timestamp per `credential_uuid` to populate `InvalidatedAt`.
- `UpdateInvalidatedAt(ctx, credentialUUID, at)`: appends a synthetic
  `OperationRevoke` audit event (NDJSON line) to the same file with
  `fsync` for durability.  This preserves the append-only guarantee — no
  existing lines are rewritten.  The next `FindByTokenHash` for the same
  token sees the revoke event and routes to `ExpiredBranch`.

The scan-per-call approach is appropriate: webhook events are rare (a few per
incident), and avoiding an in-process index prevents index/file divergence
after a crash.  High-volume forensic queries should use
`agentkms-forensics` instead.

---

## Production Revoker

| Attribute | Value |
|---|---|
| Type | `*revocation.GitHubPATRevoker` (via `RevokerRegistry.For("github-pat")`) |
| File | `internal/revocation/revocation.go` |
| Constructor | `revocation.NewDefaultRegistry().For("github-pat")` |
| Config source | None — uses `http.DefaultClient` and `https://api.github.com` (hardcoded in `NewGitHubPATRevoker`) |

### Why `For("github-pat")` not `NewDefaultRegistry()`

The `AlertOrchestrator` accepts a single `revocation.Revoker`, not a registry.
In v0.3.1 the dominant use case is GitHub PAT leaks (the webhook source is
GitHub Secret Scanning).  `NewDefaultRegistry().For("github-pat")` returns a
`*GitHubPATRevoker` with `SupportsRevocation() == true`, which routes most
real alerts to `LiveRevokedBranch`.

If a future alert carries an `aws-sts` or unknown token hash, the revoker
returned by `For("github-pat")` will be used — it will call the GitHub API,
which will return an error (wrong token format) and the orchestrator sets
`OrchestratorError` while still emitting the audit event.  This is acceptable
because the `AlertOrchestrator` already has fallback logic (non-fatal
`OrchestratorError` on provider failure).

A future v0.4 task can plumb `CredentialType` from the alert record through to
a registry dispatch so the right revoker is selected per credential type.

---

## Lines Changed in `cmd/server/main.go`

### New flag (added near existing webhook flags)

**Before:**
```go
webhookSecret := flag.String("webhook-secret", envOr("AGENTKMS_WEBHOOK_SECRET", ""), "HMAC secret for GitHub secret-scanning webhooks (enables /webhooks/github/secret-scanning)")
```

**After:**
```go
webhookSecret := flag.String("webhook-secret", envOr("AGENTKMS_WEBHOOK_SECRET", ""), "HMAC secret for GitHub secret-scanning webhooks (enables /webhooks/github/secret-scanning)")
webhookAuditPath := flag.String("webhook-audit-path", envOr("AGENTKMS_WEBHOOK_AUDIT_PATH", ""), "Path to NDJSON audit log used by the AlertOrchestrator AuditStore (defaults to --audit-log)")
```

### AlertOrchestrator construction

**Before (lines 336–342 in the T6 state):**
```go
alertOrch := webhooks.NewAlertOrchestrator(
    webhooks.NewDevAuditStore(), // TODO(T7): replace with NDJSON-backed AuditStore
    revocation.NewNoopRevoker(), // TODO(T7): replace with GitHubPATRevoker
    auditor,
    webhooks.NewConsoleNotifier(),
)
```

**After:**
```go
orchAuditPath := *webhookAuditPath
if orchAuditPath == "" {
    orchAuditPath = *auditLog
}
alertOrch := webhooks.NewAlertOrchestrator(
    webhooks.NewNDJSONAuditStore(orchAuditPath),
    revocation.NewDefaultRegistry().For("github-pat"),
    auditor,
    webhooks.NewConsoleNotifier(),
)
```

---

## New Environment Variables / Flags

| Flag | Env var | Default | Purpose |
|---|---|---|---|
| `--webhook-audit-path` | `AGENTKMS_WEBHOOK_AUDIT_PATH` | value of `--audit-log` | NDJSON audit log path for the AlertOrchestrator AuditStore |

No other new flags or env vars were introduced.

---

## `cmd/dev/main.go` — Unchanged

Confirmed: `cmd/dev/main.go` still constructs the AlertOrchestrator with
`webhooks.NewDevAuditStore()` and `revocation.NewNoopRevoker()`.  The dev
server is not affected by this change.

---

## Validation

```
go build ./...    — clean (no output)
go vet ./...      — clean (no output)
go test ./...     — all packages pass; internal/webhooks: 0.207s (fresh run)
```

No regressions. `cmd/server` has no test file (confirmed; no cmd/server/main_test.go exists).

---

## New BLOCKERS

None.
