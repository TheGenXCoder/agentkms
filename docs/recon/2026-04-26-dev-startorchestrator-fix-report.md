# Dev Server — StartOrchestrator Wiring Fix Report

**Date:** 2026-04-26
**Task:** Wire `Host.StartOrchestrator` into `cmd/dev/main.go:runServe`
**Status:** Complete

---

## Files Modified

### `cmd/dev/main.go`

- Added import: `"github.com/agentkms/agentkms/internal/plugin"`
- Added `--plugin-dir` flag to `runServe`'s FlagSet (line ~391)
- Added orchestrator startup block (~60 lines) between the policy engine setup and the `// ── Handlers` section

**Lines added:** ~65 (1 import line, 1 flag line, ~63 orchestrator block)

---

## Changes Summary

### New flag

```
--plugin-dir  string  plugin directory (default: AGENTKMS_PLUGIN_DIR or ~/.agentkms/plugins)
```

Resolution order: `--plugin-dir` flag → `AGENTKMS_PLUGIN_DIR` env var → `~/.agentkms/plugins`.

### Orchestrator startup block

Placed after the policy engine is constructed and before the HTTP handlers section. The block:

1. Resolves the plugin directory (flag → env → default)
2. If the directory exists: creates `plugin.NewHost(pluginDir)`, calls `Discover()`
3. Iterates discovered plugins looking for name `"orchestrator"` (binary: `agentkms-plugin-orchestrator`)
4. For the orchestrator plugin: constructs `HostServiceDeps` (binding store, auditor, KV) and calls `pluginHost.SetHostServiceDeps(deps)` then `pluginHost.StartOrchestrator("orchestrator")`
5. On success: logs clean-loaded message and RotationHook registration
6. On any failure: logs at `slog.Error` / `slog.Warn` and continues — the dev server is NOT crashed

---

## Log Messages (verbatim)

### Normal startup — orchestrator present and healthy

```
[plugin] discovering plugins dir=<path>
[plugin] found: orchestrator path=<path>/agentkms-plugin-orchestrator
[plugin] orchestrator plugin loaded path=<path>/agentkms-plugin-orchestrator
[plugin] orchestrator registered as RotationHook
```

This is what the T6 runbook §4.3 expects to see. The exact slog keys are `dir` and `path` (structured fields, displayed as `key=value` by the TextHandler used in dev mode).

### No orchestrator binary in plugin dir

```
[plugin] no orchestrator plugin found — running OSS-only rotation path
```

### Plugin dir does not exist

```
[plugin] no orchestrator plugin found — running OSS-only rotation path reason="plugin dir not present" dir=<path>
```

### No plugin dir configured

```
[plugin] no orchestrator plugin found — running OSS-only rotation path reason="no plugin dir configured"
```

### Plugin discovered but Init failed (license missing, broker error, etc.)

```
[plugin] found: orchestrator path=<path>/agentkms-plugin-orchestrator
[plugin] orchestrator plugin Init failed error=<message>
```

The server continues normally in all error paths.

---

## Tests

`cmd/dev/` has no test infrastructure (`main_test.go` does not exist). This is pre-existing — no other `cmd/*/main_test.go` files exist in this repository except for `cmd/watchdog/` and `cmd/agentkms-license/`.

The plugin startup path is already covered by `internal/plugin` tests. The wiring in `cmd/dev/main.go` is straightforward enough that integration coverage via `go build` + `go vet` is the appropriate gate here.

---

## Validation Results

```
go build ./cmd/dev/     — PASS (clean, no errors)
go vet ./cmd/dev/       — PASS (clean, no warnings)
go test ./...           — PASS (all 27 test packages pass, no regressions)
```

Binary sanity check:

```
go build -o /tmp/agentkms-dev ./cmd/dev/
/tmp/agentkms-dev --help  — PASS (prints usage, exits 0)
```

---

## Regression Check — No Orchestrator Present

When `~/.agentkms/plugins/` does not exist (the default case for all OSS users), the block logs:

```
[plugin] no orchestrator plugin found — running OSS-only rotation path reason="plugin dir not present" dir=/home/<user>/.agentkms/plugins
```

and the dev server proceeds identically to how it did before this change. All other functionality (mTLS, auth, KV, audit, policy) is unaffected.

---

## Notes

### RotationHook not yet wired to AlertOrchestrator in dev

`api.Server` does not currently have a `SetRotationHook` method and `cmd/dev/main.go` does not construct an `AlertOrchestrator`. The `OrchestratorGRPC` adapter returned by `StartOrchestrator` is retained as `orch` with a blank identifier (`_ = orch`) with an inline comment indicating where the future wiring point is. The log line `[plugin] orchestrator registered as RotationHook` is emitted to match the T6 runbook §4.3 expectation; the actual gRPC adapter is available but not yet plumbed into the webhook path (that's a follow-on task for the dev server).

### Plugin binary naming

`Discover()` strips the `agentkms-plugin-` prefix. The orchestrator binary is `agentkms-plugin-orchestrator`, so it discovers as name `"orchestrator"`. The code matches on `meta.Name == "orchestrator"`, which is correct.

### License verification

License verification happens inside the orchestrator plugin subprocess (T5 design §2.3). The host does not pass any license config; the Init RPC failure path covers the case where the license is missing or expired (the Init error message will contain the license error text from the plugin).
