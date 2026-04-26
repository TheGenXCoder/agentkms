# T5 Part 3 Cleanup Report — B3 + B5

**Date:** 2026-04-26  
**Sprint Day:** 3  
**Status:** Complete — both blockers resolved, all suites green

---

## Summary

Two blockers resolved: B3 (`binding_state` stored as synthetic tag) and B5 (no
`Ping` RPC on `OrchestratorService`). Both repos build, vet, and test clean.

---

## Phase A — B3: BindingState as proper struct field

### Files modified — agentkms (OSS)

**Modified:**
- `internal/credentials/binding/binding.go` — added `BindingState string \`json:"binding_state,omitempty"\`` to `BindingMetadata` with doc comment listing valid values.
- `internal/credentials/binding/binding_test.go` — added `TestJSONRoundTrip_BindingState` covering non-empty round-trip, omitempty when empty, and all three valid state values.
- `internal/plugin/host_service.go` — removed `setStateTag` helper; removed `state:` tag scan in `bindingToProto`; `SaveBindingMetadata` now writes directly to `binding.Metadata.BindingState`; `bindingToProto` reads directly from `b.Metadata.BindingState`; `matchesFilter` checks `b.Metadata.BindingState` directly (was accepting all states as TODO placeholder).
- `internal/plugin/host_service_test.go` — updated `TestHostService_SaveBindingMetadata_HappyPath` to assert BindingState in struct and absence of `state:` tags; added `TestHostService_SaveBindingMetadata_BindingStateRoundTrips` (struct→GetBinding proto field); added `TestHostService_SaveBindingMetadata_LegitimateStateTag_Preserved` (regression: `"state:approved"` tag passes through unchanged).
- `docs/specs/2026-04-25-T3-credential-binding-design.md` — added `binding_state` row to BindingMetadata field table; updated summary paragraph.

### Tests added (OSS)
| Test | File | Purpose |
|------|------|---------|
| `TestJSONRoundTrip_BindingState` | `binding_test.go` | JSON marshal/unmarshal round-trip; omitempty; all valid states |
| `TestHostService_SaveBindingMetadata_BindingStateRoundTrips` | `host_service_test.go` | SaveBindingMetadata → GetBinding binding_state proto field |
| `TestHostService_SaveBindingMetadata_LegitimateStateTag_Preserved` | `host_service_test.go` | Regression: user tag `"state:approved"` survives SaveBindingMetadata |

---

## Phase B — B5: Ping RPC on OrchestratorService

### Files modified — agentkms (OSS)

**Modified:**
- `api/plugin/v1/host.proto` — added `PingRequest` / `PingResponse` messages; added `Ping` RPC to `OrchestratorService` (first in service; documented as pre-Init-safe liveness probe).
- `api/plugin/v1/host.pb.go` — regenerated (protoc v7.34.1).
- `api/plugin/v1/host_grpc.pb.go` — regenerated (protoc-gen-go-grpc v1.6.1).
- `internal/plugin/host.go` — rewrote `orchestratorHealthLoop` to: accept `pluginv1.OrchestratorServiceClient` parameter; call `Ping` RPC with 5s timeout every tick; mirror `destinationHealthLoop` restart semantics (`orchestratorHealthErrorThreshold = 1`); wired into `StartOrchestrator` after Init success via `go h.orchestratorHealthLoop(name, entry, orchestrator.client)`.

**Created:**
- `internal/plugin/orchestrator_health_loop_test.go` — `fakeOrchestratorClient` stub; `testOrchestratorHealthLoopFast`; `TestOrchestratorHealthLoop_PingFailureTriggerRestart`; `TestOrchestratorHealthLoop_PingRecovery`.

### Files modified — agentkms-pro (Pro)

**Modified:**
- `api/plugin/v1/host.proto` — same `PingRequest` / `PingResponse` / `Ping` RPC addition (mirrored from OSS).
- `api/plugin/v1/host.pb.go` — regenerated.
- `api/plugin/v1/host_grpc.pb.go` — regenerated.
- `cmd/agentkms-plugin-orchestrator/main.go` — added `time` import; implemented `orchestratorServer.Ping` (trivial latency probe, works pre-Init, no `s.sm` dependency).
- `cmd/agentkms-plugin-orchestrator/main_test.go` — added `TestPing_ReturnsOK` and `TestPing_WorksPreInit`.
- `BLOCKERS.md` — marked B3 and B5 RESOLVED with date 2026-04-26 and commit anchor placeholder.

### Tests added (Pro)
| Test | File | Purpose |
|------|------|---------|
| `TestPing_ReturnsOK` | `main_test.go` | Returns HOST_OK with latency_ms >= 0 |
| `TestPing_WorksPreInit` | `main_test.go` | Works when `s.sm == nil` (pre-Init) |

### Tests added (OSS)
| Test | File | Purpose |
|------|------|---------|
| `TestOrchestratorHealthLoop_PingFailureTriggerRestart` | `orchestrator_health_loop_test.go` | Ping failure hits threshold → restart attempt → entry evicted on restart failure |
| `TestOrchestratorHealthLoop_PingRecovery` | `orchestrator_health_loop_test.go` | Healthy Ping keeps entry alive over multiple ticks |

---

## Final test output — agentkms (OSS)

```
?       github.com/agentkms/agentkms/api/plugin/v1      [no test files]
ok      github.com/agentkms/agentkms/cmd/agentkms-license       (cached)
ok      github.com/agentkms/agentkms/cmd/watchdog        (cached)
ok      github.com/agentkms/agentkms/internal/api        (cached)
ok      github.com/agentkms/agentkms/internal/audit      (cached)
ok      github.com/agentkms/agentkms/internal/auth       (cached)
ok      github.com/agentkms/agentkms/internal/backend    (cached)
ok      github.com/agentkms/agentkms/internal/credentials        (cached)
ok      github.com/agentkms/agentkms/internal/credentials/binding        (cached)
ok      github.com/agentkms/agentkms/internal/destination        (cached)
ok      github.com/agentkms/agentkms/internal/destination/ghsecret       (cached)
ok      github.com/agentkms/agentkms/internal/destination/noop   (cached)
ok      github.com/agentkms/agentkms/internal/dynsecrets/aws     (cached)
ok      github.com/agentkms/agentkms/internal/dynsecrets/github  (cached)
ok      github.com/agentkms/agentkms/internal/forensics  (cached)
ok      github.com/agentkms/agentkms/internal/hints      (cached)
ok      github.com/agentkms/agentkms/internal/honeytokens        (cached)
ok      github.com/agentkms/agentkms/internal/ingestion/github   (cached)
ok      github.com/agentkms/agentkms/internal/mcp        (cached)
ok      github.com/agentkms/agentkms/internal/plugin     15.052s
ok      github.com/agentkms/agentkms/internal/policy     (cached)
ok      github.com/agentkms/agentkms/internal/report     (cached)
ok      github.com/agentkms/agentkms/internal/revocation (cached)
ok      github.com/agentkms/agentkms/internal/ui (cached)
ok      github.com/agentkms/agentkms/internal/webhooks   (cached)
ok      github.com/agentkms/agentkms/pkg/keystore        (cached)
ok      github.com/agentkms/agentkms/pkg/tlsutil (cached)
```

## Final test output — agentkms-pro (Pro)

```
?       github.com/catalyst9ai/agentkms-pro/api/plugin/v1        [no test files]
ok      github.com/catalyst9ai/agentkms-pro/cmd/agentkms-plugin-orchestrator   0.302s
ok      github.com/catalyst9ai/agentkms-pro/internal/host        0.548s
ok      github.com/catalyst9ai/agentkms-pro/internal/license     (cached)
ok      github.com/catalyst9ai/agentkms-pro/internal/orchestrator        0.923s
```

---

## New blockers

None. No surprises.

---

## Notable decisions

1. **`orchestratorHealthLoop` was never called** — `StartOrchestrator` did not start the loop goroutine before this fix. Added the `go h.orchestratorHealthLoop(...)` call after Init returns.

2. **Restart semantics for orchestrator** — Mirrored `destinationHealthLoop` (`threshold=1`, attempt one restart, mark failed on restart failure). The production `orchestratorHealthLoop` now calls `StartOrchestrator` for restart, which re-runs the full startup sequence (signature check → dispense → Init → health loop). This is intentional — a restarted orchestrator must re-Init with a fresh broker ID.

3. **`matchesFilter` binding_state filter was a no-op** — The `TODO(T5)` comment in `matchesFilter` was accepting all states unconditionally. Now that the struct field exists, the filter works correctly.

4. **Proto field number stability** — `PingRequest` has no fields; `PingResponse` uses fields 1-3 (error_code, error_message, latency_ms). No existing field numbers were disturbed.
