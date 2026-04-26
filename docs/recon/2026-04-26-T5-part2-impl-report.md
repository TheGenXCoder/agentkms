# T5 Part 2 Implementation Report — OSS HostService gRPC Callback Server

**Date:** 2026-04-26  
**Sprint day:** 3 of 17  
**Author:** implementation subagent

---

## What was built

OSS-side HostService: the gRPC callback server that the Pro rotation orchestrator
calls back into during rotation, plus orchestrator loading support in the plugin
host infrastructure.

### Files added or modified in `agentkms`

| File | Type | Summary |
|---|---|---|
| `api/plugin/v1/host.proto` | Modified | Added `OrchestratorService` service with `Init`, `TriggerRotation`, `BindingForCredential` RPCs and all request/response messages |
| `api/plugin/v1/host.pb.go` | Generated | Regenerated from updated proto |
| `api/plugin/v1/host_grpc.pb.go` | Generated | Regenerated from updated proto |
| `internal/audit/events.go` | Modified | Added `OperationBindingRotateStart` and `OperationDestinationDeliver` constants |
| `internal/plugin/host_service.go` | New | Full `hostServiceServer` implementing all 11 HostService RPCs |
| `internal/plugin/host_service_test.go` | New | 19 unit tests, all passing |
| `internal/plugin/host.go` | Modified | Added `HostServiceDeps`, `SetHostServiceDeps`, `StartOrchestrator`, `RotationHookFor`, `orchestratorRotationHook` |
| `internal/plugin/plugins.go` | Modified | Added `OrchestratorPlugin` to the plugin map, `OrchestratorGRPC` struct |

---

## Design decisions

**HC-1 — Patch-only SaveBindingMetadata:**  
`SaveBindingMetadata` accepts a 4-field `BindingMetadataPatch` (LastGeneration,
LastRotatedAt, BindingState, LastCredentialUuid) rather than a full Binding
replacement. A read-modify-write under per-binding mutex enforces that
`patch.LastGeneration > stored.LastGeneration` (rejects regression).

**HC-2 — Audit firewall:**  
`EmitAudit` calls `AuditEvent.Validate()` server-side before writing. Key
material in `CredentialValue` fields causes an immediate `HOST_PERMANENT` error.

**HC-3 — ListBindings pagination:**  
Default page size 50, max 200. Page token is an opaque base-10 offset string.

**HC-4 — VendCredential does not auto-emit audit:**  
The orchestrator is responsible for emitting its own `binding_rotate_start` and
`binding_rotate` audit events. The host does not emit `OperationCredentialVend`
from `VendCredential`.

**HC-5 — Fail-closed on connection loss:**  
`Dial` in `host.Client` is fail-fast. A `HOST_TRANSIENT` error from
`DeliverToDestination` triggers retry with exponential backoff; a `HOST_TRANSIENT`
error from other calls propagates to the state machine which aborts the rotation.

**HC-6 — No ready channel:**  
The ~1s startup race between `AcceptAndServe` and the host's `Init` RPC call
is accepted. No coordination channel is needed at this scale.

---

## Known limitations

- `RevokeCredential` uses O(N) vender scan (no UUID→provider index). See
  BLOCKERS.md B2.
- `binding_state` is stored as a `"state:<value>"` tag until T5 Part 3 adds the
  field to `CredentialBinding`. See BLOCKERS.md B3.
- Distributed lock not implemented (single-node only). See BLOCKERS.md B4.

---

## Test results

```
ok  github.com/agentkms/agentkms/internal/plugin   14.574s
```

19 tests, all passing.
