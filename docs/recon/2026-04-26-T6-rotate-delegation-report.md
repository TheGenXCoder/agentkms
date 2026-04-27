# T6 — Rotate Handler Orchestrator Delegation Report

**Date:** 2026-04-26
**Task:** Wire `POST /bindings/{name}/rotate` to delegate to the Pro orchestrator's `RotateBinding` state machine when a `RotationHook` is registered. Previously the handler always took the OSS stub path even with the Pro orchestrator loaded.
**Status:** Complete — both repos build/vet/test green, no commits made.

---

## Problem Statement

The T6 demo showed that `POST /bindings/{name}/rotate` always emitted `binding_rotate_stub` and returned a stub credential, even when:

- The Pro rotation orchestrator plugin was loaded and `Init`'d
- The GitHub provider plugin was loaded
- The `gh-secret` destination plugin was loaded

The handler (`internal/api/handlers_bindings.go` → `handleRotateBinding`) had no code path to check for a registered `RotationHook`. It unconditionally proceeded to the OSS Vender path, which stubs out any provider not in the built-in LLM provider list.

---

## Root Cause

`handleRotateBinding` was written before `RotationHook` existed (T3 era). The T5 Part 1 work added the `RotationHook` interface and wired it for webhook-triggered rotation, but `handleRotateBinding` was not updated to use it for the `POST /rotate` endpoint.

T5 §3.4 design doc stated: "The `POST /bindings/{name}/rotate` endpoint works in both OSS and Pro configurations without code branching in the handler itself — the handler calls a single `RotateBinding(ctx, name)` function whose implementation is swapped at runtime." This contract was not yet implemented.

---

## Design Decision: New `RotateBinding` RPC

The `RotationHook` interface (and the corresponding `OrchestratorService` gRPC service) only had `TriggerRotation` (emergency rotation for a credential UUID) and `BindingForCredential` (UUID → binding name lookup). Neither was suitable for the manual rotate endpoint, which works by binding name and requires the full synchronous 8-step state machine.

**Option chosen (a):** Add `RotateBinding(ctx, name) error` to `RotationHook` and a corresponding `RotateBinding` RPC to `OrchestratorService`.

This is a clean additive extension. The Pro orchestrator's `StateMachine.RotateBinding` already implemented the 8-step lifecycle; it just needed to be exposed over gRPC.

**Proto regen strategy:** `protoc` is not available in this environment. The `_grpc.pb.go` files were hand-extended, reusing existing message types:
- Request: `GetBindingRequest` (already has a `Name string` field)
- Response: `TriggerRotationResponse` (already has an `ErrorMessage string` field)

This avoids regeneration while maintaining wire compatibility. The generated proto stubs (`host.pb.go`) did not need modification because no new message types were introduced.

---

## Files Modified

### `api/plugin/v1/host.proto` (OSS + Pro, identical)

Added `RotateBinding` RPC to `OrchestratorService`:

```proto
rpc RotateBinding(GetBindingRequest) returns (TriggerRotationResponse);
```

### `api/plugin/v1/host_grpc.pb.go` (OSS + Pro, identical)

Hand-extended to add:
- `OrchestratorService_RotateBinding_FullMethodName` constant
- `RotateBinding` method on `OrchestratorServiceClient` interface and `orchestratorServiceClient` impl
- `RotateBinding` method on `OrchestratorServiceServer` interface and `UnimplementedOrchestratorServiceServer`
- `_OrchestratorService_RotateBinding_Handler` server handler function
- `RotateBinding` entry in `OrchestratorService_ServiceDesc.Methods` slice

### `internal/webhooks/rotation_hook.go` (OSS)

Extended `RotationHook` interface with:

```go
// RotateBinding executes a synchronous full rotation for the named binding.
// Implements the T6 §3.4 manual-rotate entry point. Returns nil on success
// (including degraded state); non-nil on fatal failure.
RotateBinding(ctx context.Context, bindingName string) error
```

### `internal/webhooks/orchestrator.go` (OSS)

Added `RotationHook()` getter on `AlertOrchestrator` so `handleRotateBinding` can access the hook without reaching into unexported fields:

```go
func (o *AlertOrchestrator) RotationHook() RotationHook {
    return o.rotationHook
}
```

### `internal/plugin/host.go` (OSS)

Added `RotateBinding` to `orchestratorRotationHook` (the gRPC adapter that wraps `OrchestratorServiceClient`):

```go
func (h *orchestratorRotationHook) RotateBinding(ctx context.Context, bindingName string) error {
    resp, err := h.client.client.RotateBinding(ctx, &pluginv1.GetBindingRequest{Name: bindingName})
    if err != nil {
        return fmt.Errorf("orchestrator RotateBinding RPC: %w", err)
    }
    if msg := resp.GetErrorMessage(); msg != "" {
        return fmt.Errorf("orchestrator RotateBinding: %s", msg)
    }
    return nil
}
```

### `internal/api/handlers_bindings.go` (OSS) — PRIMARY CHANGE

Added orchestrator delegation block in `handleRotateBinding`, inserted between the policy-gate check and the OSS stub path. The block is a pure early-return prefix; the existing OSS stub path is unchanged.

Key behavior:
- When `alertOrchestrator != nil` and its `RotationHook()` returns non-nil: delegate to `hook.RotateBinding(ctx, name)`.
- On success: emit `binding_rotate` audit with `OutcomeSuccess`, re-read binding metadata from store (the orchestrator persists `LastGeneration` and `LastRotatedAt` via `SaveBindingMetadata`), return 200 with updated generation.
- On error: emit `binding_rotate` audit with `OutcomeError`, return 500.
- When no orchestrator is wired (OSS-only deployment): fall through to the existing stub/Vender path unchanged.

### `cmd/agentkms-plugin-orchestrator/main.go` (Pro)

Added `RotateBinding` RPC handler on `orchestratorServer`:

- Returns `errNotInitialized` message when `sm == nil`.
- Returns descriptive error when `binding_name` is empty.
- Calls `s.sm.RotateBinding(ctx, bindingName)` and maps errors to `ErrorMessage` field.

---

## Test Changes

### `internal/api/server_test.go` (OSS)

Added `RotateBinding` method + `rotateCalls []string` + `rotateErr error` fields to `stubRotationHook` to satisfy the updated `RotationHook` interface.

### `internal/webhooks/rotation_hook_test.go` (OSS)

Added `RotateBinding` to `testHookImpl` (the interface compliance canary).

### `internal/webhooks/orchestrator_test.go` (OSS)

Added `RotateBinding` to `fakeRotationHook` (returns nil; not exercised by the webhook alert flow).

### `internal/plugin/orchestrator_health_loop_test.go` (OSS)

Added `RotateBinding` to `fakeOrchestratorClient` (the health-loop test double for `OrchestratorServiceClient`).

### `internal/api/handlers_bindings_test.go` (OSS) — NEW TESTS

Added two tests covering the orchestrator delegation path:

**`TestHandleRotateBinding_OrchestratorDelegation`**
- Wires an `AlertOrchestrator` + `stubRotationHook` onto the test server.
- Calls `POST /bindings/{name}/rotate`.
- Asserts: HTTP 200, `hook.RotateBinding` called with the correct binding name, `binding_rotate` audit event with `OutcomeSuccess` emitted, no `binding_rotate_stub` audit event.

**`TestHandleRotateBinding_OrchestratorDelegation_HookError`**
- Same setup but `stubRotationHook.rotateErr = context.DeadlineExceeded`.
- Asserts: HTTP 500, `binding_rotate` audit event with `OutcomeError` emitted.

### `cmd/agentkms-plugin-orchestrator/main_test.go` (Pro) — NEW TESTS

Added three tests for the `RotateBinding` RPC handler:

**`TestOrchestratorServer_RotateBinding_Uninitialized`** — pre-Init path returns `errNotInitialized`.

**`TestOrchestratorServer_RotateBinding_EmptyName`** — empty binding name returns descriptive error after Init.

**`TestOrchestratorServer_RotateBinding_AfterInit_UnknownBinding`** — post-Init call with unknown binding returns a non-empty, non-"not-initialized" error.

---

## Test Results

```
OSS:  go test ./...  — all packages ok
OSS:  go vet ./...   — clean
Pro:  go test ./...  — all packages ok
Pro:  go vet ./...   — clean
```

---

## Architectural Notes

### Stub path preserved

The OSS stub/direct-delivery path (`binding_rotate_stub` audit + Vender + destination delivery) is completely unchanged. It fires if and only if `alertOrchestrator == nil` OR `alertOrchestrator.RotationHook() == nil`. This means:

- OSS-only deployments: stub path always taken (no regression).
- Pro deployments after orchestrator Init: delegation path taken.
- Pro deployments before orchestrator Init (plugin startup failure): hook is nil → stub path taken (safe degradation).

### Audit ownership

The handler emits exactly one `binding_rotate` audit event regardless of path. In the orchestrator path, the orchestrator's own `StateMachine.RotateBinding` emits additional internal events (`binding_rotate_start`, per-destination `destination_deliver`) via `HostService.EmitAudit`. The handler's single event serves as the API-layer policy-gate record.

### Metadata re-read

After successful orchestrator delegation, the handler re-reads the binding from the store to surface the `LastGeneration` and `LastRotatedAt` values the orchestrator persisted. If the re-read fails (e.g., transient store error), the handler falls back to `b.Metadata.LastGeneration + 1` and the current time — graceful degradation, not a 500.

### Per-binding deduplication

`StateMachine.RotateBinding` acquires a `singleflight.Group` key on the binding name, so concurrent `POST /rotate` requests for the same binding are serialized (only the first issues a vend; subsequent callers receive the same result). This is transparent to the handler.
