# T5 Part 1 — RotationHook Implementation Report

**Date:** 2026-04-26
**Sprint:** Automated Rotation Sprint, Day 3 of 17
**Track:** OSS (public plugin API)
**Status:** Complete — all tests pass, no regressions

---

## Files Created

| File | Purpose |
|---|---|
| `internal/webhooks/rotation_hook.go` | New — `RotationHook` interface + `ErrNoBinding` sentinel |
| `internal/webhooks/orchestrator_test.go` | New — 5 hook-integration tests |
| `internal/webhooks/rotation_hook_test.go` | New — interface-shape + ErrNoBinding export tests |

## Files Modified

| File | Changes |
|---|---|
| `internal/webhooks/orchestrator.go` | Added `rotationHook RotationHook` field to `AlertOrchestrator`; added `SetRotationHook(hook RotationHook)` method; modified `handleLiveRevokedBranch` to implement T5 §3.3 dispatch logic |

---

## Tests Added

**`internal/webhooks/orchestrator_test.go`** — 5 tests:

| Test | What it covers |
|---|---|
| `TestAlertOrchestrator_NoHook_FallsBackToRevoker` | nil hook → revoker.Revoke called, audit event emitted, baseline behavior preserved |
| `TestAlertOrchestrator_HookManagedCredential_DelegatesToHook` | Hook with binding found → TriggerRotation called once, revoker.Revoke NOT called, no OSS audit event (hook owns audit chain) |
| `TestAlertOrchestrator_HookUnmanagedCredential_FallsBack` | Hook returns ErrNoBinding → TriggerRotation NOT called, revoker.Revoke called |
| `TestAlertOrchestrator_HookTriggerFails_FallsBack` | TriggerRotation returns error → revoker.Revoke called (safety property), OrchestratorError set |
| `TestSetRotationHook` | Replace hook A with hook B; A receives no additional calls after replacement, B is called for subsequent alerts |

**`internal/webhooks/rotation_hook_test.go`** — 2 tests:

| Test | What it covers |
|---|---|
| `TestRotationHook_InterfaceShape` | Compile-time assertion that any type satisfying both methods implements `RotationHook`; locks the interface contract |
| `TestErrNoBinding_IsExported` | `errors.Is(ErrNoBinding, ErrNoBinding)` works; wrapped errors match via errors.Is; distinct errors do not match |

**Total new tests: 7**

---

## Validation Output

```
go build ./...         → (no output — clean build)
go vet ./...           → (no output — clean vet)
go test ./internal/webhooks/... -v:

  TestGitHubWebhook_ParseAlert_ValidPayload           PASS
  TestGitHubWebhook_ParseAlert_InvalidSignature       PASS
  TestGitHubWebhook_ParseAlert_MalformedJSON          PASS
  TestGitHubWebhook_ParseAlert_MissingSecret          PASS
  TestGitHubWebhook_ParseAlert_TokenHashCorrect       PASS
  TestGitHubWebhook_ParseAlert_ExtractsRepository     PASS
  TestGitHubWebhook_ParseAlert_EmptySignatureHeader   PASS
  TestOrchestration_ExpiredCredential_AutoCloses      PASS
  TestOrchestration_ExpiredCredential_TagsDetectedAfterExpiry PASS
  TestOrchestration_ExpiredCredential_AuditEvent      PASS
  TestOrchestration_ExpiredCredential_NotifiesNoEscalation PASS
  TestOrchestration_LiveCredential_RevokesAtProvider  PASS
  TestOrchestration_LiveCredential_TagsRevokedOnDetection PASS
  TestOrchestration_LiveCredential_AuditEvent         PASS
  TestOrchestration_LiveCredential_Escalates          PASS
  TestOrchestration_NoRevoke_EmitsHighPriorityAlert   PASS
  TestOrchestration_NoRevoke_AuditEvent               PASS
  TestOrchestration_CredentialNotFound                PASS
  TestOrchestration_ProviderAPIDown                   PASS
  TestOrchestration_Idempotency_DuplicateAlert        PASS
  TestOrchestration_Idempotency_DurableStoreSemantics PASS
  TestOrchestration_HMACValidated_MalformedAlertBody  PASS
  TestWebhookHandler_EndToEnd                         PASS
  TestWebhookHandler_InvalidSignature_Rejected        PASS
  TestAlertOrchestrator_NoHook_FallsBackToRevoker     PASS
  TestAlertOrchestrator_HookManagedCredential_DelegatesToHook PASS
  TestAlertOrchestrator_HookUnmanagedCredential_FallsBack PASS
  TestAlertOrchestrator_HookTriggerFails_FallsBack    PASS
  TestSetRotationHook                                 PASS
  TestRotationHook_InterfaceShape                     PASS
  TestErrNoBinding_IsExported                         PASS

ok  github.com/agentkms/agentkms/internal/webhooks  0.435s

go test ./...          → all packages pass, zero regressions
```

---

## Hook Call vs. Revoker Fallback Ordering (T5 §3.3 / §5)

The exact dispatch order in `handleLiveRevokedBranch`, verified by tests:

```
1. if rotationHook != nil
   a. Call BindingForCredential(ctx, credentialUUID)
      - err == nil (binding found):
        i.  Call TriggerRotation(ctx, credentialUUID)
            - nil error: notify, return immediately.
              revoker.Revoke is NOT called.
              OSS audit event is NOT emitted (hook owns audit chain).
            - non-nil error: set OrchestratorError, FALL THROUGH to revoker.Revoke.
              Safety: broken hook must not leave credential unrevoked.
      - err != nil (ErrNoBinding or other): FALL THROUGH to revoker.Revoke.
        TriggerRotation is NOT called.

2. revoker.Revoke (existing OSS path, runs when):
   - rotationHook is nil, OR
   - BindingForCredential returned an error (no binding), OR
   - TriggerRotation returned an error (hook failed)
```

This matches T5 design §3.3 exactly. The one deliberate implementation choice
beyond the spec: when TriggerRotation fails, `OrchestratorError` is set on the
`AlertResult` so callers/tests can detect the failure mode, but the function
does not return a top-level error (consistent with existing OSS behavior where
provider errors are non-fatal and set `OrchestratorError`).

---

## OSS/Pro Boundary Compliance

- `rotation_hook.go` defines `RotationHook` and `ErrNoBinding` in package `webhooks` only — zero references to any Pro package, binary name, or license concept.
- `orchestrator.go` calls `o.rotationHook.BindingForCredential` and `o.rotationHook.TriggerRotation` only — no type assertions, no package imports beyond what already existed.
- Any third-party plugin can implement `RotationHook` and call `SetRotationHook` without any Catalyst9 Pro dependency.

---

## Thread Safety Note

`SetRotationHook` is documented as a startup-time, single-writer call (consistent with the existing orchestrator's single-writer pattern — no `sync.RWMutex` exists on the struct). No mutex was added. This matches the existing concurrent-access model in `orchestrator.go`. If the startup-race window identified in T5 §6 OQ-T5-8 ever needs addressing, a mutex can be added to `SetRotationHook`/`handleLiveRevokedBranch` without any interface changes.

---

## Blockers

None. T5 Part 1 is complete. The Pro orchestrator plugin can now:
1. Import `internal/webhooks` (or the public Go module path).
2. Implement `RotationHook`.
3. Call `alertOrchestrator.SetRotationHook(impl)` at plugin startup.

The OSS server will delegate `LiveRevokedBranch` for managed credentials to the Pro hook from that point forward.
