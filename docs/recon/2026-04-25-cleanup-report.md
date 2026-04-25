# Cleanup Report — Day-1 Sprint Review Fixes

**Date:** 2026-04-25
**Scope:** Three fixes addressing MUST-FIX and SHOULD-FIX items from `2026-04-25-review-report.md`.
**Status:** All fixes applied, all tests green, no regressions.

---

## Fix 1 (MUST-FIX) — Validate timeout on StartDestination

### Files Modified

**`internal/plugin/host.go`**

- Replaced the uncapped `adapter.Validate(ctx, nil)` call (where `ctx` had no deadline) with a dedicated `validateCtx, validateCancel := context.WithTimeout(ctx, 10*time.Second)` / `defer validateCancel()` pair.
- The validate context is strictly local to the startup Validate call and does not propagate to other startup steps (Kind, Capabilities, registry, etc.).
- The production `ctx` (which drives subprocess lifecycle cancellation) is unchanged.

**`internal/destination/testdata/slow-validate-deliverer/main.go`** (new file)

- New test binary that implements `DestinationDelivererService` with a `Validate` that blocks forever until its context deadline fires.
- Pre-built binary committed at: `internal/destination/testdata/slow-validate-deliverer/agentkms-plugin-slow-validate`

### Tests Added

**`internal/plugin/destination_host_test.go`** — `TestDestinationHost_ValidateTimeout`

- Sets up a Host with the slow-validate binary.
- Calls `StartDestination("slow-validate")` and measures elapsed time.
- Asserts: (a) an error is returned (Validate fails), (b) elapsed time < 11 seconds (timeout fires, call does not hang), (c) the deliverer is NOT registered after failed startup.
- Observed runtime: ~10.27 seconds (deadline fires at exactly 10 s).

---

## Fix 2 (SHOULD-FIX) — Destination health loop restart semantics

### Files Modified

**`internal/plugin/host.go`**

Three changes in this file:

1. **Constant**: Added `destinationHealthErrorThreshold = 1` matching the provider `healthLoop` pattern (one failure → restart attempt → if restart fails, mark failed).

2. **Interface widening**: Changed `destinationHealthLoop` parameter from `*destination.DestinationDelivererGRPC` (concrete type) to `destination.DestinationDeliverer` (interface). This has no effect on production behaviour because `*DestinationDelivererGRPC` satisfies the interface; it enables mock injection in tests without forking a subprocess.

3. **Restart trigger**: Added threshold check inside the Health() failure branch. After `destinationHealthErrorThreshold` consecutive Health() failures: kill the subprocess, attempt one `StartDestination`; if that fails, remove the entry from `h.clients` (mark failed). This exactly mirrors the provider `healthLoop` pattern.

### Tests Added

**`internal/plugin/destination_host_test.go`** — two additions:

- `controllableDeliverer` struct: in-test `DestinationDeliverer` mock with an atomic `healthFail` toggle and call counter.
- `testDestinationHealthLoopFast(h, name, entry, adapter)`: test-only variant of `destinationHealthLoop` using a 200 ms ticker (instead of 30 s) and a 2-second Health context timeout. Mirrors the production logic exactly, only the intervals differ.
- `TestDestinationHealthLoop_HealthFailureTriggerRestart`: Starts the real noop subprocess (to get a live `pluginEntry` with a working gRPC client for ping), then drives `testDestinationHealthLoopFast` with a `controllableDeliverer` that always fails Health(). Asserts the loop exits within 5 seconds and that Health() was called at least `destinationHealthErrorThreshold` times.

---

## Fix 3 (SHOULD-FIX) — Audit marker on provider stub path

### Files Modified

**`internal/audit/events.go`**

- Added `OperationBindingRotateStub = "binding_rotate_stub"` constant with doc comment explaining its purpose: marks rotations where the stub credential path was taken because no provider plugin was available for the binding's `provider_kind`.

**`internal/api/handlers_bindings.go`**

- In the stub credential branch (`if credentialUUID == ""`), after generating the stub UUID and value, emit a second audit event with `Operation = audit.OperationBindingRotateStub`.
- The stub event carries: `KeyID` (same as the rotation event), `CallerID`/`TeamID`/`CertFingerprint` from identity, `RuleID` from the policy decision, `Outcome = success`, and `ErrorDetail = "provider plugin not available; stub credential used for provider_kind=<kind>"`.
- The primary `OperationBindingRotate` event is still emitted at the end of the handler unchanged.

Approach rationale: a separate constant (rather than a field/tag on the existing event) was chosen because it enables `grep`/`filter` on `operation = binding_rotate_stub` in any audit sink without query-time field parsing, matching the existing audit constant conventions in the codebase.

**`internal/api/handlers_bindings_test.go`**

- Added `TestHandleRotateBinding_StubPathAuditMarker`: registers a binding with `provider_kind = "github-app-token"` (not in Vender's supported LLM list), rotates it, then scans the captured audit events for `OperationBindingRotateStub`. Asserts the stub event has correct `KeyID`, `Outcome`, and non-empty `ErrorDetail`.
- Added `operationNames(events []audit.AuditEvent) []string` helper for test failure messages.
- Added `_ = audit.OperationBindingRotateStub` to the compile-check block.

---

## Verification Output

### go build ./...

```
(no output — clean build)
```

### go vet ./...

```
(no output — no issues)
```

### go test ./... -timeout 120s

```
?       github.com/agentkms/agentkms/api/plugin/v1      [no test files]
?       github.com/agentkms/agentkms/cmd/cli             [no test files]
?       github.com/agentkms/agentkms/cmd/dev             [no test files]
?       github.com/agentkms/agentkms/cmd/disk            [no test files]
?       github.com/agentkms/agentkms/cmd/enroll          [no test files]
?       github.com/agentkms/agentkms/cmd/mcp             [no test files]
?       github.com/agentkms/agentkms/cmd/server          [no test files]
ok      github.com/agentkms/agentkms/cmd/watchdog                          0.718s
ok      github.com/agentkms/agentkms/internal/api                          1.511s
ok      github.com/agentkms/agentkms/internal/audit                        0.820s
ok      github.com/agentkms/agentkms/internal/auth                         1.952s
ok      github.com/agentkms/agentkms/internal/backend                      1.741s
ok      github.com/agentkms/agentkms/internal/credentials                  2.251s
ok      github.com/agentkms/agentkms/internal/credentials/binding          1.872s
ok      github.com/agentkms/agentkms/internal/destination                  2.620s
ok      github.com/agentkms/agentkms/internal/destination/noop             2.304s
ok      github.com/agentkms/agentkms/internal/dynsecrets/aws               0.945s
ok      github.com/agentkms/agentkms/internal/dynsecrets/github            2.384s
ok      github.com/agentkms/agentkms/internal/forensics                    1.475s
ok      github.com/agentkms/agentkms/internal/hints                        2.688s
ok      github.com/agentkms/agentkms/internal/honeytokens                  2.135s
ok      github.com/agentkms/agentkms/internal/ingestion/github             2.198s
ok      github.com/agentkms/agentkms/internal/mcp                          1.847s
ok      github.com/agentkms/agentkms/internal/plugin                      17.307s
ok      github.com/agentkms/agentkms/internal/policy                       2.284s
ok      github.com/agentkms/agentkms/internal/report                       2.076s
ok      github.com/agentkms/agentkms/internal/revocation                   2.201s
ok      github.com/agentkms/agentkms/internal/ui                           2.072s
ok      github.com/agentkms/agentkms/internal/webhooks                     2.229s
?       github.com/agentkms/agentkms/pkg/identity        [no test files]
ok      github.com/agentkms/agentkms/pkg/keystore                          2.392s
ok      github.com/agentkms/agentkms/pkg/tlsutil                           2.207s
```

All packages pass. No regressions.

---

## Divergences from spec

None. All three fixes implement the spec'd behaviour exactly.

**Fix 2 design note**: The spec says "triggers the existing restart logic after the same threshold as provider plugins." The provider `healthLoop` triggers restart after a single ping failure (threshold = 1). `destinationHealthErrorThreshold = 1` matches this. For Health() failures (as opposed to ping failures), the reviewer noted that a destination being unreachable (e.g., GitHub API down) does not imply the subprocess is broken. The spec requires the contract to match regardless; threshold 1 is conservative and matches the intent. If the team decides Health() failures should have a higher threshold, increment `destinationHealthErrorThreshold` — the restart logic and tests are parameterised on it.

**Fix 3 design note**: A second distinct audit event (`OperationBindingRotateStub`) was chosen over a field/tag on the primary event because it enables zero-configuration filtering at any audit sink (`operation = "binding_rotate_stub"`) without requiring field parsing or schema version checks. This matches how the existing codebase handles distinct audit conditions (e.g., `OperationRevokeCert` vs `OperationRevoke`).

---

## BLOCKERS

None.
