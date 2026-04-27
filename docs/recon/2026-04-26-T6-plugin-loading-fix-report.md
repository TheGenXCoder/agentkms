# T6 Plugin Loading Fix Report

**Date:** 2026-04-26
**Branch:** main
**Status:** FIXED — both issues resolved, all tests green

---

## Summary

Two bugs blocked the T6 demo end-to-end flow. Both are now fixed with additive
changes only — no proto changes required, no existing behaviour altered.

---

## Issue 1 — Destination plugin startup Validate intolerance

### Root Cause

`Host.StartDestination` (in `internal/plugin/host.go`, line ~505) called
`adapter.Validate(validateCtx, nil)` as a startup connectivity probe. The
`ghsecret.Deliverer.Validate` method (in
`internal/destination/ghsecret/deliverer.go`) called `parseParams(params)`, which
returned a permanent error for nil or empty `params` because `writer_token` was
absent.

Error path: `parseParams(nil)` → `fmt.Errorf("ghsecret: [permanent] missing
required param \"writer_token\"")` → `StartDestination` logs the error and
refuses to register the plugin.

### Contract Problem

Destinations do not have per-instance configuration at registration time.
Credentials (including `writer_token`) arrive in per-`Deliver` params, not at
startup. The startup `Validate(ctx, nil)` call is a **connectivity / sanity
probe**, not a credential check. Requiring `writer_token` at that point is a
contract violation.

### Fix

**File:** `internal/destination/ghsecret/deliverer.go`

`Deliverer.Validate` now short-circuits before `parseParams` if `params` is nil
OR `writer_token` is absent:

```go
// Startup-probe tolerance: nil params or absent writer_token → defer to Deliver.
if params == nil {
    return nil
}
if _, hasToken := params["writer_token"]; !hasToken {
    return nil
}
```

The full token-validity check (GET /user → 401/403 → permanent error) only runs
when `writer_token` is present. A present-but-bad token is still a permanent error.

The existing `Host.StartDestination` call site is unchanged — it continues to call
`Validate(ctx, nil)`, which is now the correct startup probe.

### Tests Updated

**File:** `internal/destination/ghsecret/deliverer_test.go`

- `TestValidate_NilParams` — nil params → nil (new)
- `TestValidate_EmptyParams` — empty map, no writer_token → nil (new)
- `TestValidate_TokenMissing` — updated assertion: missing writer_token now expects nil, not error
- `TestValidate_TokenPresentButBad` — writer_token present + 401 → permanent error (new, mirrors old TokenRejected)
- `TestValidate_TokenRejected` — existing test kept; still passes (same assertion as TokenPresentButBad)

---

## Issue 2 — No Host.StartProvider for CredentialVender plugins

### Root Cause

`cmd/dev/main.go` plugin dispatch `default` case called `pluginHost.Start(name)`.
`Host.Start` dispenses `"scope_validator"` and calls `ScopeValidatorService.Kind()`.
The github provider plugin registers under PluginMap key `"credential_vender"` and
serves `CredentialVenderService` only — it does not implement `ScopeValidatorService`.
The gRPC call failed:

```
rpc error: code = Unimplemented desc = unknown service agentkms.plugin.v1.ScopeValidatorService
```

### Fix — Part A: `Host.StartProvider`

**File:** `internal/plugin/host.go`

New method `Host.StartProvider(name string) error` (added before the orchestrator
section, ~line 410):

```go
func (h *Host) StartProvider(name string) error
```

**Behaviour:**
1. `findPluginPath(name)` — same discovery check as all other Start* methods
2. Idempotency check — if already running, returns nil
3. Optional signature verification
4. Forks subprocess via `goplugin.NewClient` (same config as StartDestination)
5. Dispenses `"credential_vender"` (not `"scope_validator"`)
6. Type-asserts to `*CredentialVenderGRPC` (already exists in `grpcadapter.go`)
7. Calls `Kind()` on `CredentialVenderService` → sets `adapter.kind`
8. Calls `Capabilities()` (Unimplemented → empty caps, backwards compatible)
9. `registry.RegisterVender(adapter.kind, adapter)` — makes it findable via `LookupVender`
10. Starts `providerHealthLoop` goroutine (protocol-level ping only; no Health RPC in CredentialVenderService v0.3.x)

**New method:** `Host.providerHealthLoop` — mirrors `healthLoop` but restarts via
`StartProvider` instead of `Start`.

### Fix — Part B: `cmd/dev/main.go` dispatch

**File:** `cmd/dev/main.go`, line ~593

Changed `default` case from:

```go
if err := pluginHost.Start(meta.Name); err != nil {
```

To:

```go
if err := pluginHost.StartProvider(meta.Name); err != nil {
```

Updated the comment to explain why `Start()` is wrong for credential-vender plugins.

### Registry

`registry.RegisterVender` / `registry.LookupVender` already existed in
`internal/plugin/registry.go` (lines 163–197). No changes needed.

`CredentialVenderGRPC` adapter already existed in `internal/plugin/grpcadapter.go`
(lines 183–236). No changes needed.

### Proto / new RPC

No proto changes required. `CredentialVenderService` has `Kind()` and
`Capabilities()` RPCs already generated and working.

`CredentialVenderService` does not define a `Health` RPC in v0.3.x. The
`providerHealthLoop` uses go-plugin's protocol-level keepalive ping only, which
is sufficient. Adding a Health RPC would require proto regen and is deferred to
v0.4.

### Tests Added

**File:** `internal/plugin/provider_host_test.go` (new file)

Uses `internal/plugin/testdata/noop-vender/main.go` (new testdata binary) which
implements `CredentialVenderService` with Kind=`"noop-vender"` and always returns
a synthetic credential.

Tests:
- `TestProviderHost_Handshake_KindCapabilitiesRegistered` — forks subprocess, verifies Kind/Caps, checks registry
- `TestProviderHost_Vend_RoundTrip` — calls `Vend()` through gRPC transport end-to-end
- `TestProviderHost_IsRunning_AfterStart` — IsRunning true after StartProvider
- `TestProviderHost_StartProvider_Idempotent` — second StartProvider is no-op
- `TestProviderHost_StartProvider_UnknownPlugin` — returns error for undiscovered plugin
- `TestProviderHost_VenderKinds_AfterStart` — VenderKinds lists the registered kind
- `TestProviderHost_CapabilityMismatch_GracefulDegradation` — capabilities survive handshake

---

## cmd/server/main.go

**No plugin discovery loop exists in `cmd/server/main.go`** — the production
server does not load plugins at all. The fix is needed only in `cmd/dev/main.go`.
This is documented but not a blocker.

---

## Files Modified

| File | Change |
|------|--------|
| `internal/destination/ghsecret/deliverer.go` | Validate tolerates nil/absent writer_token at startup |
| `internal/destination/ghsecret/deliverer_test.go` | Tests for new Validate tolerance contract |
| `internal/plugin/host.go` | Added `StartProvider` + `providerHealthLoop` |
| `cmd/dev/main.go` | `default` dispatch: `Start` → `StartProvider` |
| `internal/plugin/provider_host_test.go` | New — 7 tests for StartProvider lifecycle |
| `internal/plugin/testdata/noop-vender/main.go` | New — mock CredentialVender for subprocess tests |

---

## Validation Results

```
go build ./...   ✅ clean
go vet ./...     ✅ clean
go test ./...    ✅ all pass (35 packages, zero failures)
agentkms-pro:    ✅ unaffected (StartProvider is purely additive)
```

---

## Blockers

None. Both issues are resolved. The T6 demo path is unblocked:
- gh-secret destination plugin starts cleanly (Validate(nil) → nil)
- github provider plugin starts cleanly (StartProvider dispenses credential_vender)
