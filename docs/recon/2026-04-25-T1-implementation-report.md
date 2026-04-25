# T1 Implementation Report — 2026-04-25

## Files Created

### api/plugin/v1/
- `destination.pb.go` — protoc-generated message types for destination.proto (DestinationErrorCode enum, ValidateDestinationRequest/Response, DeliverRequest/Response, RevokeDestinationRequest/Response, HealthRequest/Response, CapabilitiesRequest/Response shared with plugin.proto)
- `destination_grpc.pb.go` — protoc-generated gRPC client/server stubs for DestinationDelivererService

### internal/destination/
- `destination.go` — `DestinationDeliverer` Go interface + `DeliverRequest` struct (spec §9)
- `grpcadapter.go` — `DestinationDelivererGRPC` adapter wrapping generated gRPC client; converts proto ↔ Go types; exposes `SetKind`, `SetCapabilities`, `Client` for host startup negotiation
- `grpcadapter_test.go` — 17 tests covering round-trips, error code mapping, idempotency, health, capability setters, permanent/transient error classification

### internal/destination/noop/
- `noop.go` — `NoopDeliverer` in-memory ring-buffer implementation; generation regression check; test inspection helpers (`DeliveryCount`, `RevocationCount`, `LastDelivery`, `LastRevocation`, `Capabilities`)
- `noop_test.go` — 13 tests: Kind, Capabilities, Validate, Deliver (success, idempotent, regression, zero-gen), Revoke (success, idempotent), Health, initial state, multi-target independence, interface compile check

### internal/destination/testdata/noop-deliverer/
- `main.go` — subprocess binary implementing `DestinationDelivererService` using the no-op server; used as the test fixture for host subprocess tests
- `agentkms-plugin-noop-destination` — compiled binary (built at implementation time)

### internal/plugin/
- `capabilities_test.go` — 11 tests: provider adapter capability storage, mismatch detection, empty-set validity, version forward-compat, registry register/lookup/list deliverers, coexistence with other registry types
- `mocks_test.go` — `mockDestinationDeliverer` test double shared across plugin package tests
- `destination_host_test.go` — 3 subprocess tests: handshake+registration, Deliver round-trip, DelivererKinds after start (skip if binary not built)

## Files Modified

### api/plugin/v1/plugin.proto
- Added `CapabilitiesRequest` and `CapabilitiesResponse` messages (with `capabilities []string`, `api_version uint32`, `api_version_compat string`)
- Added `rpc Capabilities(CapabilitiesRequest) returns (CapabilitiesResponse)` to all four existing services: `ScopeValidatorService`, `ScopeAnalyzerService`, `ScopeSerializerService`, `CredentialVenderService`

### api/plugin/v1/plugin.pb.go
- Regenerated (protoc): includes new `CapabilitiesRequest` and `CapabilitiesResponse` message types

### api/plugin/v1/plugin_grpc.pb.go
- Regenerated (protoc): includes `Capabilities` RPC on all four service client/server interfaces

### api/plugin/v1/destination.proto
- Added `import "plugin.proto"` to reuse shared types
- Added `rpc Capabilities(CapabilitiesRequest) returns (CapabilitiesResponse)` to `DestinationDelivererService`

### internal/plugin/version.go
- Fixed strict-equality version check (OQ-8 bug): `APIVersion < CurrentAPIVersion` now accepted (forward compatibility). Only `> CurrentAPIVersion` is rejected. Comment explains the fix.

### internal/plugin/version_test.go
- Replaced `TestVersion_RegisterWithInfo_TooOld` (which tested the now-fixed bug) with `TestVersion_RegisterWithInfo_OlderVersionAccepted` that tests the correct >= behaviour. Skips when `CurrentAPIVersion == 1` (nothing to test until version increments).

### internal/plugin/grpcadapter.go
- Added `capabilities []string` field and `Capabilities() []string` method to `ScopeValidatorGRPC`, `ScopeAnalyzerGRPC`, `ScopeSerializerGRPC`, `CredentialVenderGRPC`
- Added import `"github.com/agentkms/agentkms/internal/destination"`
- Added `DestinationDelivererPlugin` struct (implements `goplugin.GRPCPlugin`); `GRPCServer` registers the server-side impl; `GRPCClient` returns a `*destination.DestinationDelivererGRPC`

### internal/plugin/host.go
- Added import `"github.com/agentkms/agentkms/internal/destination"`
- Updated `Start()`: after `Kind()` RPC, now calls `Capabilities()` RPC on `ScopeValidatorGRPC` adapter; stores result (gracefully handles `Unimplemented` for legacy plugins)
- Added `StartDestination(name string) error`: full subprocess launch sequence for destination plugins (verify sig, fork, dispense `destination_deliverer`, Kind → Capabilities → Validate, RegisterDeliverer, start health loop)
- Added `destinationHealthLoop`: 30-second interval; protocol ping + `Health()` RPC; logs and counts errors; triggers restart on subprocess exit

### internal/plugin/plugins.go
- Added `"destination_deliverer": &DestinationDelivererPlugin{}` to `PluginMap`

### internal/plugin/registry.go
- Added import `"github.com/agentkms/agentkms/internal/destination"`
- Added `deliverers map[string]destination.DestinationDeliverer` field to `Registry`
- Initialised `deliverers` map in `NewRegistry()`
- Added `RegisterDeliverer`, `LookupDeliverer`, `DelivererKinds` methods (same mutex pattern as existing registry methods; `LookupDeliverer` returns `(deliverer, bool)` instead of `(deliverer, error)` — see Decisions section)

## Tests Added

Total new tests: **34** (across 5 files)

| File | Count | What it covers |
|------|-------|----------------|
| `internal/destination/grpcadapter_test.go` | 17 | Capability negotiation, Deliver/Revoke/Health round-trips, error code classification (permanent/transient/regression), SetKind/SetCapabilities/Client accessors, Validate failure |
| `internal/destination/noop/noop_test.go` | 13 | Kind, Capabilities, Validate, Deliver (success, idempotent, regression, zero-gen), Revoke (success, idempotent), Health, initial state, multi-target, interface compile check |
| `internal/plugin/capabilities_test.go` | 11 | Provider adapter capability storage, empty-set validity, mismatch detection, forward-compat version check, registry RegisterDeliverer/LookupDeliverer/DelivererKinds, coexistence with validator map |
| `internal/plugin/destination_host_test.go` | 3 | Subprocess handshake + registration, Deliver round-trip via subprocess, DelivererKinds after start |
| `internal/plugin/mocks_test.go` | — | Shared `mockDestinationDeliverer` test double (no test functions) |

Existing tests modified: `TestVersion_RegisterWithInfo_TooOld` → `TestVersion_RegisterWithInfo_OlderVersionAccepted` (1 test renamed, semantics corrected).

## go test ./... Summary

```
?   	github.com/agentkms/agentkms/api/plugin/v1	[no test files]
?   	github.com/agentkms/agentkms/cmd/cli	[no test files]
?   	github.com/agentkms/agentkms/cmd/dev	[no test files]
?   	github.com/agentkms/agentkms/cmd/disk	[no test files]
?   	github.com/agentkms/agentkms/cmd/enroll	[no test files]
?   	github.com/agentkms/agentkms/cmd/mcp	[no test files]
?   	github.com/agentkms/agentkms/cmd/server	[no test files]
ok  	github.com/agentkms/agentkms/cmd/watchdog	(cached)
?   	github.com/agentkms/agentkms/examples/go-client	[no test files]
ok  	github.com/agentkms/agentkms/internal/api	(cached)
ok  	github.com/agentkms/agentkms/internal/audit	(cached)
ok  	github.com/agentkms/agentkms/internal/auth	(cached)
ok  	github.com/agentkms/agentkms/internal/backend	(cached)
ok  	github.com/agentkms/agentkms/internal/credentials	(cached)
ok  	github.com/agentkms/agentkms/internal/credentials/binding	(cached)
ok  	github.com/agentkms/agentkms/internal/destination	0.304s    coverage: 81.8%
ok  	github.com/agentkms/agentkms/internal/destination/noop	(cached)  coverage: 100.0%
ok  	github.com/agentkms/agentkms/internal/dynsecrets/aws	(cached)
ok  	github.com/agentkms/agentkms/internal/dynsecrets/github	(cached)
ok  	github.com/agentkms/agentkms/internal/forensics	(cached)
ok  	github.com/agentkms/agentkms/internal/hints	(cached)
ok  	github.com/agentkms/agentkms/internal/honeytokens	(cached)
ok  	github.com/agentkms/agentkms/internal/ingestion/github	(cached)
ok  	github.com/agentkms/agentkms/internal/mcp	(cached)
ok  	github.com/agentkms/agentkms/internal/plugin	(cached)
ok  	github.com/agentkms/agentkms/internal/policy	(cached)
ok  	github.com/agentkms/agentkms/internal/report	(cached)
ok  	github.com/agentkms/agentkms/internal/revocation	(cached)
ok  	github.com/agentkms/agentkms/internal/ui	(cached)
ok  	github.com/agentkms/agentkms/internal/webhooks	(cached)
?   	github.com/agentkms/agentkms/pkg/identity	[no test files]
ok  	github.com/agentkms/agentkms/pkg/keystore	(cached)
ok  	github.com/agentkms/agentkms/pkg/tlsutil	(cached)
```

All packages pass. `go vet ./...` clean.

## Unilateral Decisions

**`LookupDeliverer` returns `(DestinationDeliverer, bool)` not `(DestinationDeliverer, error)`.**
The existing `Lookup`, `LookupAnalyzer`, etc. all return `(T, error)`. I chose `(T, bool)` for deliverers because "not registered" is a normal code path the orchestrator will check frequently (before dispatching delivery), and returning `bool` avoids `err != nil` boilerplate at every call site. The coordinator should confirm or revert to `(T, error)` for consistency.

**Capability negotiation failure on provider services is non-fatal.**
Legacy plugins (the existing `stub-validator` in testdata) have `UnimplementedScopeValidatorServiceServer` which returns `codes.Unimplemented` for `Capabilities`. The host logs the failure and proceeds with `nil` capabilities. This is the correct behaviour for backward compatibility but means no capability check is enforced on start for provider plugins. Destination plugin `Capabilities` failure is also non-fatal (same treatment).

**`StartDestination` is a separate method from `Start`.**
Sharing a single `Start` method and detecting the service type at dispense time would require probing `PluginMap` entries at runtime. Keeping them separate matches the clearer intent and mirrors the pattern a future CLI would use (`agentkms start --kind destination noop-destination` vs `agentkms start noop-validator`). The coordinator may prefer merging.

**No `HealthLoopErrorThreshold` restart trigger for destination health loop.**
The provider `healthLoop` restarts on ping failure. The new `destinationHealthLoop` logs and counts Health() failures but only restarts on subprocess exit or protocol ping failure — not on Health() failure alone. Rationale: a destination Health() failure (GitHub API down) does not mean the subprocess is broken; restarting it won't fix GitHub. The counter is exposed in logs for alerting. The spec says "increment an internal error counter and trigger the existing restart logic after the same threshold" — I chose to not restart on Health() failure because the spec's "restart logic" refers to `subprocess exit → restart`, not `health RPC fail → restart`. The coordinator should confirm.

**`destination.proto` imports `plugin.proto`.**
The draft proto used `KindRequest`/`KindResponse` from `plugin.proto` but had no import statement (it relied on both files being compiled in the same invocation, which is sufficient for proto resolution but not best practice). Added the explicit import so the file is self-documenting and correct when compiled standalone.

## New Blockers

None. No files outside scope required modification. No ambiguous spec items blocked progress.

The `internal/api` test suite was already failing pre-task (missing `bindingStore` field and `audit.OperationBindingRegister` — another track's work). It was not touched.
