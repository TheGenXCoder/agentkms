# Day 3 Cleanup Report — Review-Flagged Findings

**Date:** 2026-04-26
**Scope:** 1 MUST-FIX + 4 SHOULD-FIX from `2026-04-26-day3-review-report.md`
**NICE-TO-HAVE items:** explicitly deferred — not addressed

---

## Summary

| Fix | Severity | Status |
|-----|----------|--------|
| Fix 1 — hostErr zero-value safety | MUST-FIX | Done |
| Fix 2 — License signature comment | SHOULD-FIX | Done |
| Fix 3 — Generation strict monotonicity | SHOULD-FIX | Done |
| Fix 4 — DeliverToDestination audit timing | SHOULD-FIX | Done |
| Fix 5 — BindingForCredential happy-path test | SHOULD-FIX | Done |

---

## Fix 1 — hostErr Zero-Value Safety

**File modified:** `agentkms-pro/internal/host/client.go`

**Change:** `hostErr` now returns nil ONLY when `code == HOST_OK`. `HOST_ERROR_UNSPECIFIED`
(proto zero-value = 0) now returns a non-nil `*HostError` with message
`"host returned unspecified error code; treating as failure (fail-closed)"`.
Pattern (b) from the review spec. Decision documented in comment above `hostErr`.

Also cleaned up the stale comment at the `DeliverToDestination` call site which
previously said UNSPECIFIED was treated as success.

**Cascading fix required:** All existing stubs in
`agentkms-pro/internal/orchestrator/state_machine_test.go` were returning
zero-value proto responses (empty structs). These now returned UNSPECIFIED and
failed. Updated all 10 stub methods to return `HOST_OK` explicitly:
- `ListBindings`, `GetBinding`, `VendCredential`, `DeliverToDestination`,
  `SaveBindingMetadata`, `RevokeCredential`, `EnqueueRevocation`,
  `DrainPendingRevocations`, `AckRevocation`, `EmitAudit`, `RevokeAtDestination`

**Tests added:** 1 new test in `agentkms-pro/internal/host/client_test.go`:
- `TestHostClient_UnspecifiedErrorCode_TreatedAsError` — fake host returns
  `HOST_ERROR_UNSPECIFIED` (zero-value) with empty message for both
  `DeliverToDestination` and `SaveBindingMetadata`. Asserts non-nil error
  returned from typed `host.Client` methods. Also required adding
  `"github.com/catalyst9ai/agentkms-pro/internal/host"` import to the test file.

---

## Fix 2 — License Signature Comment

**File modified:** `agentkms-pro/internal/license/verify.go`

**Change:** Added an 8-line block comment above the `ed25519.Verify` call at line 114
(now slightly offset due to the new comment). Comment explicitly states:
- The signature is verified against `manifestBytes` (raw JSON bytes decoded from
  line 1 of the license file), NOT a re-marshaled version of the parsed `Manifest` struct.
- Re-marshaling after parsing would break verification because JSON field ordering
  may differ.
- Future maintainers must always pass `manifestBytes` (the raw decoded bytes) here.

**Code correct as-is** — the bug was comment clarity only, not a functional defect.

**Tests added:** 0 (comment-only change; existing license tests provide adequate coverage).

---

## Fix 3 — Generation Strict Monotonicity

**File modified:** `agentkms/internal/plugin/host_service.go`

**Change:** `SaveBindingMetadata` generation check changed from:
```go
if patch.GetLastGeneration() < b.Metadata.LastGeneration {
```
to:
```go
if patch.GetLastGeneration() <= b.Metadata.LastGeneration {
```

Error message updated: `"generation regression or replay: patch=%d must be > stored=%d"`.

Comment updated to explain single-node scope and reference BLOCKERS.md B4 for
multi-node distribution.

**Tests added:** 1 new test in `agentkms/internal/plugin/host_service_test.go`:
- `TestHostService_SaveBindingMetadata_SameGeneration_Rejected` — binding at stored
  gen=5, patch with gen=5 (same). Asserts `HOST_PERMANENT` and non-empty error message
  containing the stored generation value.

Also added helper `containsGen(s string, gen uint64) bool` and required adding
`"fmt"` and `"strings"` to the test file imports.

---

## Fix 4 — DeliverToDestination Audit Emission Timing

**File modified:** `agentkms/internal/plugin/host_service.go`

**Change:** The previous code emitted an audit event with `OutcomeSuccess` BEFORE
calling `deliverer.Deliver`, then emitted a second `OutcomeError` event if the
delivery failed — producing a false success record for every failing delivery.

New behavior: emit EXACTLY ONE audit event PER DELIVERY, AFTER `deliverer.Deliver`
returns, with the actual outcome. Decision: single post-delivery event (not
start+complete pair) for simplicity; the Part 8 forensics narrative requires that
audit records accurately reflect what happened, not what was intended.

`emitDestinationDeliverAudit` signature extended with an `anomalyTag string`
parameter:
- Success: `anomalyTag = ""` (no anomaly appended)
- Permanent error: `anomalyTag = "delivery_permanent_error"`
- Transient error: `anomalyTag = "delivery_transient_error"`

**Tests added:** 4 new tests in `agentkms/internal/plugin/host_service_test.go`:
- `TestHostService_DeliverToDestination_Audit_Success` — stub deliverer returns
  success; audit event has `outcome="success"`, empty error_detail, empty anomalies.
- `TestHostService_DeliverToDestination_Audit_PermanentError` — stub deliverer returns
  permanent error; audit event has `outcome="error"`, populated error_detail,
  anomaly tag `"delivery_permanent_error"`.
- `TestHostService_DeliverToDestination_Audit_TransientError` — stub deliverer returns
  transient error (isPerm=false); audit event has `outcome="error"`, anomaly tag
  `"delivery_transient_error"`.
- `TestHostService_DeliverToDestination_AuditEventCount` — verifies exactly 1 audit
  event is emitted per delivery (not 2 from old start+complete pair).

Also added helper `containsAnomaly(anomalies []string, tag string) bool`.

---

## Fix 5 — BindingForCredential Happy-Path Test

**File modified:** `agentkms-pro/cmd/agentkms-plugin-orchestrator/main_test.go`

**Added:** 1 new test + 1 new stub type:
- `TestBindingForCredential_AfterInit_HappyPath` — sets up a `bindingAwareHostService`
  that returns one binding with `last_credential_uuid = knownUUID`. Inits the
  orchestratorServer via fakeBroker injection. Then:
  - `BindingForCredential(knownUUID)` → asserts `BindingName == knownBinding`,
    `NotFound == false`
  - `BindingForCredential("unknown-uuid-xyz")` → asserts `NotFound == true`,
    empty BindingName
- `bindingAwareHostService` — implements `HostServiceServer` with `ListBindings`
  returning one known binding and `DrainPendingRevocations` returning empty-OK
  (both required for `CronDriver.Start` to succeed during `Init`).

---

## Final Test Output

### agentkms (OSS)

```
?   github.com/agentkms/agentkms/api/plugin/v1          [no test files]
ok  github.com/agentkms/agentkms/cmd/agentkms-license   0.241s
ok  github.com/agentkms/agentkms/cmd/watchdog            0.755s
ok  github.com/agentkms/agentkms/internal/api            0.703s
ok  github.com/agentkms/agentkms/internal/audit          1.159s
ok  github.com/agentkms/agentkms/internal/auth           2.637s
ok  github.com/agentkms/agentkms/internal/backend        0.985s
ok  github.com/agentkms/agentkms/internal/credentials    1.168s
ok  github.com/agentkms/agentkms/internal/credentials/binding   1.122s
ok  github.com/agentkms/agentkms/internal/destination    1.450s
ok  github.com/agentkms/agentkms/internal/destination/ghsecret  1.783s
ok  github.com/agentkms/agentkms/internal/destination/noop      1.587s
ok  github.com/agentkms/agentkms/internal/dynsecrets/aws        1.966s
ok  github.com/agentkms/agentkms/internal/dynsecrets/github     3.540s
ok  github.com/agentkms/agentkms/internal/forensics     1.748s
ok  github.com/agentkms/agentkms/internal/hints          1.846s
ok  github.com/agentkms/agentkms/internal/honeytokens   1.731s
ok  github.com/agentkms/agentkms/internal/ingestion/github      1.815s
ok  github.com/agentkms/agentkms/internal/mcp            1.953s
ok  github.com/agentkms/agentkms/internal/plugin         17.264s
ok  github.com/agentkms/agentkms/internal/policy         2.233s
ok  github.com/agentkms/agentkms/internal/report         1.979s
ok  github.com/agentkms/agentkms/internal/revocation     2.057s
ok  github.com/agentkms/agentkms/internal/ui             2.020s
ok  github.com/agentkms/agentkms/internal/webhooks       1.733s
ok  github.com/agentkms/agentkms/pkg/keystore            1.914s
ok  github.com/agentkms/agentkms/pkg/tlsutil             1.748s
```

`go build ./...` and `go vet ./...` both clean.

### agentkms-pro

```
?   github.com/catalyst9ai/agentkms-pro/api/plugin/v1                        [no test files]
ok  github.com/catalyst9ai/agentkms-pro/cmd/agentkms-plugin-orchestrator     0.242s
ok  github.com/catalyst9ai/agentkms-pro/internal/host                        0.398s
ok  github.com/catalyst9ai/agentkms-pro/internal/license                     0.508s
ok  github.com/catalyst9ai/agentkms-pro/internal/orchestrator                0.811s
```

`go build ./...` and `go vet ./...` both clean.

---

## Decisions Made Unilaterally

1. **Fix 1 — Pattern choice:** Chose pattern (b) from the review: `UNSPECIFIED` returns
   a distinct error message rather than using pattern (a) which requires checking
   `error_message == ""` too. Simpler and sufficient for fail-closed semantics.

2. **Fix 1 — Cascade scope:** Updated all 10 smStubServer methods in
   `state_machine_test.go` to return explicit `HOST_OK`. This was required by the
   Fix 1 change, not mentioned in the review spec, but inescapable. All other
   existing tests continue to pass.

3. **Fix 4 — Single event vs start+complete:** Chose single post-delivery event.
   The review offered both options; single-event is simpler and the forensics
   narrative only requires accuracy of outcome, not a delivery-initiated marker.

4. **Fix 4 — Anomaly tag naming:** `"delivery_permanent_error"` and
   `"delivery_transient_error"` — lowercase-hyphen-separated consistent with
   existing anomaly tags visible in the codebase.

5. **Fix 4 — Audit event count test added:** Not in the review spec, but directly
   validates the "exactly one event" invariant. Caught that the old code emitted two
   events on error; the new code correctly emits one.

---

## New Blockers

None. All 5 fixes implemented cleanly. No new BLOCKERS introduced.
