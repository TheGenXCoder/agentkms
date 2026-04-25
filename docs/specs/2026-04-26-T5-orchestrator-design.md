# T5 Pro Rotation Orchestrator — Design Document

**Date:** 2026-04-26
**Sprint:** Automated Rotation Sprint (2026-04-25 – 2026-05-11), Day 2 of 17
**Track:** Pro (license-gated plugin)
**Status:** Design pass — awaiting coordinator review before implementation
**Author:** Design agent (read-only research pass)
**Related:**
- `docs/specs/2026-04-25-destination-plugin-interface.md` — destination interface (§5, §6)
- `docs/specs/2026-04-25-T3-credential-binding-design.md` — binding model
- `docs/specs/2026-04-25-T2-multi-app-design.md` — multi-App provider
- `internal/webhooks/orchestrator.go` — existing `AlertOrchestrator` (v0.3.1, commit `d5621d19`)
- `internal/plugin/signing.go` — Ed25519 sidecar signing model
- `internal/audit/events.go` — audit schema and operation constants

---

## 1. Plugin Packaging Decision

### Three Options Evaluated

**Option A — `hashicorp/go-plugin` plugin binary (`agentkms-plugin-orchestrator`)**

The orchestrator ships as a plugin binary that the OSS host loads at startup. License self-check happens in the plugin's `Init` RPC before any rotation work begins. The OSS host knows nothing about orchestration specifics; it only knows how to load and dispatch to a plugin identified by a PluginMap key.

*Discovery:* A customer trying Pro places the binary in the plugin directory and restarts. No separate process or port required. Identical mechanics to placing `agentkms-plugin-github-secret`.

*Update cadence:* The orchestrator can ship on its own release schedule. The OSS host's plugin protocol version (`ProtocolVersion: 1`, `MagicCookieValue: "agentkms_plugin_v1"`) is the only compatibility contract.

*Security boundary:* The plugin subprocess has only what the host explicitly passes it via gRPC. It cannot reach into OSS host memory. The host passes binding records, provider vend results, and destination registry handles via structured RPC; the plugin returns rotation outcomes. This is actually a tighter boundary than Option B.

*OSS obligations:* The plugin is a separate binary with separate licensing. The OSS host is Apache-2.0 (or chosen license); the plugin binary is closed-source Pro. No AGPL/Apache conflict arises because the plugin is not a derived work that statically imports the OSS package — it communicates over a socket.

**Option B — Separate `agentkms-pro` binary wrapping the OSS package**

A distinct Go binary imports `github.com/agentkms/agentkms` as a library, embeds the full server, and adds Pro features compiled in. Customer replaces `agentkms` with `agentkms-pro`.

*Problems:* This is a hard fork of the server binary at the executable level. Every OSS release requires a coordinated Pro release. If the OSS package is Apache-2.0 and the wrapping binary is proprietary, this is legally unambiguous, but the operational cost of maintaining a parallel binary that must track every OSS server change is prohibitive for a solo developer. The "try Pro" story requires swapping binaries rather than dropping a file. Discovery is worse.

**Option C — Separate Pro repository connecting to OSS server over the existing HTTP/gRPC API**

A separate Pro process runs alongside the OSS `agentkms` server and calls its public API to read bindings, trigger rotations, etc.

*Problems:* The rotation orchestrator needs to call the provider's `Vend` RPC and the destination registry's `Deliver` RPC as part of a single atomic-ish rotation unit. If these are mediated through the public API, the orchestrator must make multiple round-trip API calls, each audited independently, with no transactional isolation. Failure recovery becomes much harder because the orchestrator's state is not co-located with the server's state. The API surface would need to be extended specifically to support the orchestrator's needs, effectively creating a private back-channel through the public API. This is an anti-pattern.

### Recommendation: Option A

**Ship as `agentkms-plugin-orchestrator`, loaded by the OSS host as a `hashicorp/go-plugin` plugin.**

Rationale: consistent with the existing freemium plugin architecture, tightest security boundary, best discovery experience, independent release cadence, and no OSS license complications. The implementation agent should treat this plugin as structurally identical to a provider plugin (same handshake, same PluginMap extension pattern) with one new PluginMap key: `"rotation_orchestrator"`.

The coordinator may override to Option B if the operational model is later changed (e.g., if a "Pro server" binary becomes desirable for enterprise on-premise deployments). The design below does not preclude that path — the license check primitive and the rotation interface are identical either way.

---

## 2. License Check Primitive

### 2.1 License File Format

The license file is a JSON manifest signed with Ed25519, written as two concatenated base64url-encoded blobs separated by a newline:

```
<base64url(manifest_json)>\n<base64url(ed25519_signature_of_manifest_bytes)>
```

The manifest is a JSON object:

```json
{
  "license_id":    "uuid-v4",
  "customer":      "Acme Corp",
  "email":         "admin@acme.example",
  "issued_at":     "2026-05-01T00:00:00Z",
  "expires_at":    "2027-05-01T00:00:00Z",
  "features":      ["rotation_orchestrator"],
  "schema_version": 1
}
```

`features` is the authoritative list of Pro capabilities the license permits. The orchestrator plugin checks that `"rotation_orchestrator"` is present in `features` at load time before registering itself. This generalizes: future Pro plugins check for their own feature string without code changes to the license format.

**Why not JWT?** JWT would require importing a JWT library and selecting an algorithm. The Ed25519 signing model already exists in `internal/plugin/signing.go` and uses `crypto/ed25519` from the standard library. Matching that style avoids a new dependency and keeps the signing logic consistent across plugin verification and license verification.

**Why not `.lic` with a hash?** A hash without an asymmetric signature allows license forgery by anyone who knows the hash algorithm. Ed25519 signatures require possession of the private key, which is never distributed to customers.

### 2.2 Public Key Embedding

The Catalyst9 license-signing public key (32 bytes, Ed25519) is embedded in the orchestrator plugin binary as a `var` initialized from a compile-time constant:

```go
// internal/license/verify.go (inside the plugin binary, not in the OSS host)

// licensingPublicKey is the Ed25519 public key used to verify AgentKMS Pro
// license manifests. The corresponding private key is held by Catalyst9 and
// never distributed. Rotate by incrementing licenseKeyVersion and shipping a
// new binary; old licenses signed with the prior key stop validating.
//
// Key version: 1 (2026-05-01)
var licensingPublicKey = ed25519.PublicKey([]byte{
    // 32 bytes — replaced with real key before first Pro release
    0x00, /* ... */
})
```

This mirrors the pattern in `internal/plugin/signing.go` where the `Verifier` holds `ed25519.PublicKey`. No runtime key fetch is needed; the public key is intrinsic to the binary.

Key rotation: when Catalyst9 needs to rotate the license signing key, a new binary ships with the new public key embedded. Old licenses signed by the previous key will fail verification on the new binary. This is acceptable because license rotation accompanies major version bumps. The `license_id` and `issued_at` fields make it clear which signing epoch a license belongs to.

### 2.3 License Check Behavior

**At plugin load time** (inside the plugin's gRPC `Init` or equivalent startup RPC, before registering with the host):

1. Read the license file path from an environment variable `AGENTKMS_LICENSE_FILE` (default: `$XDG_CONFIG_HOME/agentkms/license.lic`, fallback `~/.config/agentkms/license.lic`).
2. Parse the two-line format; base64url-decode both blobs.
3. Verify the Ed25519 signature of the manifest bytes using the embedded public key.
4. Unmarshal the manifest JSON. Check `expires_at > time.Now().UTC()`. Check `"rotation_orchestrator"` present in `features`.
5. On success: proceed with plugin initialization and register the `"rotation_orchestrator"` PluginMap service.
6. On any failure: log the failure reason to stderr (the host captures plugin stderr), return a non-nil error from the startup RPC. The host does not register the plugin. **The OSS host continues to operate normally** — missing Pro license degrades gracefully to manual-only rotation (T3's `ManualOnly: true` behavior).

**At runtime** (every 24 hours and at each rotation trigger):

The license is re-validated in memory (no re-read from disk). The in-memory validated manifest is checked for `expires_at > time.Now().UTC()`. If expired at runtime, the orchestrator rejects new rotation requests with an error that includes the expiration date and a license renewal URL. In-flight rotations that started before expiry are allowed to complete.

**Offline tolerance:** License validation is entirely offline. The embedded public key, the manifest, and the signature are all local. No network call is made. This is a hard requirement to avoid production outages from license server unavailability.

**Revocation story:** There is no online revocation check. License revocation is handled by expiry: when Catalyst9 needs to cancel a license, it allows the existing license to expire and declines to issue a renewal. For emergency revocation (customer breach), Catalyst9 can rotate the signing key in a new binary release — licenses signed by the old key stop validating on upgrade. This is a deliberate simplicity/reliability tradeoff: an online revocation check introduces a network dependency in the rotation critical path, which conflicts with the offline-tolerance requirement. Coordinator should confirm this tradeoff is acceptable.

---

## 3. Schedule Trigger Model

### 3.1 Rotation Policy Extension

T3's `RotationPolicy` struct (`docs/specs/2026-04-25-T3-credential-binding-design.md`, line 61) currently carries only `TTLHintSeconds` and `ManualOnly`. The orchestrator adds the following fields to `RotationPolicy` (implemented in the Pro plugin, not the OSS binding layer):

```go
type RotationPolicy struct {
    // TTLHintSeconds: existing field. The orchestrator uses this as the
    // rotation interval when Schedule is empty. If both are set, Schedule wins.
    TTLHintSeconds int64 `json:"ttl_hint_seconds,omitempty"`

    // ManualOnly: existing field. When true, disables cron and webhook triggers.
    // The orchestrator respects this flag; manual API/CLI triggers still work.
    ManualOnly bool `json:"manual_only"`

    // Schedule is an optional cron expression (standard 5-field, UTC) for
    // time-based rotation. Examples: "0 3 * * *" (daily at 03:00 UTC),
    // "0 */6 * * *" (every 6 hours).
    // When empty and ManualOnly is false and TTLHintSeconds > 0, the
    // orchestrator derives a schedule: rotate at TTLHintSeconds * 0.8 elapsed
    // (rotate at 80% of TTL to ensure a fresh credential is always available).
    Schedule string `json:"schedule,omitempty"`

    // GracePeriodSeconds is how long to wait after a successful rotation before
    // revoking the previous credential at the provider. Allows consumers time
    // to pick up the new credential. Default 0 (revoke immediately).
    // For long-lived secrets (e.g. annual API keys), set to 3600 (1 hour) or more.
    GracePeriodSeconds int64 `json:"grace_period_seconds,omitempty"`

    // MaxDeliveryAttempts overrides the default retry limit (5) for this binding.
    // Zero means use the default.
    MaxDeliveryAttempts int `json:"max_delivery_attempts,omitempty"`
}
```

These fields extend the OSS struct. The OSS binding layer stores them opaquely (the JSON is stored as-is in `EncryptedKV`). The Pro orchestrator reads and interprets them. The OSS layer never breaks if these fields are absent. This avoids a schema migration for existing bindings.

### 3.2 Cron Driver

The cron driver lives **in-process inside the orchestrator plugin** as a goroutine pool managed by the plugin's lifecycle. It does not require a separate daemon process.

Implementation: use `github.com/robfig/cron/v3`, which is a well-maintained cron parser/scheduler for Go with no CGO dependencies. If the coordinator prefers minimal dependencies, a `time.Ticker` per binding is acceptable for simple TTL-based intervals (but cannot express arbitrary cron expressions). The recommendation is `robfig/cron/v3` for expressiveness.

On orchestrator plugin startup:
1. Load all bindings from the binding store where `ManualOnly == false`.
2. For each binding, derive or parse its schedule.
3. Register a cron entry. The cron entry's function calls `RotateLocked(ctx, bindingName)` (see §4).

On binding register/update: the OSS host calls a notification RPC on the orchestrator plugin (see §5 for the OSS→Pro interface). The orchestrator adds or replaces the cron entry for the binding.

On orchestrator plugin shutdown: the cron scheduler is stopped gracefully (`scheduler.Stop()`). In-flight rotations that have already started their delivery phase are allowed to complete (context with deadline, not cancel).

### 3.3 Webhook Dispatch

The existing `AlertOrchestrator.ProcessAlert` in `internal/webhooks/orchestrator.go` (commit `d5621d19`) handles `LiveRevokedBranch` by calling `o.revoker.Revoke(ctx, *record)` (line 202). In the Pro-enhanced path, the orchestrator plugin replaces "revoke-only" with "rotate then revoke-old."

The OSS webhook orchestrator must not know about the Pro orchestrator by name. Instead, the OSS `AlertOrchestrator` calls into a `RotationHook` interface (new, defined in the OSS package):

```go
// RotationHook is an optional extension point for the AlertOrchestrator.
// If registered, it is called in place of (or in addition to) the
// provider-level revocation during LiveRevokedBranch.
// The implementation is supplied by the Pro orchestrator plugin at load time.
// If no RotationHook is registered, the OSS orchestrator falls back to
// its existing revoker-only logic.
type RotationHook interface {
    // TriggerRotation initiates an emergency rotation for the credential
    // identified by credentialUUID. Returns immediately; rotation proceeds
    // asynchronously. The caller should not also call Revoker.Revoke —
    // the rotation hook includes revocation of the old credential after
    // delivery completes.
    TriggerRotation(ctx context.Context, credentialUUID string) error

    // BindingForCredential returns the binding name associated with a given
    // credentialUUID, or ("", ErrNoBinding) if the credential is not managed
    // by any binding.
    BindingForCredential(ctx context.Context, credentialUUID string) (string, error)
}
```

The OSS `AlertOrchestrator` gains an optional `rotationHook RotationHook` field (nil by default). In `handleLiveRevokedBranch`, the branch becomes:

```
if o.rotationHook != nil:
    binding, err := o.rotationHook.BindingForCredential(ctx, record.CredentialUUID)
    if err == nil:
        o.rotationHook.TriggerRotation(ctx, record.CredentialUUID)
        // skip revoker.Revoke — rotation hook owns revocation
    else:
        // credential not managed by a binding; fall through to revoker.Revoke
        o.revoker.Revoke(...)
else:
    o.revoker.Revoke(...)
```

The Pro orchestrator plugin registers itself as the `RotationHook` via a new host-side registration call at plugin startup. The OSS code never imports the Pro plugin package; it only calls via the interface.

### 3.4 Manual Triggers

`kpm cred rotate <name>` (T3, `internal/kpm/cred.go`) calls `POST /bindings/{name}/rotate`. The rotate handler in the OSS server checks whether the Pro orchestrator plugin is loaded (via a registry lookup). If loaded, it delegates to the orchestrator's `RotateLocked` function. If not loaded, it executes the existing stub/direct-delivery path from T3.

This means the `POST /bindings/{name}/rotate` endpoint works in both OSS and Pro configurations without code branching in the handler itself — the handler calls a single `RotateBinding(ctx, name)` function whose implementation is swapped at runtime.

### 3.5 Trigger Idempotency

Two simultaneous triggers for the same binding (e.g., cron fires while a webhook trigger is in flight) are handled by the per-binding rotation lock (§4.1). The second trigger blocks on lock acquisition. Once the first rotation completes, the second trigger re-evaluates: if `last_rotated_at` is sufficiently recent (within the schedule jitter window, default 60 seconds), the second trigger is a no-op — it logs a `rotation_skipped_duplicate` anomaly to the audit log and returns. This prevents double-minting in burst scenarios.

---

## 4. Rotation State Machine

### 4.1 Per-Binding Lock

Each binding has a named mutex keyed by binding name. In single-node deployments (v1 scope), this is an in-process `sync.Mutex` held in a `map[string]*sync.Mutex` inside the orchestrator, guarded by a `sync.RWMutex` on the map.

Multi-node distributed lock is deferred (see §6, OQ-1). The design does not preclude adding a Redis or etcd-backed distributed lock later — the `RotationLock` interface below abstracts the lock primitive:

```go
type RotationLock interface {
    Acquire(ctx context.Context, bindingName string) (unlock func(), err error)
}
```

In-process implementation uses a `singleflight.Group` (from `golang.org/x/sync`) as an additional deduplication layer on top of the mutex: concurrent callers for the same binding coalesce into a single execution.

### 4.2 State Machine Steps

Each binding rotation proceeds through the following numbered steps. Failures at any step are described in §4.3.

**Step 1 — Acquire lock**
Call `RotationLock.Acquire(ctx, binding.Name)`. Blocks until acquired. Defer `unlock()`.

**Step 2 — Emit `binding_rotate_start` audit event**
New operation constant `OperationBindingRotateStart`. Fields: `CredentialUUID` (empty, not yet minted), `CredentialType` = `binding.ProviderKind`, `CallerID` = `"orchestrator"`, `Outcome` = `OutcomeSuccess` (the start event always succeeds; failure events follow from later steps). The `EventID` of this event becomes the `rotation_correlation_id` threaded through all subsequent events in this rotation run.

**Step 3 — Vend new credential**
Call `CredentialVenderService.Vend(ctx, scope)` on the provider plugin for `binding.ProviderKind`. `scope` is constructed from `binding.Scope` and `binding.ProviderParams`. The vend response carries the new `CredentialUUID` and the raw credential value.

On vend failure: emit `OperationBindingRotate` with `Outcome = OutcomeError`, `ErrorDetail = <provider error>`, `Anomalies = ["vend_failed"]`. Release lock. Do not attempt delivery. Notify.

**Step 4 — Deliver to all destinations**
For each `dest` in `binding.Destinations`, in parallel (bounded goroutine pool, default concurrency 4):
- Look up `DestinationDeliverer` by `dest.Kind` in the destination registry.
- Call `Deliver(ctx, DeliverRequest{...})` with the new credential value, `generation = binding.Metadata.LastGeneration + 1`, `delivery_id = rotation_correlation_id + ":" + dest.TargetID` (UUID-stable composite, consistent across retries), `credential_uuid = newCredentialUUID`.
- Apply retry policy: exponential backoff, base 1s, max 60s, up to `binding.RotationPolicy.MaxDeliveryAttempts` (default 5), per T1 spec §5. Only retry on `is_transient: true` responses.
- Record per-destination outcome.

**Step 5 — Evaluate batch outcome**
- All destinations succeeded → proceed to Step 6.
- At least one succeeded, at least one failed permanently → `degraded` (§4.4). Proceed to Step 6 for the succeeded destinations' metadata update. Skip revocation.
- All destinations failed → total failure. Proceed to Step 6 (failure path). Skip revocation.

**Step 6 — Update binding metadata / emit final audit events**
If at least one destination succeeded:
- Increment `binding.Metadata.LastGeneration` to `generation`.
- Set `binding.Metadata.LastRotatedAt` = `time.Now().UTC()`.
- Set `binding.Metadata.BindingState` = `"ok"` if all succeeded, `"degraded"` if partial.
- Persist via `BindingStore.Save(ctx, binding)`.
- Emit `OperationBindingRotate` with `Outcome = OutcomeSuccess` (or `OutcomeError` for degraded), `CredentialUUID = newCredentialUUID`, `Anomalies = ["partial_delivery_failure"]` if degraded.

If all destinations failed:
- Do not update `LastGeneration` or `LastRotatedAt`.
- Set `binding.Metadata.BindingState` = `"rotation_failed"`.
- Emit `OperationBindingRotate` with `Outcome = OutcomeError`, `Anomalies = ["total_delivery_failure"]`.

Per-destination audit events (`OperationDestinationDeliver`) are emitted by the OSS host at the time of each `Deliver` call, with the `rotation_correlation_id` in an `AgentSession` field. This allows forensics queries to join the per-destination delivery events to the parent rotation event.

**Step 7 — Revoke old credential (optional, post-grace-period)**
If `binding.RotationPolicy.GracePeriodSeconds > 0`, schedule the old credential's revocation at `time.Now().Add(gracePeriod)` by enqueuing a `RevokeOldCredential(oldCredentialUUID, bindingName)` task. The task calls `CredentialVenderService.Revoke` (or the provider's equivalent) at the configured delay.

If `GracePeriodSeconds == 0`, revoke the old credential immediately before releasing the lock. The old credential is identified by the `CredentialUUID` recorded at the previous rotation (stored in an optional `LastCredentialUUID` field in `BindingMetadata`).

Revocation failure is non-fatal: emit `OperationRevoke` with `Outcome = OutcomeError`, add `"old_credential_revoke_failed"` to anomalies of the rotation event. The rotation is still considered successful.

**Step 8 — Release lock**
Call `unlock()` (deferred; happens automatically).

### 4.3 Retry Policy

Confirmed per T1 spec §5:
- Base backoff: 1 second
- Maximum backoff: 60 seconds
- Maximum attempts: 5 (overridable per binding via `RotationPolicy.MaxDeliveryAttempts`)
- Jitter: ±25% of computed backoff to prevent thundering herd across multiple bindings rotating simultaneously
- Each retry carries the same `delivery_id` and `generation` (idempotent per T1 spec §5)

### 4.4 Degraded State

A binding enters `degraded` state when at least one destination failed permanently during a rotation. Operationally:

- **Reads are unaffected.** The binding still serves reads; the old credential is still valid at the provider (revocation is skipped on partial failure).
- **The new credential is live at the succeeded destinations.** Those destinations now hold generation N; failed destinations hold generation N-1. This is an inconsistent state by design — per T1 spec §6, no rollback.
- **Automatic recovery:** On the next scheduled rotation trigger, the orchestrator attempts full delivery again (all destinations, not just failed ones — full delivery is safe because `Deliver` is idempotent). If all destinations succeed, the binding transitions from `degraded` to `ok`.
- **Operator recovery:** `kpm cred rotate <name>` forces an immediate retry. The CLI response includes per-destination outcome so the operator can identify the failing destination and fix its configuration.
- **Notification:** `Notifier.Notify` is called with a structured `AlertResult` describing the degraded state, the failed destination(s), and the recommended action. This uses the existing `Notifier` interface from `internal/webhooks/orchestrator.go` (line 47).

### 4.5 Restart Recovery

On orchestrator plugin restart, the generation counter and `last_rotated_at` for each binding are read from the `BindingStore` (which persists to `EncryptedKV`). The orchestrator does not use the audit log as the source of truth for `LastGeneration` — `BindingMetadata.LastGeneration` in the binding store is the canonical value. The audit log is the forensics trail; the binding store is the operational state.

If the orchestrator crashed mid-rotation (after minting but before persisting `LastGeneration`), the next rotation attempt will mint a new credential with `generation = LastGeneration + 1`. The previously minted-but-undelivered credential becomes orphaned at the provider. Orphan cleanup is handled by the grace-period revocation queue: on startup, the orchestrator checks for any pending delayed revocations (persisted to `EncryptedKV` under `orchestrator/pending-revocations/<uuid>`) and replays them. This prevents credential accumulation at the provider across restarts.

---

## 5. Relationship to Existing Webhook Orchestrator

The OSS `AlertOrchestrator` (`internal/webhooks/orchestrator.go`, commit `d5621d19`) handles three branches: `ExpiredBranch`, `LiveRevokedBranch`, `ManualRevokeBranch`. The Pro orchestrator extends Branch 2 (live credential, programmatic revocation available) by replacing "revoke" with "rotate and revoke old."

**Chosen pattern: Pro-side hook registered against an OSS interface.**

The OSS `AlertOrchestrator` gains an optional `rotationHook RotationHook` field (nil by default). This field is defined in a new OSS file `internal/webhooks/rotation_hook.go` which contains only the interface definition — no implementation. The Pro orchestrator plugin registers itself as the hook implementation via a call to `AlertOrchestrator.SetRotationHook(hook)` during plugin startup.

The webhook handler dispatch becomes:

```
Branch 2:
  if rotationHook != nil && rotationHook.BindingForCredential(uuid) != ErrNoBinding:
      rotationHook.TriggerRotation(ctx, uuid)
      // skip direct revoke — rotation owns old-credential lifecycle
  else:
      revoker.Revoke(...)  // existing OSS path unchanged
```

This satisfies the public plugin API constraint: the OSS code calls into a generic `RotationHook` interface that any third-party plugin could implement. The Pro orchestrator is one implementation of that interface. The OSS webhook orchestrator has no awareness of Pro specifically.

The audit event sequence for a webhook-triggered rotation is:
1. `OperationRevoke` (from OSS `handleLiveRevokedBranch`) — marks the old credential as compromised
2. `OperationBindingRotateStart` — orchestrator begins rotation
3. `OperationDestinationDeliver` × N — per destination (from OSS host during delivery)
4. `OperationBindingRotate` — final rotation outcome (success/degraded/failed)
5. `OperationRevoke` (from orchestrator, after grace period) — revocation of old credential at provider

The `rotation_correlation_id` (stored in `AgentSession` field of audit events 2–5) allows forensics to join the full sequence. Event 1's `CredentialUUID` is the old credential; events 2–5's `CredentialUUID` is the new credential. The join is by `CredentialUUID` for the old credential's chain and by `AgentSession` for the new credential's rotation chain.

---

## 6. Open Questions for Coordinator

**OQ-T5-1: Distributed rotation lock (multi-node)**

The v1 design uses an in-process `sync.Mutex` per binding. If the orchestrator runs on multiple nodes simultaneously (e.g., k3s HA deployment on `odev`), two nodes could attempt to rotate the same binding concurrently. The coordinator should decide: is multi-node a v1 concern? If yes, the `RotationLock` interface is implemented with an etcd or Redis lease. If no, the in-process design ships and multi-node is a v1.1 item. Recommendation: defer to v1.1; document the limitation.

**OQ-T5-2: License revocation policy**

The design above relies entirely on expiry for revocation (no online check). This means a customer who stops paying retains Pro functionality until their license expires. If license terms are annual, a canceled subscription on day 1 of year 2 has no enforcement. Coordinator should decide: is this acceptable, or should there be a periodic (e.g., weekly) license revalidation call to a Catalyst9 endpoint — with graceful degradation if the endpoint is unreachable for N days? Note: adding an online check introduces a network dependency in the rotation critical path.

**OQ-T5-3: Default rotation cadences**

What are the recommended default `TTLHintSeconds` values for common credential types? Suggestions:
- GitHub installation tokens: 3600 (1 hour, matches GitHub's fixed TTL; rotation is mostly a no-op for caching purposes)
- GitHub PATs: 2592000 (30 days)
- Anthropic API keys: 7776000 (90 days)
- AWS STS: 3600–43200 (1–12 hours, depending on session duration)

Coordinator should confirm or adjust these defaults, which will be documented in `kpm cred register --help` output.

**OQ-T5-4: CLI extension vs. separate `kpm orchestrator` subcommand**

The orchestrator exposes operational controls: pause/resume all scheduled rotations, inspect the pending rotation queue, force a rotation, view degraded bindings. Should these surface as `kpm cred <subcommand>` (extending the existing T3 CLI surface) or as a new `kpm orchestrator <subcommand>`? Recommendation: `kpm cred` for per-binding operations (rotate, status), `kpm orchestrator` for global operations (pause-all, resume-all, queue). Coordinator should confirm.

**OQ-T5-5: Pending revocation durability**

The design stores pending delayed revocations (grace-period queue) in `EncryptedKV` under `orchestrator/pending-revocations/<uuid>`. This couples the Pro orchestrator to the OSS KV store. An alternative is an in-memory queue that is rebuilt from the audit log on restart (similar to how `LastGeneration` can be recovered from audit). The KV approach is simpler and more robust across restarts. Coordinator should confirm.

**OQ-T5-6: `BindingMetadata.LastCredentialUUID` field**

Step 7 of the rotation state machine requires knowing the `CredentialUUID` of the previously vended credential to revoke it after the grace period. This UUID is not currently stored in `BindingMetadata` (T3 spec). The orchestrator needs to persist it on each successful rotation. Options: (a) add `LastCredentialUUID string` to `BindingMetadata` in the OSS binding model, or (b) query the audit log for the most recent `OperationBindingRotate` event for this binding and extract the UUID. Option (a) is simpler; option (b) avoids changing the OSS data model from the Pro plugin. Recommendation: (a), since the field is operationally useful (operators can correlate via `kpm cred inspect`). Coordinator should confirm.

**OQ-T5-7: Cron library dependency**

The design recommends `github.com/robfig/cron/v3` for the cron driver. This adds a dependency to the Pro plugin binary (not the OSS binary). Coordinator should confirm this is acceptable, or specify preference for a simpler TTL-ticker-only approach (which cannot express arbitrary cron expressions but eliminates the dependency).

**OQ-T5-8: Rotation hook registration timing**

The `RotationHook` interface is registered by the Pro orchestrator plugin during its startup sequence, which runs after the OSS host has initialized. There is a startup window where the webhook handler could receive a secret-scanning alert before the Pro hook is registered, causing it to fall through to the OSS revoker-only path. The coordinator should decide: is this startup race acceptable (likely yes — the window is under one second), or should the host defer webhook processing until all plugins have completed startup?
