# T5 Part 1.5 — `HostService` Host Callback Design

**Date:** 2026-04-26
**Sprint:** Automated Rotation Sprint (2026-04-25 – 2026-05-11), Day 3 of 17
**Track:** Pro (license-gated plugin) / OSS host interface
**Status:** Design pass — awaiting coordinator review before Part 2 implementation
**Author:** Design agent (read-only research pass)
**Related:**
- `docs/specs/2026-04-26-T5-orchestrator-design.md` — parent T5 design (§3–§5 especially)
- `api/plugin/v1/host.proto` — the draft proto file produced by this design pass
- `api/plugin/v1/destination.proto` — precedent for error enum and service shape
- `internal/credentials/binding/binding.go` — `CredentialBinding`, `BindingMetadata` shapes
- `internal/audit/events.go` — `AuditEvent` struct and Operation/Outcome constants
- `internal/plugin/host.go` — existing plugin dispatch and lifecycle model
- `internal/webhooks/orchestrator.go` — post-Part 1 `RotationHook` delegation flow

---

## 1. Service Shape and Lifecycle

### 1.1 What Problem This Solves

The Pro rotation orchestrator ships as a `hashicorp/go-plugin` subprocess (T5 §1, Option A confirmed). As a separate subprocess it cannot reach OSS-internal types directly: the `BindingStore`, the provider plugin registry, the destination plugin registry, the `Auditor`, or the `EncryptedKV` pending-revocation queue. The `HostService` is the controlled bridge — a gRPC service that the OSS host serves and the Pro plugin consumes via callback.

The pattern is identical in principle to HashiCorp Vault's plugin system, where plugins call back into the Vault core over a broker-established side channel. go-plugin's `GRPCBroker` is the mechanism.

### 1.2 Transport: GRPCBroker Side Channel

`hashicorp/go-plugin` establishes one primary gRPC connection per plugin subprocess (used for the plugin's own service — `CredentialVenderService`, `DestinationDelivererService`, etc.). The `GRPCBroker` allows either side to open additional numbered side channels over the same underlying multiplexed connection.

For `HostService`:

1. During `StartOrchestrator` (the new Host method analogous to `StartDestination` in `internal/plugin/host.go`), the host calls `broker.NextId()` to allocate a broker ID, then launches a goroutine calling `broker.AcceptAndServe(brokerID, grpcServer)` where `grpcServer` is a `*grpc.Server` with `HostService` registered.
2. The host passes `brokerID` to the plugin via the `Init` RPC (a new unary RPC on the `RotationOrchestratorService` defined in the Pro plugin — see §7).
3. The plugin's `Init` implementation calls `broker.Dial(brokerID)` to obtain a `*grpc.ClientConn`, constructs a `HostServiceClient`, and stores it for later use.
4. If `broker.Dial` fails, `Init` returns an error and the host's `StartOrchestrator` fails, preventing a broken plugin from registering the `RotationHook`.

### 1.3 Which Plugins Receive a HostService Handle

Only plugins dispensed under the PluginMap key `"rotation_orchestrator"`. Provider plugins (`"scope_validator"`, `"credential_vender"`) and destination plugins (`"destination_deliverer"`) are launched without a broker ID: their `ClientConfig` does not include a `GRPCBrokerMultiplex` server, and they have no `Init` RPC that accepts one. This prevents provider/destination plugins from accessing binding state or the audit chain.

The PluginMap extension (`internal/plugin/plugins.go`, not yet existing) adds:

```go
"rotation_orchestrator": &OrchestratorPlugin{},
```

`OrchestratorPlugin` implements `goplugin.GRPCPlugin` and wraps the Pro plugin's gRPC service definition.

### 1.4 Authentication

The gRPC connection for `HostService` lives within the established plugin process pair. Authentication is gated by:

1. **Handshake cookie** — `MagicCookieKey: "PLUGIN_MAGIC_COOKIE"`, `MagicCookieValue: "agentkms_plugin_v1"` (same as all other plugins, see `internal/plugin/host.go` line 173).
2. **Ed25519 plugin binary signature** — verified by `Verifier.Verify` before subprocess launch (`internal/plugin/host.go` lines 159–167).

No additional TLS certificate, mTLS, or token is needed at the `HostService` gRPC level. The broker channel inherits the security of the already-authenticated parent connection.

### 1.5 Lifecycle: Connection Established at Init (Fail-Fast)

The plugin connects to `HostService` inside its `Init` RPC — the first call the host makes after dispensing the `rotation_orchestrator` service. This is the fail-fast design: if the broker channel cannot be established (host bug, version mismatch), the plugin startup fails immediately, the host does not register the `RotationHook`, and OSS webhook handling falls back to the existing revoker-only path.

The alternative (connect on first use) would defer failure to rotation time, potentially mid-rotation when a binding is already locked. Fail-fast at startup is the correct choice.

---

## 2. Method Surface

### 2.1 Bindings

**`ListBindings(ListBindingsRequest) → BindingList`**

Wraps `BindingStore.List` (`internal/credentials/binding/binding.go`, line 217) with a filter and pagination layer. The orchestrator calls this on startup (to load all bindings for cron scheduling, T5 §3.2 step 1) and on notification of binding changes.

- Idempotency: safe to call in parallel, read-only.
- Filter: tags (all-match), provider_kind, binding_state, page_size, page_token.
- Default page_size: 50. Maximum: 200 (open question OQ-HC-3).
- Error: HOST_TRANSIENT if the KV layer is temporarily unavailable.
- Audit: no audit event emitted by this call. Read operations are not audited at the binding level.

**`GetBinding(GetBindingRequest) → GetBindingResponse`**

Wraps `BindingStore.Get`. Called by the orchestrator at rotation time to fetch the authoritative binding state after acquiring the per-binding lock (T5 §4.2 step 1→3).

- Idempotency: safe to retry, read-only.
- Error: HOST_NOT_FOUND if the name does not exist (maps from `binding.ErrNotFound`).
- No audit event emitted.

**`SaveBindingMetadata(SaveBindingMetadataRequest) → SaveBindingMetadataResponse`**

Persists the four metadata fields the orchestrator owns after a successful (or partial) rotation: `LastGeneration`, `LastRotatedAt`, `BindingState`, `LastCredentialUUID`. It does NOT replace the full binding record. The host implements this as a read-modify-write under the binding store's write mutex:

```
read current binding
validate patch.last_generation >= current.LastGeneration (reject regression)
update only the four patch fields
write back via BindingStore.Save
```

This prevents race conditions with concurrent `kpm cred register`/`remove` calls (`BindingStore.Save` in `internal/credentials/binding/binding.go` line 257 replaces the full record).

- Idempotency: calling with the same patch twice is safe (generation check is `>=`, not `>`).
- Concurrent calls for the same binding name: serialized by the host.
- Concurrent calls for different binding names: parallel-safe.
- Error: HOST_NOT_FOUND if binding missing; HOST_PERMANENT if generation regression; HOST_TRANSIENT if KV unavailable.
- No audit event emitted from this call — the orchestrator emits `OperationBindingRotate` via `EmitAudit` (step 6 in T5 §4.2).

### 2.2 Provider Invocation

**`VendCredential(VendCredentialRequest) → VendCredentialResponse`**

The host looks up the provider plugin by `provider_kind` in the provider registry (`internal/plugin/registry.go` — the existing `Registry` type), calls `CredentialVenderService.Vend`, and returns the `VendedCredential`. The orchestrator never holds provider plugin handles directly; the host is the single point of dispatch.

This corresponds to T5 §4.2 step 3 ("Call `CredentialVenderService.Vend`").

- Idempotency: NOT idempotent. Each call mints a new credential at the provider.
- Error: HOST_NOT_FOUND if provider_kind unregistered; HOST_TRANSIENT if provider plugin subprocess is restarting; HOST_PERMANENT if the provider rejects the vend.
- Audit: open question OQ-HC-4 (see §6). Pending coordinator decision, the orchestrator is responsible for calling `EmitAudit` before and after `VendCredential` — the host does not auto-emit for this call to avoid double-emission with the provider's own audit events.
- Ordering: the orchestrator must emit `binding_rotate_start` via `EmitAudit` before calling `VendCredential` (T5 §4.2 step 2→3). The host does not enforce this.

### 2.3 Destination Invocation

**`DeliverToDestination(DeliverToDestinationRequest) → DeliverToDestinationResponse`**

The host dispatches to the named destination plugin's `Deliver` RPC. All fields mirror `DeliverRequest` in `destination.proto` (line 99). The host maps `DestinationErrorCode` onto `HostCallbackErrorCode` in the response:

| DestinationErrorCode | HostCallbackErrorCode |
|---|---|
| DESTINATION_OK | HOST_OK |
| DESTINATION_TRANSIENT | HOST_TRANSIENT |
| DESTINATION_PERMANENT | HOST_PERMANENT |
| DESTINATION_GENERATION_REGRESSION | HOST_PERMANENT |
| DESTINATION_TARGET_NOT_FOUND | HOST_NOT_FOUND |
| DESTINATION_PERMISSION_DENIED | HOST_PERMISSION_DENIED |

This mapping lets the orchestrator's retry logic operate uniformly over both provider and destination errors without knowing which plugin type it called.

- Idempotency: idempotent via `delivery_id` (per `DeliverRequest` semantics in `destination.proto` line 130).
- Parallel calls for different `destination_kind` values: safe (T5 §4.2 step 4, bounded pool of 4).
- Error: HOST_NOT_FOUND if destination_kind not registered.
- Audit: the host emits `OperationDestinationDeliver` per-destination during dispatch (as documented in T5 §5: "Per-destination audit events are emitted by the OSS host at the time of each Deliver call"). The orchestrator does NOT call `EmitAudit` for delivery events.

**`RevokeAtDestination(RevokeAtDestinationRequest) → RevokeAtDestinationResponse`**

Symmetric to `DeliverToDestination`. The host dispatches `DestinationDelivererService.Revoke`. Used when the orchestrator wants to clean up a credential from a destination after rotation (destination-side cleanup distinct from provider-side revocation).

- Idempotency: idempotent — `DESTINATION_OK` returned if credential already absent.
- Error: HOST_PERMANENT if destination plugin reports inability to remove (non-fatal for the rotation, per T5 §4.2).

### 2.4 Provider Revocation (Grace-Period Old-Credential Cleanup)

**`RevokeCredential(RevokeCredentialRequest) → RevokeCredentialResponse`**

The host looks up the credential by UUID in the audit store, identifies its `provider_kind`, and dispatches to the provider plugin's Revoke RPC (not yet defined in `plugin.proto` — separate task). This is the mechanism for T5 §4.2 step 7: "revoke the old credential at the provider."

- Idempotency: idempotent. Already-revoked or provider-unknown credentials return HOST_OK.
- Error: HOST_NOT_FOUND if UUID not in audit store; HOST_TRANSIENT if provider plugin restarting; HOST_PERMANENT if provider permanently rejects.
- Revocation failure is non-fatal (T5 §4.2 step 7): the orchestrator logs `"old_credential_revoke_failed"` anomaly and continues.
- Audit: the orchestrator emits `OperationRevoke` via `EmitAudit` after calling this method.

### 2.5 Audit Emission

**`EmitAudit(EmitAuditRequest) → EmitAuditResponse`**

The orchestrator passes an `AuditEventProto` to the host, which maps it onto `audit.AuditEvent` (filling in `EventID`, `Timestamp`, `SchemaVersion` from the host), calls `AuditEvent.Validate()`, and passes it to `audit.Auditor.Log`. The Auditor is already constructed and injected into the host at startup.

This is the critical integration point: it keeps the orchestrator's audit trail in the same unified stream as OSS-side events, enabling forensics queries to join the full rotation chain by `AgentSession` (= `rotation_correlation_id`, T5 §5).

- Idempotency: NOT idempotent. Each call writes a new event with a host-generated EventID.
- Error: HOST_PERMANENT if `AuditEvent.Validate()` fails (key material in free-text field, invalid `InvalidationReason`); HOST_TRANSIENT if audit sink unavailable.
- Security: the host runs `AuditEvent.Validate()` as a server-side firewall — a buggy orchestrator plugin cannot inject malformed events into the audit chain.

### 2.6 Pending Revocation Queue

These three methods together implement the grace-period durability mechanism (T5 §4.2 step 7, OQ-T5-5 resolved: KV persistence confirmed).

**`EnqueueRevocation(credential_uuid, scheduled_at) → ()`**

Host persists to `EncryptedKV` under key `"orchestrator/pending-revocations/<credential_uuid>"`. Called by the orchestrator immediately after step 6 when `GracePeriodSeconds > 0`.

- Idempotency: idempotent (upsert; later `scheduled_at` wins).
- Linearizability: serialized with `DrainPendingRevocations` via KV write mutex. An entry enqueued before a drain with `now >= scheduled_at` is guaranteed visible.
- Error: HOST_TRANSIENT if KV unavailable.

**`DrainPendingRevocations(now) → []PendingRevocation`**

Returns all entries whose `scheduled_at <= now`. Called on orchestrator startup (to replay crash-surviving entries, T5 §4.5) and periodically (recommended: every 60 seconds).

- Idempotency: idempotent. Returning the same entry twice is safe — `RevokeCredential` and `AckRevocation` are both idempotent.
- Does not remove entries — `AckRevocation` does.
- Error: HOST_TRANSIENT if KV unavailable.

**`AckRevocation(credential_uuid) → ()`**

Host removes the entry from `EncryptedKV`. Called after `RevokeCredential` succeeds.

- Idempotency: idempotent — acking an already-removed UUID returns HOST_OK.
- Error: HOST_TRANSIENT if KV unavailable.

---

## 3. Type Schema

### 3.1 Reused Types (from `plugin.proto`, same package)

- `Scope` — reused verbatim in `Binding.scope` and `VendCredentialRequest.scope`.
- `VendedCredential` — reused verbatim in `VendCredentialResponse.credential`.
- `KindRequest`, `KindResponse`, `CapabilitiesRequest`, `CapabilitiesResponse` — reused for the `RotationOrchestratorService` Init/Kind/Capabilities RPCs (Part 2).

### 3.2 New Types

**`HostCallbackErrorCode`** — error enum mirroring `DestinationErrorCode` (destination.proto line 41). Five values: `HOST_OK`, `HOST_NOT_FOUND`, `HOST_TRANSIENT`, `HOST_PERMANENT`, `HOST_PERMISSION_DENIED`. Every response carries this field plus `error_message`.

**`Binding`** — wire representation of `CredentialBinding` (`binding.go` line 38). Twelve fields covering all struct fields. `ProviderParams` and destination `Params` are `google.protobuf.Struct` because they are opaque to the binding layer. `RotationPolicy` is expanded inline into `BindingRotationPolicy` which includes the Pro-extended fields (T5 §3.1): `schedule`, `grace_period_seconds`, `max_delivery_attempts`. `Metadata` fields are flattened into the top-level `Binding` message (no nested `BindingMetadata` message) to reduce message nesting depth.

**`BindingMetadataPatch`** — partial update message for `SaveBindingMetadata`. Contains only the four fields the orchestrator is permitted to write: `last_generation`, `last_rotated_at`, `binding_state`, `last_credential_uuid`. Restricting to a patch prevents the orchestrator from overwriting `provider_kind`, `destinations`, or other operator-set fields. This directly resolves OQ-HC-1 (coordinator decision: patch, not full Binding).

**`AuditEventProto`** — thin wire shape mapping to `audit.AuditEvent` (`events.go` line 97). Omits fields the host always sets itself: `EventID`, `Timestamp`, `SchemaVersion`. Includes the ten fields the orchestrator provides: `operation`, `credential_uuid`, `credential_type`, `caller_id`, `outcome`, `error_detail`, `anomalies`, `agent_session`, `invalidation_reason`, `rule_id`. The `agent_session` field carries the `rotation_correlation_id` (EventID of the `binding_rotate_start` event) throughout the rotation chain.

**`PendingRevocation`** — three fields: `credential_uuid`, `scheduled_at`, `retry_count`. The host increments `retry_count` on each drain that surfaces the entry without a subsequent Ack; it is informational and not used by the host for any scheduling decision.

**`BindingFilter`** and **`BindingList`** — pagination wrapper. `BindingList` embeds error fields directly (no separate response wrapper) following the pattern of `VendResponse` in `plugin.proto` (line 204).

---

## 4. Concurrency Contracts

| Operation | Parallel safety | Serialization |
|---|---|---|
| `ListBindings` | Safe — read-only; KV reads are concurrent | None needed |
| `GetBinding` | Safe — read-only | None needed |
| `SaveBindingMetadata` for different bindings | Safe | Independent KV keys |
| `SaveBindingMetadata` for the same binding | Host serializes | Binding store write mutex |
| `VendCredential` | Safe — provider plugins are designed for concurrent Vend calls | None (each call is independent) |
| `DeliverToDestination` for different destinations | Safe — orchestrator's bounded pool of 4 (T5 §4.2 step 4) | None |
| `DeliverToDestination` for same destination | Safe — destination plugins handle concurrency | None |
| `RevokeAtDestination` | Same as `DeliverToDestination` | None |
| `RevokeCredential` | Safe | None |
| `EmitAudit` | Safe — Auditor.Log is designed for concurrent calls | None |
| `EnqueueRevocation` vs `DrainPendingRevocations` | Linearizable | KV write mutex |
| `AckRevocation` | Safe — idempotent removes | None |

The orchestrator's per-binding rotation lock (T5 §4.1, `sync.Mutex` per binding name) ensures that `VendCredential` → `DeliverToDestination` × N → `SaveBindingMetadata` for a single binding run serially. The host's `SaveBindingMetadata` serialization is a second layer of defense for the edge case where two plugin goroutines race (which should not occur under the per-binding lock, but the host does not assume the plugin's locking is correct).

The host does NOT guarantee ordering between calls to different methods. The orchestrator is responsible for correct sequencing (emit `binding_rotate_start`, then `VendCredential`, then `DeliverToDestination` × N, then `SaveBindingMetadata`, then `EmitAudit` for the final rotation event, then `EnqueueRevocation` if grace period).

---

## 5. Error Model

Every response message carries `error_code HostCallbackErrorCode` and `error_message string`. The `error_message` is always a human-readable string safe for operator logs (no key material — the host validates this before returning). The caller (orchestrator) makes retry decisions based solely on `error_code`, never on `error_message` content.

**Retry decision table (orchestrator's responsibility):**

| error_code | Retry? | Orchestrator action |
|---|---|---|
| HOST_OK | N/A | Continue |
| HOST_NOT_FOUND | No | Log error; fail the rotation step |
| HOST_TRANSIENT | Yes, with backoff | Apply exponential backoff (same 1s/60s/5-attempt policy as delivery retries, T5 §4.3) |
| HOST_PERMANENT | No | Log error; fail the rotation step permanently |
| HOST_PERMISSION_DENIED | No | Log error; alert; investigate plugin signing |

**Per-method error constraints** (callers must observe these invariants):

- `VendCredential` returning HOST_TRANSIENT: do not retry within the same rotation lock hold. Release the lock, emit error audit event, and let the next scheduled trigger retry.
- `SaveBindingMetadata` returning HOST_PERMANENT (generation regression): this indicates a bug in the orchestrator (called Save twice for the same rotation). Log `FATAL`-level and halt the rotation — do not retry.
- `EmitAudit` returning HOST_PERMANENT: the event contains prohibited content. The orchestrator must not silently discard; it should log the failure and alert. Rotation may continue (audit failure is non-fatal for the credential rotation itself, but it is a compliance event).
- `RevokeCredential` returning HOST_PERMANENT: revocation failure is non-fatal per T5 §4.2 step 7. Log anomaly, emit `OperationRevoke` with `OutcomeError`, continue.

---

## 6. Open Questions for Coordinator

**OQ-HC-1: SaveBindingMetadata — patch vs full Binding** (recommendation: patch)

This design uses a `BindingMetadataPatch` message containing only the four fields the orchestrator owns. The alternative is accepting the full `Binding` and having the host merge it. Patch is safer (prevents accidental overwrites of operator-configured fields) and makes the contract explicit. Tradeoff: if the orchestrator needs to update a fifth field in the future, a proto change is required.

**Decision needed:** confirm patch approach is acceptable.

**OQ-HC-2: EmitAudit — structured fields vs pre-marshaled blob**

This design sends structured fields (ten typed proto fields that the host assembles into `audit.AuditEvent`). The alternative is having the orchestrator marshal the `AuditEvent` to JSON and pass an opaque bytes blob. Structured fields are preferable: they let the host enforce `AuditEvent.Validate()` server-side and make the wire format inspectable. The tradeoff is that `AuditEventProto` must track `AuditEvent` field additions (any new audit field the orchestrator needs requires a proto change).

**Decision needed:** confirm structured fields approach.

**OQ-HC-3: ListBindings pagination defaults**

Draft default page_size: 50. Maximum: 200. For a solo developer running dozens to low hundreds of bindings, a single page is likely sufficient; pagination is included for correctness, not expected load. The orchestrator loads all bindings at startup, so a large page size reduces round trips.

**Decision needed:** confirm defaults, or specify different values.

**OQ-HC-4: VendCredential — host auto-emit of OperationCredentialVend audit event**

When the host dispatches `VendCredential`, the existing provider vend path in `internal/credentials/vend.go` emits `OperationCredentialVend` to the audit log (for LLM session vends). Provider plugins for binding rotation (e.g. `github-app-token`) may or may not emit their own vend audit events.

Two options:
- (A) Host auto-emits `OperationCredentialVend` within `VendCredential` dispatch, in addition to whatever the provider plugin emits. Risk: double-emission if the provider plugin also emits.
- (B) Host does NOT auto-emit. The orchestrator calls `EmitAudit` with `binding_rotate_start` (step 2) and `binding_rotate` (step 6); the per-credential vend event is implicit. Risk: some audit consumers expect an `OperationCredentialVend` for every minted credential.

Recommendation: (B), because the orchestrator's `binding_rotate_start` event already records `credential_type` and the rotation context. Adding a vend event requires coordination with provider plugin authors.

**Decision needed:** confirm (B), or specify how to handle double-emission risk if (A) is chosen.

**OQ-HC-5: Plugin connection failure during rotation — fail-closed or fail-open**

If the `HostService` gRPC connection drops mid-rotation (host crash, subprocess restart), the orchestrator's in-flight calls return transport errors. The orchestrator should fail-closed (abort the rotation, release the lock, let the next trigger attempt retry). The alternative is fail-open (proceed with partial data). Fail-closed is strongly recommended — a rotation that cannot reach the binding store should not attempt delivery.

**Decision needed:** confirm fail-closed. If fail-open is preferred for any specific method, identify it.

**OQ-HC-6: Startup race — webhook received before HostService connected**

Noted in T5 OQ-T5-8: there is a startup window between OSS host start and orchestrator plugin `Init` completing where a webhook could arrive and fall through to the revoker-only path. The HostService design does not change this window (it may add a few milliseconds for the broker dial). The recommendation remains: accept the startup race (window is well under one second); if desired, add a `ready` channel to `AlertOrchestrator` that blocks webhook dispatch until `SetRotationHook` completes.

**Decision needed:** confirm startup race is acceptable, or request the `ready` channel approach.

---

## 7. Files Needed by Part 2 (Preview)

Part 2 is the implementation pass. It will touch the following files (not exhaustive, implementation agent scopes itself):

**New OSS files:**
- `internal/plugin/host_service.go` — `HostService` gRPC server implementation (wraps `BindingStore`, provider registry, destination registry, `Auditor`, `EncryptedKV` for the revocation queue).
- `api/plugin/v1/host.pb.go` — generated from `host.proto` (regenerate with protoc).
- `api/plugin/v1/host_grpc.pb.go` — generated gRPC stubs from `host.proto`.

**Modified OSS files:**
- `internal/plugin/host.go` — add `StartOrchestrator` method (analogous to `StartDestination`, lines 384–491), add broker setup and `HostService` registration, pass broker ID to plugin via `Init` RPC.
- `internal/plugin/plugins.go` — add `"rotation_orchestrator"` key to `PluginMap`.

**New Pro repo files** (in `agentkms-pro`, the separate closed-source repo):
- `internal/host/client.go` — `HostServiceClient` wrapper consumed by the orchestrator. Implements `broker.Dial`, constructs the gRPC client, exposes typed Go methods matching the `HostService` RPC surface.
- `internal/orchestrator/rotation.go` — the Pro rotation state machine (T5 §4.2 steps 1–8) that calls `client.VendCredential`, `client.DeliverToDestination`, `client.SaveBindingMetadata`, `client.EmitAudit`, etc.
- `internal/orchestrator/cron.go` — cron driver (T5 §3.2).
- `internal/orchestrator/hook.go` — `RotationHook` interface implementation; calls back into the rotation state machine from `TriggerRotation`.

**Not touched by Part 2:**
- `internal/webhooks/rotation_hook.go` — already landed in Part 1.
- `internal/webhooks/orchestrator.go` — already updated in Part 1 with `SetRotationHook`.
- `api/plugin/v1/host.proto` — produced by this Part 1.5 design pass; Part 2 runs `protoc` on it.
