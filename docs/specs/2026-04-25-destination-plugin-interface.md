# Destination Plugin Interface Specification

**Date:** 2026-04-25
**Author:** Spec agent (read-only research pass)
**Status:** Draft — awaiting coordinator review before implementation
**Related:**
- `api/plugin/v1/plugin.proto` — existing provider plugin wire format
- `internal/plugin/` — host, registry, grpcadapter, plugins, signing
- `docs/design/2026-04-16-dynamic-secrets.md` — credential lifecycle context
- `docs/design/2026-04-16-scoped-credential-vending.md` — vending pipeline

---

## 1. Purpose and Mental Model

The provider plugin interface answers the question: "how do I mint a credential?"
The destination plugin interface answers the symmetric question: "where do I put it?"

A destination plugin receives a vended credential value from the AgentKMS orchestrator and writes it into a consumer-side target — a GitHub Actions repository secret, a Kubernetes Secret object, a `.env` file, a HashiCorp Vault KV path, a `systemd-creds` unit, etc. The plugin owns every byte of I/O against that target system. The orchestrator owns policy, ordering, audit, and retry decisions.

This interface is not a secret store. It is a delivery channel. The credential already exists when `Deliver` is called; the plugin's job is transport and confirmation, not issuance.

---

## 2. Provider Interface Summary (Reference Baseline)

This section documents the existing provider interface that the destination spec mirrors. Any divergence below this baseline is called out explicitly.

### 2.1 Wire encoding

Standard protobuf binary (proto3) over gRPC, transported by `hashicorp/go-plugin` with `ProtocolGRPC`. The JSON codec used pre-v0.3.1 was removed in commit `ef5fd5a1` to restore Python interop; do not reintroduce it.

### 2.2 Handshake

```
ProtocolVersion:  1
MagicCookieKey:   "PLUGIN_MAGIC_COOKIE"
MagicCookieValue: "agentkms_plugin_v1"
```

All plugins share one handshake config. PluginMap keys identify services inside a single binary. A plugin binary may implement multiple services.

### 2.3 Plugin map keys (existing)

| Map key            | Service interface           | Role          |
|--------------------|-----------------------------|---------------|
| `scope_validator`  | `ScopeValidatorService`     | required      |
| `scope_analyzer`   | `ScopeAnalyzerService`      | optional      |
| `scope_serializer` | `ScopeSerializerService`    | optional      |
| `credential_vender`| `CredentialVenderService`   | optional      |

### 2.4 Lifecycle (existing)

1. Host discovers binaries matching `agentkms-plugin-*` in plugin dir.
2. Host verifies Ed25519 `.sig` sidecar (if verifier configured).
3. `hashicorp/go-plugin` forks subprocess; gRPC handshake negotiated.
4. Host dispenses `scope_validator`, calls `Kind()` RPC, registers adapter.
5. Background goroutine pings every 30 s; single restart on failure.
6. `StopAll()` kills all subprocesses on host shutdown.

### 2.5 Error model (existing)

Errors are returned as a string field in the response message (`error string` in every `*Response`). Empty string = success. gRPC transport errors are wrapped by the adapter and returned as Go errors. There is no structured error code enum in the provider interface; this is a known weakness (see §8.3).

### 2.6 Service identification

Every service exposes a `Kind(KindRequest) → KindResponse` RPC that returns the discriminator string the plugin handles (e.g., `"aws-sts"`, `"github-pat"`). This RPC is called once at startup; the kind is stored on the adapter struct. The registry maps kind strings to adapters.

---

## 3. Destination Plugin: Design Philosophy

Three governing principles drive the choices below:

**Symmetric structure, symmetric host code.** Every divergence from the provider pattern adds host-side complexity. Destination plugins use the same `HandshakeConfig`, the same `PluginMap` extension pattern, the same `GRPCPlugin` adapter shape, the same `Kind()` registration RPC, and the same `Registry` map pattern. The implementation agent should be able to copy `grpcadapter.go` as a scaffold.

**Orchestrator owns policy; plugin owns transport.** The plugin must never decide whether a delivery is allowed. That decision is made before `Deliver` is called. The plugin must never store the credential value beyond the duration of the `Deliver` call. The plugin must confirm success or failure honestly — optimistic success responses are a security defect, not a performance optimization.

**Idempotency is a first-class contract, not a courtesy.** Rotation, restarts, and network partitions will cause the orchestrator to call `Deliver` more than once for the same logical credential update. Plugins must be designed so that a second identical `Deliver` produces the same observable outcome as the first — not an error, not a duplicate entry. The generation number field provides the ordering invariant needed to make this tractable.

---

## 4. Core RPC Operations

### 4.1 `Kind(KindRequest) → KindResponse`

Identical to the provider interface. Returns the destination kind discriminator (e.g., `"github-secret"`, `"k8s-secret"`, `"env-file"`, `"vault-kv"`, `"systemd-creds"`). Called once at startup. No divergence from provider pattern.

### 4.2 `Validate(ValidateDestinationRequest) → ValidateDestinationResponse`

Pre-flight check. Called before the first `Deliver` to verify that the target is reachable and the plugin's credentials are sufficient to write to it. Does not write any secret material.

**Rationale for pre-flight:** Provider plugins have an analogous concept in `ScopeValidatorService.Validate` (structural check) and `ScopeAnalyzerService.Analyze` (risk signals). For destinations the pre-flight is more operational — "can I connect to the GitHub API with the stored token?" — but the pattern is the same: a cheap read-only check that surfaces misconfiguration before the first real credential rotation attempt.

Contract: `Validate` must complete in under 10 seconds. It must not cache its result; the orchestrator may call it on a schedule independently of `Deliver`. A `Validate` that returns success is not a guarantee that a subsequent `Deliver` will succeed (the target may become unavailable in the interim); it is only a best-effort preflight.

### 4.3 `Deliver(DeliverRequest) → DeliverResponse`

The primary RPC. Writes the credential value to the destination target.

**Idempotency contract:** Multiple calls with the same `generation` and the same `target_id` must be safe. The plugin must not create duplicate entries, increment counters, or fail with "already exists". Full overwrite semantics are the required implementation strategy: on each `Deliver` call, write the new value unconditionally to the target, replacing whatever was there. If the target system itself supports ETags or version numbers (GitHub Secrets API uses sodium-encrypted values, Kubernetes Secrets use `resourceVersion`), the plugin uses them internally to ensure it is overwriting the correct prior version — but from the orchestrator's perspective, `Deliver` is always "write this value now".

The `generation` field is a monotonically increasing integer provided by the orchestrator. It increments each time a new credential is minted for the same logical name (i.e., on each rotation). The plugin MUST NOT deliver a `generation` lower than the last successfully delivered generation. If the orchestrator sends a lower generation (which should not happen in normal operation but can happen during recovery from a bug), the plugin must return a permanent error with code `GENERATION_REGRESSION`. This prevents stale credentials from overwriting fresh ones during retry storms.

**Divergence from provider pattern:** Provider plugins have no idempotency concept because credential minting is inherently non-idempotent (a second `Vend` call mints a second distinct credential). Delivery is idempotent by design. The `generation` field and the regression-rejection rule have no provider-side equivalent.

### 4.4 `Revoke(RevokeDestinationRequest) → RevokeDestinationResponse`

Removes the credential value from the target. Called when a credential is decommissioned — on explicit operator revocation, on end-of-life expiry cleanup, or when a security event triggers immediate invalidation.

`Revoke` is idempotent: if the target no longer contains the credential (already deleted, already rotated away), the plugin must return success, not an error. The observable post-condition is "credential not present at target"; whether it was absent already is irrelevant.

`Revoke` is optional to implement but not optional to declare. The plugin binary must expose the `DestinationDelivererService` service and implement `Revoke`. If the destination type has no meaningful revocation (e.g., a write-once append log), the implementation returns a permanent error with human-readable message explaining the limitation. The orchestrator logs this and continues; it does not block the broader revocation flow.

**Rationale for mandatory declaration:** Making `Revoke` optional-to-implement via a separate service (analogous to `ScopeAnalyzerService` being optional) would require the host to negotiate capabilities at startup and maintain a two-tier dispatch path. The complexity cost exceeds the benefit. Destinations that cannot revoke return a well-typed error; the orchestrator handles it. This is simpler than capability negotiation.

### 4.5 `Health(HealthRequest) → HealthResponse`

Liveness probe. Called by the host health loop (every 30 s, mirroring the existing provider ping interval) in addition to the `hashicorp/go-plugin` protocol-level ping. The protocol ping verifies the subprocess is alive; `Health` verifies the destination is reachable.

`Health` must respond within 5 seconds. It may perform a lightweight connectivity check (e.g., `GET /` against the GitHub API, a Kubernetes API server version call) but must not write any data. On failure it returns a non-empty `error` string; the host logs the failure, increments an internal error counter, and triggers the existing restart logic after the same threshold as provider plugins (one restart attempt, then mark failed).

**Divergence from provider pattern:** Provider plugins do not expose a `Health` RPC; the host uses only the protocol-level ping. Destinations are persistent long-running deliverers (not one-shot RPC callers), so connectivity to the target system matters independently of subprocess liveness. A destination plugin can be alive as a process but unable to reach GitHub if a network policy changed. `Health` surfaces this.

---

## 5. Idempotency Contract (Detailed)

The orchestrator guarantees the following delivery invariants:

1. **Single in-flight:** For a given `(target_id, credential_name)` pair, the orchestrator will not issue a second `Deliver` until the first has returned (success or permanent error).
2. **Retry on transient:** On transient error, the orchestrator will retry with exponential backoff with jitter (base 1 s, max 60 s, up to 5 attempts). Each retry carries the same `generation` and same `delivery_id`. The plugin must recognize retry calls by their `delivery_id` (a UUID generated by the orchestrator at the start of each rotation event) and not treat them as independent operations.
3. **No delivery after permanent error:** On permanent error, the orchestrator does not retry. It records the failure, alerts via the existing `Notifier` interface, and flags the destination as degraded.
4. **Generation ordering:** The orchestrator guarantees that `generation` values are strictly increasing over the lifetime of a credential. On restart recovery, it reads the last confirmed `generation` from the audit log before resuming delivery.

The plugin's idempotency implementation strategy:

- On `Deliver`, write the value unconditionally. Record the `(delivery_id, generation)` pair in plugin-local state (in-memory is acceptable; durability of this state is not required because the orchestrator is the source of truth).
- If a second `Deliver` arrives with the same `delivery_id` before a response to the first was sent (possible during rapid failover), return the cached result.
- If `generation` in the request is less than the last successfully delivered `generation`, return `GENERATION_REGRESSION` permanent error.

---

## 6. Partial-Failure Model

When one credential has N configured destinations and some `Deliver` calls fail:

**Transient failures** are errors the plugin expects to resolve without operator intervention: network timeouts, API rate limits, temporary credential expiry on the plugin's own service account. The plugin signals transient failure by returning a non-empty `error` string with `is_transient: true` in the response. The orchestrator retries according to §5 above.

**Permanent failures** are errors requiring operator action: target does not exist, plugin's service account lacks write permission, generation regression. The plugin signals permanent failure with `is_transient: false`. The orchestrator does not retry, records the failure in the audit log with the full error string, and escalates via the `Notifier` interface. Other destinations in the same rotation batch continue independently.

**Orchestrator contract for partial batches:** The orchestrator does not roll back successful deliveries when a sibling destination fails permanently. Each destination is delivered independently. The audit log records per-destination success/failure. An operator resolving a permanent failure may trigger a manual re-delivery (future `kpm destination deliver` CLI command; out of scope for this spec). The rationale: rollback would require the orchestrator to call `Revoke` on already-delivered destinations, which reintroduces the partial-failure problem recursively. Independent delivery with full audit visibility is operationally simpler.

**Retry safety:** `Deliver` is idempotent (§5), so the orchestrator is safe to retry without risk of duplicate credential entries at the target.

---

## 7. Metadata Schema

### 7.1 `DeliverRequest` fields

| Field              | Type                        | Description |
|--------------------|-----------------------------|-------------|
| `target_id`        | `string`                    | Opaque identifier for the specific secret slot within the destination. Format is kind-specific (see §7.3). |
| `credential_value` | `bytes`                     | The raw credential bytes to deliver. Plugins must not log this field. |
| `generation`       | `uint64`                    | Monotonically increasing rotation counter. Zero is invalid. |
| `delivery_id`      | `string`                    | UUID v4 assigned by the orchestrator for this rotation event. Used for idempotent retry detection. |
| `ttl_seconds`      | `int64`                     | Hint: the credential's expected lifetime in seconds. Informational only; the destination may or may not support TTL on stored secrets. |
| `expires_at`       | `google.protobuf.Timestamp` | Wall-clock expiry of the credential. Informational hint for destinations that can store expiry metadata alongside the value. |
| `requester_id`     | `string`                    | Stable identity string of the entity that triggered this vend (from mTLS cert CN or AgentKMS identity). Written to destination-side metadata where the destination supports it; used for attribution. |
| `credential_uuid`  | `string`                    | UUID of the `VendedCredential` this delivery corresponds to. Used for audit correlation between the vend event and the delivery event. |
| `params`           | `google.protobuf.Struct`    | Kind-specific delivery parameters (e.g., visibility scope for GitHub secrets, namespace for k8s secrets). Shape defined by the plugin. Equivalent to `Scope.Params` in the provider interface. |

### 7.2 `DeliverResponse` fields

| Field          | Type     | Description |
|----------------|----------|-------------|
| `error`        | `string` | Empty on success. Human-readable error string on failure. |
| `is_transient` | `bool`   | True if `error` is non-empty and the failure is transient (orchestrator should retry). False for permanent failures. Ignored when `error` is empty. |

### 7.3 Target identifier format

`target_id` is a kind-scoped opaque string. The format is defined per plugin kind and documented in the plugin's README. Examples:

| Kind              | Example `target_id`                          | Notes |
|-------------------|----------------------------------------------|-------|
| `github-secret`   | `owner/repo:SECRET_NAME`                     | Colon separates repo path from secret name. Organization secrets use `org/ORG_NAME:SECRET_NAME`. |
| `k8s-secret`      | `namespace/secret-name:key`                  | Colon separates Secret object name from data key within the object. |
| `env-file`        | `/etc/agentkms/envs/prod.env:API_KEY`        | Absolute path to the file, colon, then the variable name. |
| `vault-kv`        | `secret/data/myapp:api_key`                  | Vault KV v2 path, colon, then the field name within the KV entry. |
| `systemd-creds`   | `myservice.service:ANTHROPIC_API_KEY`        | Unit name, colon, then the credential name. |

**Rationale for `owner/repo:SECRET_NAME` over URI scheme:** A URI scheme like `gh-secret://owner/repo/SECRET_NAME` is visually appealing but introduces a parsing layer with no benefit — the plugin already knows its own kind, and the orchestrator does not need to introspect `target_id` contents. A simple colon delimiter is sufficient and consistent across kinds. If the coordinator wants URI schemes for CLI UX (e.g., `kpm destination list gh-secret://...`), that is a CLI-layer concern, not a wire-format concern. The `target_id` on the wire remains opaque to the orchestrator.

### 7.4 `ValidateDestinationRequest` / `ValidateDestinationResponse`

Request carries only `params` (`google.protobuf.Struct`) — the same kind-specific config the plugin would receive on `Deliver`. No credential value is passed. Response carries `error` (string, empty on success). No `is_transient` field on validate responses: a failed pre-flight is always considered a configuration error (permanent) from the orchestrator's perspective.

### 7.5 `RevokeDestinationRequest` / `RevokeDestinationResponse`

Request carries `target_id`, `credential_uuid`, `generation`, and `params`. Response carries `error` and `is_transient` (same semantics as `DeliverResponse`).

### 7.6 `HealthRequest` / `HealthResponse`

`HealthRequest` is intentionally empty (mirrors `KindRequest`). `HealthResponse` carries `error` (empty = healthy) and `latency_ms` (`int64`, optional, for observability).

---

## 8. Plugin Handshake and Registration

### 8.1 Handshake config

Identical to the provider interface. No new `MagicCookieValue` variant is needed. The destination plugin binary uses the same environment variable and the same cookie value (`agentkms_plugin_v1`). Rationale: the handshake config is a process-level authentication mechanism, not a service-level one. A single binary may register both provider and destination services.

### 8.2 PluginMap key

Add `"destination_deliverer"` to `PluginMap` in `internal/plugin/plugins.go`. The map key must match the name passed to `rpcClient.Dispense()` in the host `Start()` method. This is the only host-side change to the map registration code.

### 8.3 Registry entry

Add a `deliverers map[string]DestinationDeliverer` map to `Registry`, with `RegisterDeliverer`, `LookupDeliverer`, and `DelivererKinds` methods, mirroring the existing pattern for validators, analyzers, serializers, and venders exactly. No new locking primitives are needed; the existing `sync.RWMutex` on `Registry` guards all maps.

### 8.4 Startup sequence

After handshake, the host dispenses `"destination_deliverer"` and calls `Kind()` to get the destination kind string. It calls `Validate()` with an empty-or-config-loaded `params` as a startup health check. On success, registers the adapter in the registry. On failure, logs the error and does not register — the destination is considered unavailable. The host background loop calls `Health()` every 30 s (same interval as existing protocol ping).

### 8.5 Naming: plugin binary prefix

Destination plugin binaries use the same prefix convention: `agentkms-plugin-<name>`. The destination kind is not encoded in the binary name; it is declared by the `Kind()` RPC. Example binary names: `agentkms-plugin-github-secret`, `agentkms-plugin-k8s-secret`.

---

## 9. Go Interface (`internal/credentials` or `internal/destination`)

The implementation agent should define the Go interface in a new package `internal/destination` (not `internal/credentials`) to avoid coupling the credential vending pipeline to the delivery pipeline. The interface:

```go
// DestinationDeliverer writes credential values to a consumer-side target.
// Implementations must be safe for concurrent use.
type DestinationDeliverer interface {
    // Kind returns the destination kind this deliverer handles (e.g. "github-secret").
    Kind() string

    // Validate performs a pre-flight connectivity and permission check.
    // Must not write any secret material. Must complete within 10 seconds.
    Validate(ctx context.Context, params map[string]any) error

    // Deliver writes value to the target identified by targetID.
    // Idempotent: multiple calls with the same deliveryID and generation are safe.
    // Returns (false, err) for transient errors; (true, err) for permanent errors.
    // Returns (false, nil) on success (isPermanent is meaningless when err is nil).
    Deliver(ctx context.Context, req DeliverRequest) (isPermanentError bool, err error)

    // Revoke removes the credential from the target identified by targetID.
    // Idempotent: returns nil if the credential is already absent.
    // Returns (false, err) for transient; (true, err) for permanent.
    Revoke(ctx context.Context, targetID string, generation uint64, params map[string]any) (isPermanentError bool, err error)

    // Health returns nil if the destination is reachable and writeable.
    // Must complete within 5 seconds.
    Health(ctx context.Context) error
}

// DeliverRequest is the input to DestinationDeliverer.Deliver.
type DeliverRequest struct {
    TargetID        string
    CredentialValue []byte        // SECURITY: do not log
    Generation      uint64
    DeliveryID      string        // UUID for idempotent retry detection
    TTL             time.Duration // hint
    ExpiresAt       time.Time     // hint
    RequesterID     string
    CredentialUUID  string
    Params          map[string]any
}
```

---

## 10. Audit Integration

Every `Deliver`, `Revoke`, and `Validate` call must produce an audit event via the existing `audit.Auditor` interface. The orchestrator is responsible for emitting audit events; the plugin must not emit them directly. The orchestrator passes the `credential_uuid` and `requester_id` fields from `DeliverRequest` into the audit event so that delivery events can be joined to the originating vend event in forensics queries.

New audit operation constants needed: `OperationDestinationDeliver`, `OperationDestinationRevoke`, `OperationDestinationValidate`. These follow the existing `audit.OperationRevoke`, `audit.OperationVend` naming pattern in `internal/audit/events.go`.

---

## 11. Open Questions for Coordinator

The following questions could not be resolved unilaterally during this design pass. Each has a recommended default; the coordinator should confirm or override before implementation begins.

**OQ-1: New PluginMap key vs. new HandshakeConfig**
Recommendation: single `HandshakeConfig` (same cookie value), new `PluginMap` key `"destination_deliverer"`. If a future v2 plugin protocol is anticipated, now is the right time to decide whether destinations should use a distinct cookie to enable independent versioning. Defaulting to shared cookie keeps host code simpler.

**OQ-2: Target identifier format — opaque string vs. structured type**
The spec uses an opaque `string` with kind-specific syntax conventions. An alternative is a `TargetRef` message with explicit fields (`owner`, `repo`, `secret_name`, etc. per kind). Structured types are easier to validate in the orchestrator but require the proto to be extended for each new kind. Recommended: opaque string with `params` for kind-specific data. Coordinator should confirm.

**OQ-3: `Revoke` — mandatory declaration vs. optional service**
The spec requires `Revoke` to be implemented in every destination plugin, even if it returns a permanent error. The alternative is a separate `DestinationRevokerService` that the host negotiates at startup (analogous to `ScopeAnalyzerService` being optional). Mandatory declaration is simpler for the host; optional service is more honest about capability. Coordinator should pick one.

**OQ-4: `Health` vs. protocol-level ping only**
The spec adds a `Health` RPC. If the coordinator prefers to keep destination plugins fully symmetric to provider plugins (no `Health` RPC), the host health loop can rely solely on the protocol-level ping from `hashicorp/go-plugin`. Recommend keeping `Health` because destination connectivity failures (GitHub API down, k8s API unreachable) are operationally significant and invisible to the protocol ping.

**OQ-5: Error model — string field vs. structured `ErrorCode` enum**
The existing provider interface uses a plain `error string` in every response. This is a known weakness: callers cannot distinguish error classes without string parsing. The destination interface could introduce a `DestinationErrorCode` enum (`OK`, `TRANSIENT`, `PERMANENT`, `GENERATION_REGRESSION`, `TARGET_NOT_FOUND`, `PERMISSION_DENIED`) in addition to the human-readable string. Recommendation: add the enum now; retrofitting the provider interface is a separate decision. Coordinator should confirm scope.

**OQ-6: `delivery_id` durability on the plugin side**
The spec says plugins may keep delivery state in memory (not durable). If the plugin subprocess restarts mid-rotation, it will not remember prior deliveries and will re-execute `Deliver` for the same `delivery_id`. This is safe (overwrite semantics) but means the idempotency guard against duplicate in-flight requests is lost across restarts. Coordinator should decide whether plugins must persist delivery state to a local journal.

**OQ-7: Generation number initialization**
Who assigns generation 1 for a brand-new credential? Recommendation: the orchestrator assigns generation=1 on first `Deliver`. It reads the last delivered generation from the audit log on recovery. If no prior delivery is found in the log, it uses generation=1. Confirm this is the right source of truth vs. a separate destination-side state store.

**OQ-8: Existing provider interface design weaknesses to avoid in destination**
During research the following provider interface patterns were noted as candidates for improvement that should not be replicated:
- The `error string` field in responses (see OQ-5).
- No structured `PluginCapabilities` negotiation at startup (v0.3.2 capability manifest was planned but not shipped; destination should not ship without it).
- `RegisterWithInfo` version check is strict equality (`!=`), which breaks forward compatibility; a `>=` minimum check would be more practical.
These are flagged for the coordinator; they are not fixed in this destination spec to avoid scope creep.
