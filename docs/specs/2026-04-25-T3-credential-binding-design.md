# T3 Credential Binding — Design Document

**Date:** 2026-04-25
**Sprint:** Automated Rotation Sprint (2026-04-25 – 2026-05-11)
**Track:** OSS (no license-gate, no scheduling logic)
**Status:** Implemented

---

## 1. Purpose

A `CredentialBinding` is the persistent record that ties a credential source (provider + scope) to one or more delivery destinations and an optional rotation policy hint. It is the unit of state that the rotation orchestrator (T5, Pro track) will consume; this task delivers the OSS surface: data model, storage, HTTP endpoints, and manual one-shot rotation via the CLI.

---

## 2. Data Model

```go
type CredentialBinding struct {
    // Name is the unique, human-friendly identifier for this binding.
    // Regex: ^[a-z][a-z0-9-]{0,62}$  (lowercase, starts with letter, max 63 chars).
    // Examples: "blog-audit-pat", "prod-anthropic-key".
    Name string `json:"name"`

    // ProviderKind identifies the credential provider.
    // Examples: "github-app-token", "anthropic-api-key", "aws-sts".
    ProviderKind string `json:"provider_kind"`

    // ProviderParams holds provider-specific parameters (opaque to the binding layer).
    // Examples: {"app_name": "agentkms-blog-audit"}, {"account_id": "123456789012"}.
    ProviderParams map[string]any `json:"provider_params,omitempty"`

    // Scope is the effective permissions scope for this binding.
    // Uses the existing credentials.Scope type (kind + params + TTL).
    Scope credentials.Scope `json:"scope"`

    // Destinations is the list of delivery targets for this binding.
    // At least one destination is required on register.
    Destinations []DestinationSpec `json:"destinations"`

    // RotationPolicy controls when/how rotation occurs.
    RotationPolicy RotationPolicy `json:"rotation_policy"`

    // Metadata holds operational fields managed by the server.
    Metadata BindingMetadata `json:"metadata"`
}

type DestinationSpec struct {
    // Kind is the destination plugin kind (e.g. "github-secret", "k8s-secret", "env-file").
    Kind string `json:"kind"`

    // TargetID is the opaque kind-scoped identifier for the specific secret slot.
    // Format is kind-specific; see the destination plugin interface spec §7.3.
    // Examples: "owner/repo:SECRET_NAME", "namespace/secret:key".
    TargetID string `json:"target_id"`

    // Params holds kind-specific delivery parameters (visibility, namespace, etc.).
    Params map[string]any `json:"params,omitempty"`
}

type RotationPolicy struct {
    // TTLHintSeconds is the desired credential lifetime in seconds.
    // The rotation orchestrator (T5) uses this to schedule the next rotation.
    // Zero means "use provider default".
    TTLHintSeconds int64 `json:"ttl_hint_seconds,omitempty"`

    // ManualOnly flags this binding for manual-only rotation.
    // When true, the orchestrator (T5) will not schedule automatic rotation.
    // All currently shipped bindings set this to true; scheduled rotation is Pro.
    ManualOnly bool `json:"manual_only"`
}

type BindingMetadata struct {
    // CreatedAt is the wall-clock time this binding was first registered (RFC 3339).
    CreatedAt string `json:"created_at"`

    // LastRotatedAt is the wall-clock time of the last successful rotation (RFC 3339).
    // Empty until the first rotation completes.
    LastRotatedAt string `json:"last_rotated_at,omitempty"`

    // LastGeneration is the monotonically increasing rotation counter.
    // Zero until the first rotation. Increments on each successful rotate.
    LastGeneration uint64 `json:"last_generation"`

    // Tags is a free-form list of labels for filtering (e.g. ["ci", "prod"]).
    Tags []string `json:"tags,omitempty"`
}
```

**`BindingMetadata` field reference:**

| JSON key | Type | Description |
|----------|------|-------------|
| `created_at` | string | RFC 3339 wall-clock time this binding was first registered. |
| `last_rotated_at` | string | RFC 3339 time of the last successful rotation. Empty until the first rotation. |
| `last_generation` | uint64 | Monotonically increasing rotation counter. Zero until the first rotation. |
| `tags` | []string | Free-form labels for filtering. |
| `last_credential_uuid` | string | UUID of the most recent vended credential. Used by the Pro rotation orchestrator for grace-period revocation. Empty until first successful rotation. |
| `binding_state` | string | Operational state from the rotation orchestrator's perspective. Values: `""` (initial/no rotation yet), `"ok"` (last rotation succeeded all destinations), `"degraded"` (partial failure), `"rotation_failed"` (failed before any destination was updated). Written by the Pro orchestrator via `SaveBindingMetadata`. Empty on OSS-only bindings. Stored directly in the struct field (`omitempty`); never as a synthetic tag. |

`last_credential_uuid` and `binding_state` are written by the rotation orchestrator (Pro tier) on each successful rotation and persisted via the standard `BindingStore.Save` call. OSS code does not write to these fields.

**Validation rules:**
- `name`: required, matches `^[a-z][a-z0-9-]{0,62}$`
- `provider_kind`: required, non-empty
- `destinations`: required, at least one entry; each entry requires `kind` and `target_id`
- `destination.kind`: format `^[a-z][a-z0-9-]{0,62}$`
- `destination.target_id`: non-empty

---

## 3. Storage

Bindings live in the existing `EncryptedKV` store (`internal/credentials/`) under a stable prefix:

```
bindings/<name>   →   map[string]string{"binding": "<JSON>"}
```

The `BindingStore` interface wraps a `KVWriter`:

```go
type BindingStore interface {
    Save(ctx context.Context, b CredentialBinding) error
    Get(ctx context.Context, name string) (*CredentialBinding, error)
    List(ctx context.Context) ([]CredentialBinding, error)
    Delete(ctx context.Context, name string) error
}
```

The KV implementation stores the JSON-marshalled binding under a single `"binding"` key in the field map. This follows the existing pattern used by the secrets registry (flat field maps). The prefix `bindings/` is structurally isolated from `kv/data/secrets/` and `kv/data/metadata/` so no existing path-filtering logic is affected.

---

## 4. Server Endpoints

All endpoints live in `internal/api/handlers_bindings.go` and follow the existing handler pattern (audit scaffold → policy check → storage/action → audit success → response).

| Method | Path | Operation |
|--------|------|-----------|
| `POST` | `/bindings` | Register (create or update) a binding |
| `GET` | `/bindings` | List all bindings (summary: name, provider_kind, dest count, last_rotated) |
| `GET` | `/bindings/{name}` | Full binding JSON |
| `DELETE` | `/bindings/{name}` | Remove a binding |
| `POST` | `/bindings/{name}/rotate` | Manual one-shot rotation |

**Rotate semantics:** The rotate endpoint calls the provider to vend a fresh credential, then calls `Deliver` on each registered destination via the destination registry. Before T1 merges (destination plugin registry), the registry lookup is stubbed with a `// TODO(T1-merge)` comment and returns a stub result. Each destination attempt is independent; partial failures are reported per-destination in the response body. The binding's `last_rotated_at` and `last_generation` are updated on partial or full success.

**Audit constants added:** `OperationBindingRegister`, `OperationBindingRotate`, `OperationBindingDelete` (added to `internal/audit/events.go`).

---

## 5. KPM CLI Surface

New subcommand `kpm cred` in `internal/kpm/cred.go`, wired via `cmd/kpm/main.go`:

```
kpm cred register <name> --provider <kind> --provider-params <json>
    --scope <name> --destination <kind>:<target_id>[:<params_json>]
    [--destination ...] [--ttl <seconds>] [--tag <tag>] ...

kpm cred list [--tag <tag>]

kpm cred inspect <name> [--json]

kpm cred rotate <name>        # synchronous, prints per-destination result

kpm cred remove <name> [--purge]
```

The client methods `RegisterBinding`, `ListBindings`, `GetBinding`, `RotateBinding`, and `RemoveBinding` are added to `internal/kpm/client.go`.

---

## 6. Rotate / Destination Registry Stub (T1 Blocker)

The rotate handler needs to call `Deliver` on each destination. The destination plugin registry (T1) has not merged at T3 implementation time. The rotate handler stubs this lookup:

```go
// TODO(T1-merge): replace stub with real destination registry lookup.
// deliverer, err := s.destinationRegistry.LookupDeliverer(dest.Kind)
```

For each destination, the stub returns a synthetic "delivered" result with `is_transient: false` and no error, so the rotate endpoint is fully functional for testing the data model and CLI path. The audit event records `outcome: "success"` per destination stub. Real delivery requires T1.

---

## 7. Validation Notes

- Name regex enforced at both register and every lookup.
- Destination kind format validated on register (same regex as name).
- `provider_params` and `destination.params` are opaque JSON; the binding layer does not validate their contents.
- Best-effort destination kind validation against the stub registry on register: if the destination registry is available and the kind is unknown, a warning is included in the response but registration is not rejected (forward-compatibility with kinds registered after the binding was created).
