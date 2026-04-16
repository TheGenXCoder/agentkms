# FO-B1 — Scoped Credential Vending

**Date:** 2026-04-16
**Owner:** Bert Smith
**Status:** Design locked, ready to implement
**Related:** [2026-04-16-v0.3-scope-lock.md](2026-04-16-v0.3-scope-lock.md) · [2026-04-16-audit-schema-migration.md](2026-04-16-audit-schema-migration.md) · [2026-04-16-oss-vs-paid-surface.md](2026-04-16-oss-vs-paid-surface.md)

## The problem

v0.1 `credentials.Vend` returns the master credential with a TTL. Per-session scope does not exist — every vend grants the same permissions. The audit log has nowhere to record "this credential could do X, Y, Z but not W" because X/Y/Z/W don't exist as data.

Forensics needs scope as a first-class field. "What was this leaked credential actually allowed to do?" must be answerable from the audit record alone, without policy-engine re-evaluation against potentially-changed rules.

B1 is the refactor that adds scope as a structured, persisted, plugin-extensible type in the vending path.

## Design decisions

### 1. Structured fields, not an expression language

Scope is a struct with known fields, not a Rego/CEL/JMESPath expression evaluated at use time.

**Why:**
- Expression languages create learning curve, security review burden, and debugging surface that are a poor fit for a v0.3 forensics story. Every scope becomes a program to understand.
- Structured scope serializes cleanly to JSON, embeds cleanly in audit events, hashes cleanly for correlation.
- Provider-specific scope shapes (AWS IAM, GitHub permissions) are well-known structured formats already — our `Scope` is just a unifying representation.
- If a plugin wants expression-based policy layered on top, it can add one (`c9-policy-dsl` plugin, hypothetically). Core stays simple.

Non-goal: a universal scope algebra. Our `Scope` is a discriminated union — each `Kind` has its own structured fields. Plugins for new providers add new Kinds.

### 2. Request-driven, policy-narrowed, plugin-validated

Scope computation is a three-stage pipeline at vend time:

```
Request.DesiredScope
    ↓
policy.Evaluate(identity, operation, resource)
    returns AllowedScopeBounds
    ↓
intersect(DesiredScope, AllowedScopeBounds) = effective Scope
    ↓
for each ScopeValidator plugin:
    validator.Validate(Scope) → error | Scope (possibly further narrowed)
    ↓
finalized Scope (or error)
```

**Why request-driven:**
- Agents know what they need ("this session will only touch repo X for 8 hours").
- Making the request explicit is what makes the audit record meaningful — "Frank asked for scope X; got scope Y after policy narrowing" is the chain-of-custody story.

**Why policy-narrowed:**
- Policy rules are the authority on the maximum scope any identity is allowed to receive for an operation. A Cursor session can request everything; policy rejects what it's not allowed to have.

**Why plugin-validated:**
- Each provider knows its own valid scope shapes. AWS knows what makes a valid ARN; GitHub knows which permission combinations are issuable. Core doesn't hard-code provider rules — plugins enforce them.

### 3. Scope serialized as structured JSON in the audit event

A new `Scope` field on `AuditEvent`:

```go
type AuditEvent struct {
    // ... existing Bucket A fields ...
    Scope         *ScopeRecord `json:"scope,omitempty"`
    ScopeHash     string       `json:"scope_hash,omitempty"` // SHA-256 of canonical JSON
}
```

`ScopeHash` enables correlation (does this use match the vended scope?) without loading and parsing the full structure.

### 4. Atomic revocation; no scope-level carve-outs

- `revoke(credentialUUID)` revokes the whole credential.
- Narrowing after issuance is not supported. If a narrower credential is needed, issue a new one. The old one is revoked or left to expire.
- Why: scope-level revocation doubles the policy complexity and creates subtle timing races where "partially revoked" credentials exist. Atomic is sound, debuggable, forensics-friendly.

## Core types

### Scope

```go
// Scope describes the effective permissions of a vended credential.
// It is captured at vend time, stored in the audit log, and returned
// to the caller alongside the credential value.
type Scope struct {
    // Kind discriminates the structural shape of Params.
    // Core recognises "llm-session" and "generic-vend" (v0.1 behaviour,
    // wrapped in the new type).  Plugins register additional Kinds via
    // the plugin API (e.g., "aws-sts", "github-pat", "postgres-role").
    Kind string `json:"kind"`

    // Params holds Kind-specific structured scope data.  Its shape is
    // defined by the plugin that owns the Kind.  Core treats it as
    // opaque JSON during serialization but passes it to the registered
    // plugin for interpretation.
    Params map[string]any `json:"params,omitempty"`

    // TTL is the effective lifetime of the credential from issuance.
    // Core enforces this; no plugin can extend it.
    TTL time.Duration `json:"ttl"`

    // IssuedAt is the wall-clock time at which the scope became valid.
    IssuedAt time.Time `json:"issued_at"`

    // ExpiresAt is IssuedAt + TTL.  Recorded explicitly so that audit
    // queries don't have to reconstruct.
    ExpiresAt time.Time `json:"expires_at"`
}
```

**Kind examples (plugin-provided):**

```json
// aws-sts
{
  "kind": "aws-sts",
  "params": {
    "role_arn": "arn:aws:iam::123456789012:role/staging-deploy",
    "external_id": "c9-session-8f3a",
    "session_name": "frank-acmecorp-20260413"
  },
  "ttl": "15m",
  "issued_at": "2026-04-13T15:20:04Z",
  "expires_at": "2026-04-13T15:35:04Z"
}

// github-pat
{
  "kind": "github-pat",
  "params": {
    "installation_id": 42,
    "repositories": ["acmecorp/legacy-tool"],
    "permissions": {"contents": "write", "pull_requests": "write"}
  },
  "ttl": "8h",
  "issued_at": "2026-04-13T15:20:04Z",
  "expires_at": "2026-04-13T23:20:04Z"
}

// llm-session  (wraps v0.1 behaviour)
{
  "kind": "llm-session",
  "params": {
    "provider": "anthropic",
    "workspace": "customers/acme"
  },
  "ttl": "1h",
  "issued_at": "2026-04-13T15:20:04Z",
  "expires_at": "2026-04-13T16:20:04Z"
}
```

### VendRequest

```go
// VendRequest is the input to the credential vending pipeline.
type VendRequest struct {
    // Identity of the caller (from mTLS cert).
    Identity identity.Identity

    // DesiredScope describes what the caller wants.  The vending
    // pipeline narrows this against policy bounds and plugin
    // validators; the final Scope may be equal or narrower.
    //
    // An empty DesiredScope.Kind means "caller is making a
    // back-compat LLM-session vend" and the vender falls back to
    // legacy behaviour (kind=llm-session with Params.provider).
    DesiredScope Scope

    // AgentSession is the opaque session ID passed through for
    // audit correlation.
    AgentSession string
}
```

### ScopeBounds (from policy engine)

```go
// ScopeBounds is the maximum scope a policy rule allows for a
// given (identity, operation) pair.  Returned by Engine.Evaluate
// alongside the Allow decision.
type ScopeBounds struct {
    // Kind matches the Scope.Kind this bounds applies to.  Empty
    // means "all kinds permitted" (rare; only for admin callers).
    Kind string `json:"kind,omitempty"`

    // MaxParams is the ceiling for Scope.Params.  Intersection
    // semantics are Kind-specific and delegated to the plugin that
    // owns the Kind (see ScopeValidator.Narrow).
    MaxParams map[string]any `json:"max_params,omitempty"`

    // MaxTTL caps Scope.TTL.  Zero means "use the default for this
    // Kind" (plugin-owned default).
    MaxTTL time.Duration `json:"max_ttl,omitempty"`
}
```

Added as a field on `policy.Decision`:

```go
type Decision struct {
    Allow          bool
    DenyReason     string
    MatchedRuleID  string
    Anomalies      []AnomalyRecord
    AllowedBounds  *ScopeBounds  // NEW — nil when Allow=false
}
```

## Plugin extension points

Core defines three plugin interfaces that together own the Kind-specific semantics. All three are optional — a minimal plugin can provide one or all three. Core invokes them in sequence during the vend pipeline.

### ScopeValidator (required per-Kind)

Validates structural correctness. Called after the caller supplies a `DesiredScope` of this Kind, and again after policy narrowing to verify the narrowed shape is still valid.

```go
type ScopeValidator interface {
    // Kind returns the discriminator this validator owns.
    Kind() string

    // Validate checks that the Scope has a well-formed Params shape
    // for this Kind.  Returns an error with a descriptive (but safe)
    // message if the Scope is malformed.  Must not mutate the Scope.
    Validate(ctx context.Context, s Scope) error

    // Narrow intersects a requested Scope with policy bounds and
    // returns the effective Scope.  Returns an error if the bounds
    // are incompatible with the request (e.g., request asks for
    // repos that bounds forbid).  Kind-specific logic lives here.
    Narrow(ctx context.Context, requested Scope, bounds ScopeBounds) (Scope, error)
}
```

### ScopeAnalyzer (optional per-Kind)

Runs at vend time to assess risk. Can flag anomalies (recorded in the audit event) but not reject — rejection is the validator's job. Analyzers are where the "your AWS role grants wildcard * on every S3 bucket" warning lives.

```go
type ScopeAnalyzer interface {
    Kind() string

    // Analyze returns zero or more anomaly records describing risky
    // aspects of the Scope.  Purely informational — does not block
    // vending.
    Analyze(ctx context.Context, s Scope) []ScopeAnomaly
}

type ScopeAnomaly struct {
    Level   AnomalyLevel // info / warn / alert
    Code    string       // machine-readable anomaly ID
    Message string       // safe, operator-facing description
}
```

### ScopeSerializer (required per-Kind that vends real credentials)

Converts the structured `Scope` into the provider's native format at the moment the upstream API is called.

```go
type ScopeSerializer interface {
    Kind() string

    // ProviderRequest converts the Scope to the provider-native
    // request format (AWS IAM policy document, GitHub permissions
    // object, etc.).  The returned []byte is passed directly to the
    // upstream SDK call by the plugin's Vender; core never inspects
    // or logs the serialised form.
    ProviderRequest(ctx context.Context, s Scope) ([]byte, error)
}
```

## Plugin invocation order

```
VendRequest arrives
    ↓
[core] lookup ScopeValidator for DesiredScope.Kind
    ↓ (none? reject — unknown kind)
    ↓
[validator] Validate(DesiredScope) — structural check on request
    ↓ (error? reject)
    ↓
[core] policy.Evaluate(…) → Decision{Allow, AllowedBounds, ...}
    ↓ (deny? reject with DenyReason, audit event captured)
    ↓
[validator] Narrow(DesiredScope, AllowedBounds) → effective Scope
    ↓ (error? reject — bounds incompatible)
    ↓
[validator] Validate(effectiveScope) — structural check on narrowed shape
    ↓ (error? reject — narrowing produced malformed scope, likely plugin bug)
    ↓
[analyzer, if present] Analyze(effectiveScope) → []ScopeAnomaly
    ↓ (anomalies attached to audit event but do not block)
    ↓
[serializer] ProviderRequest(effectiveScope) → upstream-specific format
    ↓
[plugin Vender] call upstream API with serialised request
    ↓
[core] record audit event with effective Scope + anomalies + ProviderTokenHash
    ↓
return VendedCredential{APIKey, UUID, effective Scope, ExpiresAt, ...}
```

Core owns sequencing, error handling, audit emission. Plugins own Kind-specific semantics.

## Backwards compatibility

v0.1 callers that do not specify `DesiredScope` get the legacy llm-session behaviour via a core-provided default validator. No client-side code changes required for the existing Vend path.

The existing `credentials.Vend(ctx, provider, identity, session)` signature stays as a thin wrapper that constructs a default llm-session `VendRequest` and delegates to the new `VendScoped(ctx, VendRequest)` entrypoint. Old tests continue to pass.

## Audit event additions

Bucket A introduced the hooks; B1 populates them:

- `Scope *ScopeRecord` — the effective Scope at issuance
- `ScopeHash string` — SHA-256 of canonical-JSON-encoded Scope (for correlation queries)
- `Anomalies []string` — already present from Bucket A; B1 populates from `ScopeAnalyzer`

Canonical JSON encoding rules:
- Keys sorted lexicographically at every level
- No whitespace
- No trailing newline
- Numeric types written with minimum precision (no trailing zeros)

Hash stability matters: two identical Scopes must produce identical hashes so use-events can be correlated back to vend-events by `ScopeHash == ScopeHash`.

## Out of scope for B1

- **Scope-level revocation.** Atomic credential revoke only. Noted in design decision #4.
- **Cross-Kind scope policies.** "Allow AWS STS IF caller also has GitHub PAT" is not supported. Each vend is independent.
- **Scope history / diff.** We record Scope at vend time; we do NOT track scope changes over time. There are no scope changes — reissue with a new Scope is a new credential.
- **Provider federation.** Vending AWS creds via an Azure AD identity is a plugin responsibility; core stays provider-agnostic.

## OSS vs Pro

All of B1 is OSS. Scope is a core type. The three plugin interfaces are core types. Validators, analyzers, and serializers for the OSS-bundled Dynamic Secrets engines (`dynsecrets-github`, `dynsecrets-aws`, `dynsecrets-anthropic`, `dynsecrets-postgres`) are OSS plugins.

Pro-plugin hooks that could plausibly extend the scope pipeline:
- `c9-scope-analytics` — cross-scope risk scoring, historical scope-drift detection (ML)
- `c9-policy-dsl` — a Rego/CEL expression layer that evaluates alongside structured bounds
- `c9-scope-review` — a human-approval workflow injected between narrowing and validation ("this scope is unusually broad; require approval")

None of those are v0.3 scope. They're called out here so the plugin API doesn't accidentally foreclose on them.

## Implementation order

1. **Core types** — `Scope`, `VendRequest`, `ScopeBounds`, plugin interfaces. No behaviour yet.
2. **Policy Decision extension** — add `AllowedBounds` field. Rules loader parses a new `bounds:` section.
3. **Default llm-session validator** — built into core for back-compat. No external plugin needed.
4. **VendScoped entrypoint** — the new pipeline. Legacy `Vend` wraps it.
5. **Audit integration** — populate `Scope` and `ScopeHash` on vend events.
6. **Tests** — round-trip, narrowing, canonical JSON hash stability, back-compat.
7. **First real plugin** — `dynsecrets-github` as the exercise that proves the pipeline. Validator + analyzer + serializer, with real GitHub App calls against a test installation.

Step 7 requires the plugin host (FO-D1/D2) to exist. Steps 1-6 are core-only and can proceed in parallel with Bucket D plugin-host work.

## Open questions

- **MaxParams intersection semantics.** `ScopeValidator.Narrow` is Kind-specific — AWS narrows resource ARNs by longest-prefix; GitHub narrows by set intersection on repositories. The contract is "plugin decides, reports error if incompatible." Is that enough, or do we want a core helper library for common patterns (set intersection, prefix matching, etc.)?
  - Lean: ship without the helper library for v0.3; if every plugin reimplements the same three patterns, extract in v0.3+1.
- **Anomaly suppression.** Should operators be able to suppress specific `ScopeAnomaly.Code` values ("I know my terraform role is broad; stop warning me")? Suppression config in policy, or in a separate file?
  - Lean: policy is the right place — suppression is an authorization decision, not a preference. Handle in v0.3+1 if real users complain.
- **Scope equality for use-event correlation.** Two credentials with the same Scope should produce the same ScopeHash. Two different-but-semantically-equivalent Scopes (AWS role allowing `s3:*` vs explicit list of every S3 action) hash differently. Is semantic equivalence ever needed, or is structural enough?
  - Lean: structural is enough for v0.3. Semantic equivalence is the ML anomaly engine's job, not core's.
