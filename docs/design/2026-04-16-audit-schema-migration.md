# Audit Schema Migration — v0.1 → v0.3 Forensics

**Date:** 2026-04-16
**Owner:** Bert Smith
**Status:** Bucket A in flight
**Related:** [2026-04-16-forensics-v0.3.md](2026-04-16-forensics-v0.3.md)

## Context

The v0.3 announcement positions AgentKMS as the secret-issuing authority for AI agents, with complete forensic chain-of-custody per credential (see forensics design doc). Current v0.1 audit events capture operations but miss the fields needed to reconstruct a forensics report.

Without intervention, every audit event accruing between now and v0.3 is forensics-opaque once the credential expires. The authorization context is gone forever 60 minutes after issuance.

**Decision:** Land additive audit fields now (v0.1.1, quiet release) so data captured from the migration forward is queryable when v0.3 ships. Structural changes (scoped vending, revocation events) land in v0.2.

## Gap analysis

Findings from the schema audit of `internal/audit/events.go` and `internal/api/` handlers:

| Forensics requirement | v0.1 state | Bucket |
|---|---|---|
| Internal credential UUID | Missing — no per-credential identity threaded through operations | A |
| Provider token ID for reverse lookup | Deliberately absent (secret-value invariant) | A (as SHA-256 hash) |
| Credential class / type | Partial — class in `KeyID`, type not distinguished | A |
| Caller identity (CN, O) | Present in `CallerID` / `TeamID` | — |
| Caller OU / role | Extracted at `auth/mtls.go:106-119`, discarded | A |
| Cert fingerprint (SHA-256 of DER) | Computed at `pkg/identity/identity.go:79-82`, never audited | A |
| MCP tool / request path | Missing | A |
| Agent session ID | Present | — |
| Policy rule ID | Engine returns `Decision.MatchedRuleID`, not emitted (denies log `DenyReason` only) | A |
| Template or request context | Missing | A |
| Scope granted at issuance | Missing — v0.1 vends master credential with no per-session scoping | **B** (architectural) |
| Three-timestamp lifecycle (created/invalidated/detected) | `Timestamp` captures created; no invalidation event; no detection enrichment | B (invalidated) + C (detected) |
| Invalidation reason | Missing — `OperationRevoke` defined but never emitted | **B** (architectural) |
| Usage events (server-side) | Partial — client-initiated via `POST /audit/use` only | B |
| Upstream correlation IDs (GH audit, Anthropic usage, CloudTrail) | Missing | C |

## Buckets

### Bucket A — Additive fields (v0.1.1, this week)

All fields are backwards-compatible: old events parse with empty strings/zero ints in new fields.

1. `SchemaVersion int` — start at 1; every new event declares.
2. `CredentialUUID string` — generated at vend time in `internal/credentials/vend.go`, threaded through `VendedCredential` so clients echo back on `/audit/use`.
3. `RuleID string` — copy from `Decision.MatchedRuleID` on allow and deny.
4. `CertFingerprint string` — copy from `Identity.CertFingerprint` (SHA-256 of DER). Preferred over X.509 serial because it is globally unique (issuer-independent) and content-addressed.
5. `CallerOU string` — flow from mTLS extraction into AuditEvent.
6. `CredentialType string` — `llm-session`, `generic-vend`, `aws-sts`, `github-pat`, etc.
7. `ProviderTokenHash string` — SHA-256 hex of the provider-issued token. **Raw token never stored.** Enables reverse lookup when a provider reports a leak.
8. `RequestPath string` (optional v0.1.1 stretch) — which HTTP/MCP endpoint triggered the event.

Invariant preserved: audit events never contain raw secret values. Hashes are not secret values.

### Bucket B — Architectural (v0.2, internal milestone)

Require refactoring, not just field additions.

1. **Scoped credential vending.** Replace master-credential issuance (`credentials/vend.go:8` — acknowledged backlog LV-03 / T2 item) with per-session scope computation. Each vend records:
   - Permissions actually granted (not "what policy could have allowed")
   - Workspace / resource allow-list
   - Model / operation restrictions
   - IP CIDR scope (if any)
   - TTL applied
2. **Revocation event types.** Implement the revoke handler (`OperationRevoke` is defined at `audit/events.go:34` but has no emitter).
   - Explicit revoke via API
   - Automatic emission on TTL lapse
   - `InvalidationReason` enum: `expired` / `revoked-user` / `revoked-policy` / `revoked-leak`
3. **Server-side usage tracking.** Currently `OperationCredentialUse` requires the Pi extension to call `POST /audit/use`. For upstream-proxied operations, AgentKMS should emit use events itself.

### Bucket C — Post-hoc enrichment (v0.3 proper)

Lands with the forensics UX.

1. **`DetectedAt` enrichment API.** When a leak report arrives (GitHub webhook, honeytoken firing, manual incident report), PATCH the credential record to record the detection timestamp and reason.
2. **Upstream correlation fields.** Ingestion workers pull from:
   - GitHub audit log (Enterprise API)
   - Anthropic Admin usage API
   - OpenAI Admin API
   - AWS CloudTrail (via assumed-role session token)
   - Join on `ProviderTokenHash` or provider-native correlation IDs.
3. **Forensics query CLI.** `akms forensics inspect --provider-token-id ghp_ABC...` returns the full report (see forensics doc for example output).

## Migration strategy

- **Additive only.** No field renames, no type changes. Old readers remain compatible.
- **Schema version at 1 for all new fields.** v0.2 Bucket B bumps to 2.
- **No backfill of historical events.** Events written before this migration stay at their current shape; forensics queries against pre-migration data will have nulls and that's acknowledged.
- **Hash the provider token at vend time and keep the raw token out of the audit path forever.** Do NOT retrofit an audit pass over old state.

## Implementation status

- **Bucket A**: In progress (2026-04-16). Subagent dispatched with precise spec. Expected deliverables: field additions + tests + `go test -race` + quality gate pass.
- **Bucket B**: Not started. Requires design doc (scoped vending API shape, revocation semantics) before implementation.
- **Bucket C**: Not started. Depends on Bucket B and on the Dynamic Secrets engine.

## Open questions

- Should `RequestPath` be captured in v0.1.1 (Bucket A) or wait for Bucket B? Leaning toward A — it's a simple string add.
- Where does `ProviderTokenHash` live when the provider rotates their token format (e.g., GitHub PAT v2)? Hash is stable per-token but leak reports may arrive referencing the old format. Design can handle: store both `ProviderTokenHash` and `ProviderTokenPrefix` (first 8 chars, for visual triage).

## References

- `internal/audit/events.go` — current AuditEvent struct
- `internal/audit/file.go` — append-only NDJSON sink
- `internal/credentials/vend.go` — credential issuance path
- `internal/policy/engine.go` — Decision.MatchedRuleID
- `pkg/identity/identity.go` — CertFingerprint computation
- `internal/auth/mtls.go` — mTLS cert field extraction
