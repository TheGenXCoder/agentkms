# Dynamic Secrets — AgentKMS as Secret-Issuing Authority

**Date:** 2026-04-16
**Owner:** Bert Smith
**Status:** v0.2 scope locked
**Related:** [2026-04-16-forensics-v0.3.md](2026-04-16-forensics-v0.3.md) · [2026-04-16-deployment-model.md](2026-04-16-deployment-model.md)

## Principle

AgentKMS is not a secret store. **AgentKMS is the policy + audit + orchestration layer on top of whatever authority already issues short-lived credentials.** The authority (AWS STS, GitHub App API, Anthropic Admin API, PostgreSQL `CREATE ROLE`) does the actual issuance. AgentKMS holds the privilege to ask, enforces policy on when, and captures the chain-of-custody for forensics.

This frame has two consequences:

1. **Sovereignty preserved.** The privileged credential can live on a laptop (`agentkms-dev`), in a corp VPC (EC2 role, EKS IRSA), or — optionally — hosted by Catalyst9. Customer secrets never leave customer control in the first two deployments.
2. **The moat is the orchestration, not the primitive.** Everyone has the APIs; nobody has the uniform "mint me a scoped, short-lived credential" interface with policy, audit, and attribution wrapped around it.

## The flow

```
[AI agent — Claude Code, Cursor, Codex, etc.]
   ↓ MCP tool call (e.g., vend_github_pat)
[agentkms-mcp — always local to the agent, stdio JSON-RPC]
   ↓ mTLS
[AgentKMS — laptop / corp / hosted]
   ↓ calls the real authority using its own identity
[AWS STS] [GitHub App] [Anthropic Admin API] [Postgres CREATE ROLE]
   ↓
[ephemeral credential — scoped, time-boxed, attributed]
```

Every vend captured in the audit log with full chain-of-custody (see forensics doc).

## Provider landscape

Working understanding as of 2026-04-16. Verify against current provider docs before implementation.

| Provider | Programmatic key creation | Per-scope attribution | Fit |
|---|---|---|---|
| **Anthropic** | Admin API (`sk-ant-admin-...`), workspaces API | Per-workspace usage + billing in Console | Clean match |
| **OpenAI** | Admin API, Projects + Service Accounts | Per-project usage + billing | Clean match (projects are an extra layer) |
| **Google Vertex AI** | Native GCP IAM — impersonation, short-lived tokens | IAM audit logs, per-SA attribution | Native dynamic creds (like AWS STS) |
| **Google Gemini (consumer)** | Manual keys in Cloud Console | Limited | Workload Identity Federation as escape hatch |
| **xAI (Grok)** | Verify current docs | Workspace concept exists | Likely yes |
| **Cohere / Mistral / Groq** | Mixed per provider | Per-team usually | Per-provider research |
| **AWS STS** | Native (AssumeRole, GetFederationToken) | CloudTrail per role session | Reference implementation |
| **GitHub App** | Installation tokens + user-access tokens | Audit log per installation / user | Strong match |
| **PostgreSQL / MySQL** | `CREATE ROLE` with TTL via wrapper | Per-role pg_stat_activity | Matches Vault DB dynamic secrets |

## Three attribution granularities (composable)

1. **Per-user** — `anthropic-frank-2026-w16`, good for the week. Console dashboard shows Frank's usage separately. Rotation = natural expiry.
2. **Per-session** — Mint when Frank runs `claude`, revoke when session ends. Cleanest attribution; zero-exposure after session.
3. **Per-project / per-client** — `anthropic-frank-acme` vs `anthropic-frank-globex`. Two-dimensional revocation (user × client).

Compose: per-user × per-client with weekly expiry is the consulting scenario — Frank's Acme work is attributable to Frank *and* billable to Acme, and cycling off Acme revokes all keys with that client tag.

## What dynamic doesn't solve

LLM provider keys are long-lived by provider design (no "AssumeRole" equivalent at Anthropic or OpenAI for consumer keys — even with Admin APIs the issued key is long-lived until revoked). Mitigations layered:

1. **Scope via MCP allow-list.** Tool-level restriction on which secret paths an agent can request. See KPM Part 4 (`kpm run --secure`).
2. **Per-project keys.** Issue one key per workspace/project so blast radius is bounded even on leak.
3. **Short TTL + rotation.** Mint weekly keys instead of eternal ones. Rotation becomes a non-event because expiry is automatic.
4. **Honeytokens alongside.** Real keys and fake keys issued from the same authority; any use of the fake triggers an alert (see forensics doc).

## Providers without admin APIs

Fallback: AgentKMS stores pre-provisioned static keys tagged by owner/client, vends them per-user after policy check. You get AgentKMS's audit trail but lose provider-side usage attribution. Good enough for the long tail.

## v0.3 launch scope + post-launch cadence

Implementation order revised 2026-04-16 per Grok's review — lead with the engine that serves the launch audience (Cursor/Claude vibe-coders), follow with the engine that demonstrates enterprise gravity.

### v0.3 (ring-fenced launch)

1. **GitHub App ephemeral PATs** — launch demo lead. Fits the "AI agent committed to the wrong repo" narrative directly; resonates with Cursor/Claude users. Installation tokens + user-access tokens both supported.
2. **AWS STS AssumeRole** — serious-enterprise follow-up in demo order. Highest blast radius; essential proof that the pattern scales to production infrastructure.

### Post-launch month 1
3. **Anthropic Admin API** — per-user key minting for LLM attribution. Its own news cycle: "Your CFO can see per-developer Claude spend."
4. **Postgres dynamic users** — Vault parity for the DB secrets use case.

### Post-launch month N
- xAI / Grok when admin API matures
- Cohere / Mistral
- Third-party plugins for niche providers (Stripe, HashiCorp Cloud, etc.) — ecosystem-driven

Each engine is a plugin against the `CredentialVender` interface (see the plugin architecture design doc), so new providers can be added without touching core. Catalyst9 maintains the first four; the ecosystem fills in the rest.

## MCP server

`cmd/mcp/main.go` already exists (593 lines, undocumented, no tests). Exposes `get_credential`, `list_providers`, `get_secret`, `sign`, `encrypt`, `decrypt` via stdio JSON-RPC 2.0.

For v0.2, the MCP server becomes the Dynamic Secrets front door. New tools:

- `vend_aws_credential(role_arn, duration_seconds)` → STS AssumeRole with policy check
- `vend_github_pat(repos[], permissions[], ttl)` → GitHub App-scoped token
- `vend_anthropic_key(workspace, ttl)` → Admin API minted key
- `revoke_credential(credential_uuid)` → explicit revocation
- `list_my_credentials()` → caller's active credentials (for debugging)

Every tool call audited. Every credential traceable.

## Open questions

- **Admin credential rotation.** AgentKMS holds the provider admin key. How is *that* rotated? Policy decision: admin credentials for upstream providers are T2 (production) concern, use HSM-backed storage. Out of scope for v0.2 dev mode; in scope for production deployment guide.
- **Provider rate limits.** AWS STS has hard limits on AssumeRole throughput. Anthropic Admin API likely has lower limits. Need a request-coalescing / caching layer so repeated vends in a short window reuse a fresh token rather than hammering the upstream. Design decision for v0.2.
- **Token format stability.** `ProviderTokenHash` depends on hash(raw_token). If provider rotates their token format (GitHub PAT v2 migration), old hashes don't match new tokens. Store `ProviderTokenFormat` alongside to disambiguate.
