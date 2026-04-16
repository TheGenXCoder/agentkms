# OSS vs Paid Surface — Concrete Limits and Teaser Placement

**Date:** 2026-04-16
**Owner:** Bert Smith
**Status:** Locked for v0.3
**Related:** [2026-04-16-deployment-model.md](2026-04-16-deployment-model.md) · [2026-04-16-forensics-v0.3.md](2026-04-16-forensics-v0.3.md)

## Principle

OSS works completely for a solo developer or small team. The tool is never degraded below usefulness. Paid features are clearly *additional*, not paywall-gated carve-outs of capability.

**Teaser nudges** appear in output at the moment a paid buyer would feel a constraint — never as a blocking dialog, modal, or "upgrade required" error. Always a footer or inline note. The command always succeeds; the footer suggests more.

Never do the Cursor-tier pattern: no "upgrade your plan to continue" popups, no artificial latency, no watermarks on output.

## Binary boundary

Paid features live in **separate binaries or packages**. No paid-only code paths in OSS binaries. This is enforced at build time:

- `agentkms` / `agentkms-dev` — OSS binary, MIT or Apache-licensed, full source on GitHub
- `agentkms-pro` — Paid binary, private repo, extends OSS via documented plugin interfaces
- Both share the same on-disk audit format, same mTLS protocol, same policy engine. A team can migrate from OSS to Pro without data migration.

If a Pro feature is missing from an OSS install, the OSS build either:
1. Degrades gracefully (24h retention instead of unlimited), OR
2. Shows a clear "this feature is in Pro" footer pointing to docs.

Never silently missing. Never broken.

## Locked OSS constraints for v0.3

| Feature | OSS | Pro | Teaser placement |
|---|---|---|---|
| **Audit retention** | 24h rolling window; older events pruned on write | Unlimited retention, configurable expiry per event class | Footer on every `akms forensics inspect`: `ℹ 24h retention on OSS. Events older than 2026-04-15 15:22 not available. Pro retains indefinitely.` |
| **Forensics query** | Single-credential `inspect` CLI | Multi-credential correlation, org-wide search, time-range queries, saved-query API | End of each inspect report: `ℹ Single-credential inspect only on OSS. Pro: correlated multi-cred queries, org-wide search.` |
| **Upstream ingestion** | 1 provider connector (GitHub audit log) | All providers: Anthropic Admin, OpenAI, AWS CloudTrail, Google Workspace, Okta, Vault, arbitrary webhooks | Output of `akms ingest list`: `Active connectors: github-audit. Pro adds: anthropic, openai, aws-cloudtrail, google-workspace, okta, custom-webhook.` |
| **Honeytokens** | Max 5 active tokens | Unlimited | On the 6th `akms honeytoken create`: `Error: OSS caps honeytokens at 5 active. Revoke one or upgrade.` (One of the few hard failures — enforced hard limits keep the product honest.) |
| **Anomaly detection** | Threshold-based rolling averages, per-user per-day | ML-backed anomaly scoring, cross-user pattern detection, noise suppression, alert routing | Alert footer: `⚠ Baseline deviation (3.2×). Pro adds ML anomaly scoring with noise suppression.` |
| **Dashboard** | CLI + static HTML export (`akms report html`) | Live web UI with real-time updates, alert routing, team views | `akms report html` output footer: `Static report generated. Pro: live web UI with real-time alerts.` |
| **Compliance reports** | None | SOC 2, GDPR, HIPAA evidence exports with control-mapped audit events | Hint in `akms audit` help text: `Compliance-ready evidence exports (SOC 2, GDPR, HIPAA) available in Pro.` |
| **Retention queries beyond 24h** | Returns empty with explicit message | Full history | When a query crosses the retention boundary: `ℹ 14 of 47 matching events were pruned (older than 24h). Upgrade to Pro for unlimited history.` |
| **Audit sink destinations** | stdout, local file | + S3, GCS, Splunk, Datadog, Elasticsearch, arbitrary HTTP webhook | `akms audit config` listing: `Configured: file. Pro adds: s3, gcs, splunk, datadog, elasticsearch, webhook.` |
| **Policy engine** | Full policy evaluation on every operation | + policy analytics ("what policies allow this operation for this user?"), policy-change audit | Policy evaluation is identical in both tiers — no nerfing of core security. Pro adds tooling *around* policy, not *inside* it. |
| **MCP server** | All tools available, full mTLS, unlimited agent sessions | Same, plus per-tool per-user analytics and session replay | MCP itself is never gated. The sessions and analytics around it are. |
| **Number of users / callers** | Unlimited | Unlimited | **Never a seat-based limit on OSS.** Seat pricing is a Pro-tier model only. OSS is unlimited-seat — the community growth story depends on it. |

## Teaser placement rules

1. **Location:** end of output, as a single non-colored line prefixed with `ℹ` (info) or `⚠` (attention), unless the constraint is a genuine limit (honeytoken cap) in which case it's a hard failure with a clear message.
2. **Frequency:** at most once per command invocation. Don't spam.
3. **Wording:** Neutral, not sales-y. "Pro adds X" or "Upgrade for X" — never "Unlock X" or "Get the real version." The tool is real.
4. **Suppression:** `--no-upgrade-hints` flag on every command suppresses all teaser output. Always works — we respect the user.
5. **Config override:** `AGENTKMS_HINTS=off` env var suppresses globally. For CI / scripting.

## What absolutely stays OSS

These are the commitments. Never gated, never nerfed, never moved behind paywall:

- **Core credential vending** (scoped, ephemeral, policy-gated)
- **Full audit event emission** with all Bucket A forensics fields
- **mTLS** on every request
- **Policy engine** with full rule evaluation
- **MCP server** with all tools
- **All existing v0.1 functionality** (registry, templates, profiles, JIT decrypt)
- **Secret-value invariant** (audit events never contain raw secrets) — this is a product value, not a feature
- **Three deployment tiers** (laptop, corp VPC, hosted-operator) available to OSS
- **Unlimited users / unlimited credentials issued** — no seat cap on OSS

If any future proposal tries to move one of these behind paywall, the answer is no. The commitment is part of the product.

## What's legitimately Pro

Additive capabilities that require either significant engineering investment or third-party integration costs Catalyst9 absorbs:

- Long-term event retention (storage cost)
- ML anomaly scoring (research + training cost)
- Web UI + real-time alerting (separate frontend app + websocket infra)
- Multi-provider ingestion workers (ongoing maintenance cost per provider)
- Compliance reports (template upkeep, auditor coordination)
- Enterprise sinks (Splunk / Datadog / Elastic — ongoing API maintenance)
- Premium support (human time)

## Revenue model implications

- **Per-seat pricing** is OK on Pro tier. OSS is unlimited-seat.
- **Per-credential-issued pricing** is plausible for the Dynamic Secrets use case — aligns cost with value.
- **Retention pricing tiers** are plausible: "24h OSS / 30d $X / unlimited $Y."
- **No usage-based pricing on core ops.** Vending, signing, encryption throughput is never metered. Customers should feel zero friction using the product. Pro charges for *additional capabilities*, not for *more of the same thing*.

## Open questions

- **Webhook integration pricing.** The GitHub leak webhook should be OSS because it's free-tier value for any user. The enterprise audit sinks (Splunk, Datadog) are clearly Pro. Line between them: one-way *in* from public providers = OSS; one-way *out* to enterprise tooling = Pro.
- **Self-hosted Pro.** Customer runs `agentkms-pro` in their own VPC with a license key. Does the license key enable features, or does it just authenticate to a metering endpoint (telemetry back to Catalyst9)? Lean toward the former — license file unlocks features, zero phone-home. Metering for billing uses customer-provided usage reports or trust.
