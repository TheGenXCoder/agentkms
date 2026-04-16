# OSS Core + Plugin Ecosystem

**Date:** 2026-04-16 (revised same day)
**Owner:** Bert Smith
**Status:** Locked for v0.3
**Related:** [2026-04-16-deployment-model.md](2026-04-16-deployment-model.md) · [2026-04-16-forensics-v0.3.md](2026-04-16-forensics-v0.3.md)

## Principle

OSS ships a complete, fully-functional core. Pro and community capabilities are delivered as **independent plugins** that the core loads at runtime. There is no separate "Pro binary" to install — users run one `agentkms`, and plugins extend it.

> **Mental model:** Go pro for plugins.
>
> **Dual framing for audiences** (per Grok review, 2026-04-16):
> - DevOps / SRE / platform-engineer audience: "plugins — the same model that powers Terraform, Vault, and Packer." Positive ecosystem connotation; signals extensibility and third-party support.
> - CISO / security-buyer audience: "Catalyst9 Enterprise Pack — managed plugins with security boundaries, signed releases, and support contracts." Reassures the "plugins = supply-chain risk" reflex without inventing a separate product line.
>
> Same binary, same plugin system, different emphasis in different surfaces (developer docs vs. enterprise sales pages).

- OSS works completely for solo and small-team workflows out of the box.
- Paid plugins surface upgrade nudges at the exact moment a paid buyer would feel a constraint — never blocking dialogs, never watermarks, never paywall-in-workflow.
- The plugin API is **public forever**. Anything Catalyst9 builds as a Pro plugin, a third party could theoretically build too. Our moat is implementation quality and ecosystem breadth, not API gatekeeping.

## Plugin mechanism

**`hashicorp/go-plugin`** (RPC over local subprocess) — the library Vault, Terraform, and Packer use for this exact purpose.

Why not alternatives:
- Go's built-in `plugin` package: Linux-only in practice, version-pinned to the host binary, fragile. Disqualifying for a cross-platform security tool.
- Wasm / Lua / embedded interpreter: too slow for the audit hot path, and no benefit over subprocess isolation.
- Shared libraries via CGO: platform-specific build complexity, no crash isolation.

Properties `go-plugin` gives us:
- **Process isolation** — a crashing plugin can't take down core
- **Version independence** — plugin binaries built against older APIs keep working
- **Language independence** — plugins can be written in any language that speaks gRPC (future optionality)
- **Clean security boundary** — plugin subprocesses run with distinct (potentially reduced) OS privileges

## Core vs plugin split

### What lives in core OSS (`agentkms` binary)

Locked in. Never gated, never moved behind paywall:

- Plugin host + discovery + lifecycle management
- Plugin API definitions (the public interfaces plugins implement)
- Credential-vending *interface* (the thing plugins fulfill)
- Audit emission pipeline with all Bucket A forensics fields
- Policy engine with full rule evaluation
- MCP server with all tools
- Core CLI (`akms`)
- mTLS on every request
- Three deployment tiers (laptop, corp VPC, hosted-operator)
- Unlimited users / unlimited credentials issued — no seat cap on OSS
- Secret-value invariant (audit events never contain raw secrets)

These are product commitments. If a future proposal tries to move one behind a paywall, the answer is no.

### OSS-bundled plugins

Ship in the same GitHub release as core. Licensed the same as core (Apache 2.0 / MIT). Users can swap, disable, or replace them.

- `dynsecrets-aws` — AWS STS AssumeRole adapter
- `dynsecrets-github` — GitHub App ephemeral PAT
- `dynsecrets-anthropic` — Anthropic Admin API key minting
- `dynsecrets-postgres` — Postgres dynamic role creation
- `sink-file` — append-only NDJSON audit sink
- `sink-stdout` — structured log audit sink
- `anomaly-basic` — rolling-average threshold detection
- `forensics-cli` — single-credential `akms forensics inspect`
- `ingest-github-audit` — one upstream ingestion source (GitHub audit log)

Anyone can fork these. Catalyst9 maintains the reference implementations.

### Catalyst9 Enterprise Pack plugins (paid)

Separately distributed binaries. Self-enforce licensing via a license file at plugin load time. Core has zero license-awareness. Plugin-by-plugin purchasing is possible; enterprise pack bundles multiple.

- `c9-retention-unlimited` — long-term audit retention store with indexing
- `c9-anomaly-ml` — ML-backed anomaly scoring, cross-user pattern detection, noise suppression
- `c9-web-ui` — live web dashboard, real-time alerts, team views
- `c9-compliance` — SOC 2, GDPR, HIPAA evidence exports mapped to audit events
- `c9-sinks-enterprise` — Splunk, Datadog, Elasticsearch, S3, GCS, custom webhook
- `c9-hsm` — CloudHSM, PKCS#11, YubiKey backends
- `c9-sso` — SAML / OIDC integration for enterprise identity
- `c9-ingest-multi` — Anthropic, OpenAI, AWS CloudTrail, Google Workspace, Okta ingestion
- `c9-forensics-plus` — multi-credential correlation, org-wide search, saved queries

### Community / third-party plugins

Plugin API is public; anyone can write a plugin. Examples we won't build but want to see:

- Provider adapters for niche services (Stripe, HashiCorp Cloud Platform, Kubernetes)
- Organization-specific policy helpers
- Custom sinks for internal SIEMs
- Integrations with proprietary HSMs

Catalyst9 maintains a plugin registry (docs + discovery). No approval gate — anyone can list a plugin. Signed plugins from trusted publishers get a checkmark; unsigned works but shows a warning on first load.

## Teaser placement

With plugins, the upgrade hint is tool-specific:

| Scenario | Hint shape |
|---|---|
| Query crosses 24h retention boundary in core | `ℹ 14 events pruned (older than 24h). Install c9-retention-unlimited for unlimited history.` |
| 6th honeytoken creation | `Error: OSS caps honeytokens at 5 active. Install c9-retention-unlimited or revoke existing.` |
| `akms ingest list` with only GitHub configured | `Active: github-audit. Install c9-ingest-multi for Anthropic, OpenAI, CloudTrail, Google Workspace, Okta.` |
| `akms forensics inspect` completes | Footer: `Single-credential inspect only. Install c9-forensics-plus for correlated multi-credential queries and org-wide search.` |
| Anomaly threshold alert | `⚠ Baseline deviation (3.2×). Install c9-anomaly-ml for ML-backed scoring with noise suppression.` |
| `akms report` | `Static HTML report generated at ./report.html. Install c9-web-ui for live dashboard + real-time alerts.` |
| Any audit command | Hint in help text: `Compliance evidence exports (SOC 2, GDPR, HIPAA) available with c9-compliance.` |

**Suppression — always honored:**
- `--no-upgrade-hints` flag on every command
- `AGENTKMS_HINTS=off` env var
- Config setting `hints: false` in `~/.agentkms/config.yaml`

## Plugin discovery UX

```bash
# Installed plugins
akms plugin list

NAME                     VERSION   SOURCE        LICENSE
dynsecrets-aws           0.3.0     bundled       Apache-2.0
dynsecrets-github        0.3.0     bundled       Apache-2.0
dynsecrets-anthropic     0.3.0     bundled       Apache-2.0
c9-retention-unlimited   1.2.0     catalyst9.ai  Commercial (valid through 2027-01-15)
c9-web-ui                1.1.0     catalyst9.ai  Commercial (valid through 2027-01-15)

# Install a plugin
akms plugin install c9-compliance                      # from catalyst9.ai registry
akms plugin install example.com/custom-sink            # from arbitrary URL (signed)
akms plugin install ./my-plugin                        # from local path

# Search the registry
akms plugin search "sink"

# Remove a plugin
akms plugin remove c9-web-ui
```

## License enforcement model

- **License files** issued by Catalyst9 billing. Contain: customer ID, plugin entitlements, validity window, hard cap on some dimensions (seats, credentials-per-month) if we ever go metered.
- **Plugin-side check** at load. Each Pro plugin validates the license at startup and refuses to initialize if invalid. Logs a single clear error; core continues without the plugin.
- **No phone-home.** License validity is fully determined by the file. Customer trust model.
- **Grace period** for expired licenses — plugins log a warning but keep working for 30 days post-expiry, to prevent calendar-driven production outages while billing sorts out.

## Revenue model implications

- **No seat-based metering on OSS core.** Unlimited forever.
- **Plugins can have per-seat or per-credential metering** if the commercial model calls for it (e.g., `c9-anomaly-ml` priced per monitored user).
- **Plugin bundles** (Enterprise Pack, Compliance Pack) for customers who want everything without line-item purchasing.
- **Community plugins can be paid.** A third party writes a Stripe plugin and sells it; we don't take a cut unless they list via our registry. The ecosystem grows faster when we're not the bottleneck.

## Engineering implications for v0.3

**B1 (scoped credential vending) must be designed with plugin extension points.** Core defines the `Scope` primitive; plugins can add validators, analyzers, and mutators on top. The Enterprise Pack's `c9-forensics-plus` plugin, for example, will want to inject policy-analytics hooks at scope evaluation time.

**B6/B7/B8 (Dynamic Secrets engines) are plugins, not monolithic core code.** Core defines `CredentialVender` interface; AWS STS is an OSS-bundled plugin, Anthropic Admin is another, etc. This is actually the correct factoring regardless of OSS/Pro — it isolates provider-specific code and lets each engine evolve independently.

**Bucket D (the old OSS-constraint work) is reshaped.** The work is no longer "build a second binary" — it's "build the plugin host, ship the OSS-bundled plugins, scaffold the first Catalyst9 plugin to prove the API."

See the updated [backlog](../backlog.md) Bucket D for the revised tasks.

## Open questions

- **Plugin registry hosting.** `catalyst9.ai/plugins` — static JSON manifest on S3 + signatures, or a real package registry? Lean toward static JSON for v0.3, upgrade to real registry later.
- **Plugin signing keys.** We'll sign official Catalyst9 plugins. Community plugins can self-sign. Key rotation story needs to be designed before signing keys are ever issued.
- **Versioning contract.** When is a plugin API change breaking? Semver applied to the plugin API (separate from core agentkms version). Plugins declare compatible API version range; core refuses to load mismatched plugins rather than partially-init.
