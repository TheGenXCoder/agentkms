# Dynamic Secrets: Pluggable Providers (Terraform-style)

**Date:** 2026-07-15  
**Owner:** Bert Smith  
**Status:** Extraction in progress on `feat/dynsecrets-provider-extraction` — libraries under `plugins/`, binaries under `cmd/agentkms-plugin-{aws,github}`  
**Related:**

- [2026-04-16-oss-vs-paid-surface.md](2026-04-16-oss-vs-paid-surface.md) — plugins not monolithic core  
- [2026-07-14-unified-secret-catalog-plugins-policy.md](2026-07-14-unified-secret-catalog-plugins-policy.md) — path namespace, catalog, policy  
- [../superpowers/plans/2026-07-15-signed-policy-bundles.md](../superpowers/plans/2026-07-15-signed-policy-bundles.md) — pre-deploy integrity  

---

## Context

Dynamic secrets for MSSQL, Oracle, customer-internal tools, and cloud APIs must not become a permanent `switch` inside AgentKMS core. Operators and customers should **write a provider, register it with the server**, and bind paths/policy — analogous to Terraform providers.

In-tree `internal/dynsecrets/aws` and `internal/dynsecrets/github` prove the interfaces but currently live as internal packages. That is acceptable as a bootstrap; it is **not** the long-term extension story.

## Decision

### D1 — Providers are registered plugins, not core wiring

- Core owns: mTLS auth, **policy**, audit, session/lease bookkeeping, plugin host lifecycle, path routing to a registered **kind**.  
- Providers own: talking to the external system (AWS STS, GitHub, MSSQL, Oracle, Acme ERP), mint/revoke/renew semantics for that system.  
- **No new dynsecrets kinds land as hardwired branches in `main`.** Blessed engines ship as **plugins** (in-tree or out-of-tree) that **register** at load time.

### D2 — Stable provider contract (minimum)

A dynamic-secrets provider must implement (as applicable):

| Interface | Role |
|-----------|------|
| `credentials.CredentialVender` | `Kind()` + `Vend(scope)` → short-lived material |
| Optional: scope validate/narrow | Already used by aws/github patterns |
| Optional: `SecretCatalog` | List role bindings under path prefixes (catalog federation) |
| Optional: lease revoke/renew | When the authority supports destroy |

Config (role ARN, admin secret **ref**, TTL bounds) lives in **bindings/config**, not in core code.

### D3 — Extract AWS and GitHub as reference providers

**End state:**

```text
plugins/dynsecrets-aws/          # or github.com/…/dynsecrets-aws
plugins/dynsecrets-github/
# customer
plugins/dynsecrets-acme-erp/
```

- Built and versioned **separately** from core when practical.  
- Loaded via plugin host (`Install` / discover / `RegisterVender`).  
- Documented as **the** examples of “the right way” to extend DS.  
- In-tree `internal/dynsecrets/{aws,github}` become **thin shims or deleted** after extraction — not the canonical home.

**Interim:** keep internal packages until extraction PR lands; do not add MSSQL/Oracle **into** `internal/` as permanent homes — prefer `plugins/dynsecrets-mssql` from day one when those engines are written.

### D4 — Customer internal tools

Same path as cloud:

1. Implement provider binary against the public plugin API.  
2. Sign/load per trust policy (plugin signing ≠ policy-YAML signing).  
3. Register kind with AgentKMS.  
4. Create bindings (paths) + policy (`credential_vend` / `metadata_list`).  
5. Templates: `${kms:<path>#field}` — core routes by registered kind.

No AgentKMS fork required for a private authority.

### D5 — Explicit non-goals (scope control)

**Out of scope for now (not blocked forever):**

- A **higher abstraction** “AgentKMS extension SDK” that unifies dynsecrets, destinations, forensics sinks, UI plugins into one meta-framework. Useful later; **scope creep** before signed policy bundles + provider extraction.  
- Building every SQL engine before deploy.  
- Replacing `CredentialVender` with a different interface in the same breath as extraction (stabilize, then extract).

**In scope when we schedule extraction work:**

- Document register/install/run for out-of-tree providers.  
- Move aws + github to plugin layout; CI builds them as examples.  
- Ensure core tests use the host, not package-private AWS guts.

## Sequencing (relative to other work)

```text
1. P0 catalog (done on feature branch)
2. Signed policy bundles (pre-deploy priority)
3. Merge/deploy control-plane integrity (catalog + signed policy)
4. Provider extraction: aws + github as true plugins + docs
5. New engines (mssql, oracle, customer) as out-of-tree providers only
```

## Success criteria (extraction epic)

- [x] Core has **zero** `import` of provider-specific STS/GitHub mint logic except via plugin host (libraries under `plugins/`).  
- [x] `dynsecrets-aws` and `dynsecrets-github` build as **plugin binaries** (`cmd/agentkms-plugin-*`); host StartProvider loads them.  
- [x] Docs: `plugins/README.md` + per-provider READMEs (expand to full tutorial later).  
- [ ] MSSQL/Oracle (when built) never live as permanent `internal/dynsecrets` product code.  

## One sentence

> **AgentKMS is the control plane; dynamic secrets are Terraform-style providers you register — AWS and GitHub become the reference plugins, not internal special cases; broader extension frameworks wait.**
