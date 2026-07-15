# Unified Secret Catalog, Plugin Capabilities, and Policy-Gated Visibility

**Date:** 2026-07-14  
**Owner:** Bert Smith  
**Status:** P0 implemented on `feat/unified-secret-catalog-p0` (agentkms + kpm). **Pre-deploy priority:** signed policy bundles — [../superpowers/plans/2026-07-15-signed-policy-bundles.md](../superpowers/plans/2026-07-15-signed-policy-bundles.md). Dynamic SQL deferred per-provider; AWS/GitHub dynsecrets host already present.  
**Related:**

- [2026-04-16-dynamic-secrets.md](2026-04-16-dynamic-secrets.md) — AgentKMS as issuing authority; provider landscape  
- [2026-04-16-scoped-credential-vending.md](2026-04-16-scoped-credential-vending.md) — Scope, vend pipeline, plugin validators  
- [2026-04-16-oss-vs-paid-surface.md](2026-04-16-oss-vs-paid-surface.md) — `go-plugin` host/registry  
- [../kpm-unified-design.md](../kpm-unified-design.md) — KPM templates, `${kms:…}` refs, injection  
- Session context (2026-07-13/14): VPN/DNS + AgentKMS public path; LLM vs registry list confusion; UTA MSSQL static secrets  

**Spans:** `agentkms` (host, policy, plugins, API) and `kpm` (list/add/get/run UX). Server is source of truth; KPM is the primary client.

---

## Context

### What triggered this

1. **Split UX:** `kpm list` only shows the **secrets registry** (`GET /metadata`). LLM credentials live on **`GET /credentials/llm/{provider}`** and do not appear in list, even though they resolve via `${kms:llm/…}` and are first-class for agents.
2. **False security story:** Operators assume “not in list ⇒ more protected.” At-rest protection for registry secrets (e.g. `UTA/mssql-*` in OpenBao-backed AgentKMS) is comparable to LLM master material; the difference is **API shape and session protocol**, not encryption class.
3. **Desired end state:** Same **protection protocol** for DB logins and eventually **dynamic** DB roles (MSSQL today, Oracle/Postgres later) that LLM vending aspires to (TTL, uuid, audit join, policy). Dynamic engines should be **drivers under one issuer**, not one-off products.
4. **Visibility requirement:** Capabilities must be **policy-gated**. Example: `supersecret/**` — non-admins may **vend/read** a specific path but must **not** see the tree in list; admins list and write (optionally with step-up).

### Current state (as-built summary)

| Surface | Write | List | Runtime read |
|---------|-------|------|----------------|
| Registry secrets | `kpm add` → `POST /secrets/{path}` | `GET /metadata` | `GET /secrets/{path}` or template `${kms:service/name}` |
| LLM credentials | Seed (OpenBao / `key-set-llm` / ops) | `GET /credentials/llm` (providers; **not wired into `kpm list`**) | `GET /credentials/llm/{p}` → envelope with TTL + uuid |
| Generic vend | KV under `kv/…/generic/…` | No unified catalog | `GET /credentials/generic/{path}` |
| Cred bindings | `kpm cred register` | `kpm cred list` (separate) | rotate / deliver |

Policy already distinguishes operations (`metadata_list`, `secret_write`, `credential_vend`, `secret_purge`, …) but odev policy is largely open for list/write except purge step-up.

---

## Decision

### D1 — One path namespace, capability-advertised plugins

Every secret resource is addressed by a **path** (e.g. `llm/anthropic`, `UTA/mssql-password`, `db/mssql/uta-app`).  
A **plugin** (or built-in backend) owns a path prefix or kind and advertises **capabilities**.  
Clients never special-case “LLM is invisible” or “MSSQL is a different product.”

### D2 — Capability ∩ policy (normative)

| Layer | Question | Owner |
|-------|----------|--------|
| **Capability** | Can this plugin implement List / Write / Vend / Revoke at all? | Plugin registration |
| **Policy** | May *this principal* perform that op on *this path*? | Policy engine |

```text
operation allowed  ⇔  plugin.Supports(op)  ∧  policy.Allow(op, path, subject)
```

**List is a first-class operation** (`metadata_list` / `metadata_get`), independent of `credential_vend`.  
**Vend without list is intentional** (supersecret case).  
**`--all` means federate plugins**, not bypass policy.

### D3 — Standard host interfaces (logical)

Plugins implement subsets via type assertion (same style as existing `CredentialVender` / deliverer registry):

```text
SecretCatalog     — List, Describe          (never returns secret material)
SecretStore       — Write, Delete, History  (admin CRUD; static-kv)
SecretIssuer      — Vend                    (returns VendedCredential envelope)
LeasingIssuer     — Revoke, Renew           (dynamic / lease)
```

Existing `credentials.VendedCredential` (material + UUID + TTL + hash) remains the **runtime envelope** for all issuers.

### D4 — Built-in / first plugins

| Kind | Paths (examples) | Capabilities | Notes |
|------|------------------|--------------|--------|
| `static-kv` | `UTA/*`, `github/*`, … | Catalog, Store; optional Issuer wrapper | Today’s registry + `/metadata` |
| `llm` | `llm/{provider}` | Catalog, Issuer | Today’s LLM vend; List = configured providers / seeded keys (metadata only) |
| `sql-dynamic` | `db/{driver}/{role}` | Catalog, Issuer, Leasing | One plugin; **drivers** for mssql, oracle, postgres, … |
| (existing) venders | github-app, etc. | Issuer (+ scope plugins) | Align under same catalog paths over time |

**SQL drivers** share one dynamic method:

```text
SQLDriver: CreateRole / RevokeRole (+ driver-specific templates)
sql-dynamic: Vend → driver.CreateRole → VendedCredential
             Revoke/lease expiry → driver.RevokeRole
             List → role bindings (and optionally caller’s active leases)
```

Admin DSN/password used by the plugin is a **separate static-kv path**, never listed as a child of the role path for non-admins.

### D5 — Unified inventory for clients

`kpm list` (and future `GET /v1/secrets`) **federates** every registered `SecretCatalog`, then **filters each item** through policy before emission.

```text
kpm list                  # default: product choice — registry-only OR all authorized (decide in plan)
kpm list --all            # all plugins; still policy-filtered
kpm list --path llm/      # prefix filter after policy
kpm list --path db/       # dynamic roles
kpm list --cap vend       # only paths where subject may credential_vend (optional v1.1)
```

Output includes **class/caps metadata** (e.g. `llm-session`, `generic`, `dynamic-lease`) but **never values**.

### D6 — Policy operations and visibility modes

Per path (and later optional field), visibility is a set of allowed ops for a subject:

| Mode | Operation(s) | Meaning |
|------|----------------|---------|
| listable | `metadata_list` | Appears in catalog listings |
| describable | `metadata_get` | `describe` / single-path meta |
| vendable | `credential_vend` | Runtime issue / template resolve for issuer paths |
| readable | (registry get / static read) | Static value fetch where Store allows |
| writable | `secret_write` / `metadata_write` | Admin mutate |
| history | `secret_history` | Version timeline |
| purge | `secret_purge` | Hard delete (existing step-up pattern) |
| lease_revoke | (new) | Revoke dynamic lease |

**Worked example — supersecretprovider:**

```yaml
# Non-admin: no inventory of the tree
- id: deny-list-supersecret
  effect: deny
  match:
    operations: [metadata_list, metadata_get, secret_history, secret_write]
    path_pattern: "supersecret/**"

# App team may vend one path without seeing siblings
- id: allow-vend-stripe
  effect: allow
  match:
    identity: { team_id: "payments-app" }
    operations: [credential_vend]
    path_pattern: "supersecret/stripe-master"

# Admins: full inventory + management (optional step-up on write/purge)
- id: admin-supersecret
  effect: allow
  match:
    identity: { team_id: "platform-admin" }
    operations: [metadata_list, metadata_get, secret_write, secret_delete,
                 secret_history, credential_vend, secret_purge]
    path_pattern: "supersecret/**"
```

### D7 — Existence-oracle and error uniformity

For principals **lacking** `metadata_get` / `metadata_list` on a path:

- Prefer **uniform not-found** (or uniform forbidden — **pick one in implementation plan and test it**) for describe and for denied exact-path list probes.
- Federated list: **omit** denied paths; do not return `{path, denied: true}` unless a dedicated “show denied stubs” permission exists (default: no).
- `credential_vend` failures for unauthorized subjects follow the same uniformity rule so vend/list cannot be used to binary-search hidden names **beyond** what policy already allows the subject to know (exact path grants for vend are intentional).

### D8 — Evaluation pipeline (normative)

```text
List(query, subject):
  for plugin in Catalogs:
    if !plugin.Supports(List): continue
    for item in plugin.List(query):
      if policy.Allow(metadata_list, item.Path, subject):
        emit sanitize(item)   # meta + caps only

Describe(path, subject):
  if !policy.Allow(metadata_get, path, subject): return UniformNotFound
  return plugin.Describe(path)

Vend(path, subject, scope):
  if !policy.Allow(credential_vend, path, subject): return UniformNotFound|Denied
  // does NOT require metadata_list
  return plugin.Vend(...)   // VendedCredential envelope + audit
```

### D9 — API evolution

**Near term:** keep legacy routes as shims; implement federation in host + KPM.

| Legacy | Maps to |
|--------|---------|
| `GET /metadata` | List `static-kv` (+ policy) |
| `POST/GET /secrets/{path}` | Store / static read |
| `GET /credentials/llm` | List `llm` catalog |
| `GET /credentials/llm/{p}` | Vend `llm/{p}` |
| `GET /credentials/generic/{path}` | Vend static/generic |

**Target (planning phase may sequence later):**

```text
GET    /v1/secrets?prefix=&cap=
GET    /v1/secrets/{path}              # describe
POST   /v1/secrets/{path}              # write if Store
DELETE /v1/secrets/{path}
POST   /v1/secrets/{path}:vend
POST   /v1/leases/{id}:revoke
GET    /v1/leases?path=
```

### D10 — Security invariants (all plugins)

1. List/Describe never return secret material.  
2. Vend always returns the standard envelope (material + uuid + TTL + hash) when material is issued.  
3. Audit vend/use/revoke with path, kind, identity — never raw secret.  
4. Policy on **path + operation** (and auth_strength); not hard-coded “if LLM”.  
5. Plugin admin material (SQL admin, LLM master seed) only usable by host/plugin, not end-user list by default.  
6. Rate limits on **vend**, not on authorized list.  
7. List caches (if any) are **per-identity** with short TTL or disabled.  
8. T1 honesty: static LLM vend may still return long-lived master key with TTL **hint**; dynamic SQL and true provider-minted keys are the path to real short-lived material ([dynamic-secrets design](2026-04-16-dynamic-secrets.md)).

---

## Non-goals (this decision)

- Replacing OpenBao/Vault as physical storage.  
- A universal policy expression language (keep structured match rules; extend path_pattern).  
- Making `--all` a privilege escalation.  
- Field-level ACL v1 (path-level first; multi-field via separate paths or later extension).  
- Unifying `kpm cred` bindings UI in v1 (note interaction; redact binding targets under policy later).

---

## Edge cases (checklist for plan & tests)

| # | Case | Required behavior |
|---|------|-------------------|
| E1 | Vend without list (supersecret) | Vend allow; list omit; describe not-found |
| E2 | Existence oracle | Uniform error for deny vs missing when meta denied |
| E3 | Prefix list on denied tree | Empty / omit, not path enumeration |
| E4 | History sensitivity | `secret_history` separate; deny with list for supersecret |
| E5 | Dynamic role list vs admin secret | Role path listable per policy; admin DSN path not a listable child |
| E6 | Active leases | Own leases vs all leases — latter admin-only |
| E7 | Path collisions | Full path is the resource id (`llm/x` ≠ `x` registry) |
| E8 | Template local disclosure | File on disk may name paths; server inventory still filtered |
| E9 | Partial federation failure | One plugin error must not dump unfiltered others; fail closed or partial with error signal |
| E10 | Step-up | Write/purge/list-on-supersecret may require `cert+human` |
| E11 | Cache after role change | No cross-identity list cache |
| E12 | Rate limit | List ≠ vend; hidden path must not be probeable via vend rate differences beyond policy |

---

## Phased delivery (input to implementation plan)

Substantial work; **do not** attempt as one PR.

### P0 — Inventory federation + policy filter (UX unblock)

- Host: `SecretCatalog` for `static-kv` + `llm`  
- Policy filter on list/describe  
- KPM: `kpm list --all`, `kpm list --path <prefix>`, `kpm describe llm/{provider}` (metadata only)  
- Tests: supersecret omit; admin see; vend-without-list  
- **No** new dynamic SQL yet  

### P1 — Optional static Issuer envelope

- Wrap static-kv read as `VendedCredential` for session uuid/TTL audit when requested  
- Align `${kms:…}` runtime path for agent-facing static secrets  

### P2 — `sql-dynamic` plugin + MSSQL driver

- Role binding config; Vend/Revoke/Renew  
- List role bindings under `db/mssql/…`  
- Admin secret via static-kv ref  
- Integration tests against testcontainer or stub driver  

### P3 — Additional SQL drivers

- Oracle, Postgres — same plugin, new `SQLDriver` + templates  

### P4 — API v1 + policy hardening

- `/v1/secrets` shims; migrate clients  
- Path-pattern policy examples; move odev off “allow all metadata_list” for sensitive prefixes  
- Lease list APIs  

### Cross-cutting each phase

- Audit events for `metadata_list` on sensitive prefixes (at least sample/high-risk)  
- Docs: KPM skill + README “list vs vend”; operator guide for supersecret  
- Backlog items linked from this DDR  

---

## Relationship to existing designs

| Prior doc | Relationship |
|-----------|----------------|
| Dynamic secrets (2026-04-16) | This DDR is the **catalog + capability + policy shell** around that issuing-authority model. SQL dynamic is an instance of “authority = database CREATE USER.” |
| Scoped credential vending (FO-B1) | Vend pipeline (request → policy bounds → validators) **remains**; catalog List is a separate op. |
| OSS + plugins | New backends are plugins; core hosts Catalog/Issuer interfaces. |
| KPM unified design | Template grammar stays; resolver becomes path → plugin by prefix/kind. |

---

## Open questions

### Locked for P0 (2026-07-15 plan)

1. **Default `kpm list`:** registry-only; federation via `kpm list --all`.  
2. **Uniform error:** **404** on describe when meta denied or missing.  
3. **LLM List:** `SupportedProviders` filtered by `metadata_list` on `llm/{provider}` (no KV probe on list).  
4. **Dynamic path scheme:** `db/{driver}/{role}` — deferred to P2.  
5. **Templates:** unchanged in P0.  
6. **Policy:** add `path_pattern` on `Match`; keep `key_prefix`; resource path passed as Evaluate `keyID`.  
7. **PR stack:** agentkms policy+API → kpm CLI → docs (see P0 plan).

### Still open (post-P0)

- Default flip of `kpm list` to `--all` behavior  
- Signed policy bundles + client preview  
- `client_mode` (interactive vs kpm-run)  
- SE-bound device keys

---

## Success criteria

- [ ] Non-admin cannot discover `supersecret/**` via list/describe; can still vend an explicitly granted path.  
- [ ] Admin `kpm list --all` shows registry + `llm/…` (and later `db/…`) without values.  
- [ ] MSSQL and Oracle dynamic roles share one issuer plugin and differ only by driver.  
- [ ] No client code path treats “missing from default list” as “more encrypted.”  
- [ ] Policy tests cover capability ∩ authorization matrix for list/vend/write.  
- [ ] Phased PRs ship P0 without blocking on P2.

---

## Appendix A — Template examples (target)

```bash
# Static registry (today)
MSSQL_USER=${kms:UTA/mssql-user}
MSSQL_PASSWORD=${kms:UTA/mssql-password}

# LLM vend (today)
ANTHROPIC_API_KEY=${kms:llm/anthropic}

# Dynamic SQL (P2+)
MSSQL_USER=${kms:db/mssql/uta-app#username}
MSSQL_PASSWORD=${kms:db/mssql/uta-app#password}

# Supersecret: path known from app config/template, not from list
STRIPE_KEY=${kms:supersecret/stripe-master}
```

## Appendix B — Mental model (one sentence)

> **Paths are universal; plugins advertise capabilities; policy decides visibility and use; dynamic DB engines are drivers under one issuer — list hide is an authorization outcome, not a missing feature.**
