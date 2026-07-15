# Unified Secret Catalog P0 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.  
> **Factory:** Plant manager + **Production Engineer** Context Package below. Consumers stay within allowlist; file Context Requests for gaps.

**Goal:** Federate registry + LLM inventory in AgentKMS/KPM with **per-path policy** on list/describe so `kpm list --all` shows `llm/*` without values, and supersecret paths can be **hidden from list while still vendable**.

**Architecture:** Server remains source of truth. Extend policy matching so `key_prefix` / new `path_pattern` apply to secret **paths** (already passed as `keyID` to `Evaluate`). Filter **each** list item with `metadata_list` (not a single `metadata/*` gate only). KPM adds `--all` / `--path` and merges LLM catalog rows client-side from `GET /credentials/llm` (metadata only) until optional `/v1/secrets` (P4). No sql-dynamic in P0.

**Tech Stack:** Go (agentkms + kpm), existing `internal/policy`, `internal/api`, `internal/kpm`; `go test` in both modules.

**Spec:** [docs/design/2026-07-14-unified-secret-catalog-plugins-policy.md](../../design/2026-07-14-unified-secret-catalog-plugins-policy.md)

## Global Constraints

- **Never return secret values** from list/describe/catalog endpoints.
- **Server enforces policy**; client flags are UX only (`--all` ≠ privilege).
- **Operation floors** (e.g. `secret_purge` → `cert+human`) unchanged; client_mode deferred (post-P0).
- **Signed policy bundles** deferred to P4; P0 uses existing YAML loader + tests.
- **Repos[...] / root threat model** is documentation only in P0 (README/skill notes).
- Cross-repo: land **agentkms** behavior first (or same stack), then **kpm** flags; keep versions compatible (old kpm still works against new server).
- Default `kpm list` remains **registry-only** (compat); `--all` opts into federation.
- Meta deny/missing for describe: **HTTP 404** with generic body when principal lacks list/get on path (existence oracle). List: **omit** denied paths.

## Locked decisions (were open questions)

| # | Decision for P0 |
|---|-----------------|
| 1 | Default `kpm list` = registry only; document `kpm list --all` |
| 2 | Uniform **404** on describe when meta denied or missing |
| 3 | LLM list source = `SupportedProviders` filtered by `metadata_list` on `llm/{provider}`; do not require KV probe for list (vend still 404 if no key) |
| 4 | Dynamic path scheme `db/{driver}/{role}` — **P2 only** |
| 5 | Templates unchanged in P0 |
| 6 | Add optional `path_pattern` (glob, `path.Match` semantics with `**` via simple prefix/`*` rules — see Task 1); keep `key_prefix` working for paths |
| 7 | PR stack: agentkms Tasks 1–4, then kpm Tasks 5–6, then docs Task 7 |

## Out of scope (later plans)

- P1 static Issuer envelope  
- P2–P3 sql-dynamic  
- P4 `/v1/secrets`, signed bundles, client_mode  
- SE-bound device keys  

---

# Context Package (Production Engineer → implementers)

**task_id:** unified-secret-catalog-p0  
**package_version:** v1  
**consumer_role:** Implementation  
**budget:** soft ~8k tokens excerpts · max rounds 3  

## Task brief

**Goal:** P0 inventory federation + per-path policy filter + kpm UX.  
**DoD:** Tests for E1–E3 (and list/describe matrix); `kpm list --all` shows `llm/` rows without values; deny list omits `supersecret/**` while vend can remain allowed.  
**Out of scope:** dynamic SQL, signed bundles, client_mode.

## Allowlisted paths

### agentkms
- `docs/design/2026-07-14-unified-secret-catalog-plugins-policy.md` — normative DDR  
- `internal/policy/rules.go` — `Match`, `Operation`, `OpMetadataList`  
- `internal/policy/engine.go` — `Evaluate*`, `matchesScope` / key prefix  
- `internal/policy/engine_test.go`, `rules_test.go` — patterns  
- `internal/api/registry.go` — `handleListMetadata`, `handleGetMetadata` (~509–650)  
- `internal/api/credentials.go` — `handleListLLMProviders`, vend handlers  
- `internal/api/server.go` — route registration  
- `internal/api/credentials_test.go` — LLM list tests  
- `internal/credentials/vend.go` — `SupportedProviders`  
- `docs/examples/policy-step-up.yaml` — policy examples  

### kpm
- `internal/kpm/list_cmd.go` — `RunList`  
- `internal/kpm/registry.go` — `SecretMetadata`, `ListMetadata`  
- `internal/kpm/client.go` — HTTP client patterns  
- `cmd/kpm/main.go` — `list` flags (~702)  
- `internal/kpm/cmd_test.go` — `TestRunList*`  

## Contracts (current)

```text
policy.Evaluate(ctx, identity, operation, keyID string)  // keyID = resource path for secrets
Match.KeyPrefix  // string prefix on keyID
Match.KeyIDs     // exact allowlist
OpMetadataList = "metadata_list"
GET /metadata → handleListMetadata  // today: single Evaluate(..., "metadata/*")
GET /metadata/{path} → Evaluate(..., path)
GET /credentials/llm → { "providers": [...] }  // no policy filter today
kpm RunList → Client.ListMetadata only
```

## Known pitfalls

- List currently authorizes once with `"metadata/*"` — **not** per-path hide.  
- `handleListLLMProviders` returns enum of all supported names, not “configured only.”  
- Do not call per-provider **vend** for list (rate limit + material).  
- Deny rules must not leak via 403 vs 404 on describe.  

## Explicitly excluded

- `internal/plugin/**` dynamic venders (P2+)  
- Full OpenBao integration tests unless already standard in module  

---

## File map (P0)

| Area | Create | Modify |
|------|--------|--------|
| Policy path matching | `internal/policy/path_match.go` (optional helper) | `rules.go`, `engine.go`, tests |
| API list filter | — | `registry.go`, `credentials.go`, tests |
| Optional catalog DTO | `internal/api/catalog.go` if shared type helps | — |
| KPM client | — | `registry.go` or `catalog.go`, `list_cmd.go`, `main.go`, tests |
| Docs | — | kpm README snippet; DDR status line |

---

### Task 1: Policy — path_pattern + document path-as-keyID

**Files:**
- Modify: `internal/policy/rules.go` (`Match` struct)
- Modify: `internal/policy/engine.go` (matching)
- Create or modify: `internal/policy/path_match_test.go` / extend `engine_test.go`
- Modify: `internal/policy/rules_test.go` validation if needed

**Interfaces:**
- Consumes: existing `Match`, `EvaluateAtWithStrength`
- Produces: `Match.PathPattern string` `yaml:"path_pattern,omitempty"`; matching helper `pathMatches(pattern, path string) bool`

**Behavior:**
- `path_pattern` uses `path.Match` for simple globs (`supersecret/*`, `llm/*`).  
- For recursive trees, support trailing `/**` as “prefix + rest” (e.g. `supersecret/**` ⇒ path == `supersecret` OR has prefix `supersecret/`).  
- If `path_pattern` set, it applies to `keyID` (resource path).  
- Precedence: if `KeyIDs` non-empty, exact KeyIDs only (existing); else if `path_pattern` set, use it; else `KeyPrefix` (existing).  
- Empty pattern = match all (existing empty semantics).

- [ ] **Step 1: Write failing tests**

```go
// engine_test.go or path_match_test.go
func TestPathPatternSupersecretDenyList(t *testing.T) {
    // policy: deny metadata_list for path_pattern supersecret/**
    // allow metadata_list for *
    // Evaluate(..., OpMetadataList, "supersecret/stripe") → Allow false
    // Evaluate(..., OpMetadataList, "UTA/mssql-user") → Allow true
}

func TestPathPatternLLMPrefix(t *testing.T) {
    // allow metadata_list only path_pattern llm/*
    // llm/anthropic allow; UTA/x deny
}
```

- [ ] **Step 2: Run tests — expect FAIL**

```bash
cd /Users/BertSmith/work/agentkms && go test ./internal/policy/ -count=1 -run 'TestPathPattern'
```

Expected: FAIL (not implemented)

- [ ] **Step 3: Implement Match.PathPattern + engine match**

Add field to `Match` in `rules.go`. In `engine.go` where `KeyPrefix`/`KeyIDs` are applied, call path matcher on `keyID`. Validate unknown ops unchanged; validate `path_pattern` non-empty compiles (reject invalid `path.Match` patterns in `Validate()`).

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test ./internal/policy/ -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/policy/
git commit -m "feat(policy): path_pattern match for secret resource paths"
```

---

### Task 2: API — per-path filter on GET /metadata list

**Files:**
- Modify: `internal/api/registry.go` (`handleListMetadata`)
- Modify: tests under `internal/api/` (registry list tests; add if missing)

**Interfaces:**
- Consumes: `s.policy.Evaluate(ctx, id, audit.OperationMetadataList, path)`
- Produces: filtered JSON secrets list (same response shape)

**Behavior:**
1. Keep coarse gate optional: if `Evaluate(..., "metadata/*")` or `Evaluate(..., "*")` fully denies all list, return 403 as today **or** empty list — prefer: still iterate and filter (empty list if all denied) for supersecret-only denylists.  
   **Decision:** Remove reliance on single allow of `metadata/*` as sufficient to return all rows. Algorithm:
   - Load all metadata rows from registry (as today after authn).  
   - For each row path `p`, `Evaluate(ctx, id, metadata_list, p)`; if `!Allow`, **omit**.  
   - If caller has **no** allow for any list op at all (engine deny-all), return 403 once (detect: Evaluate on a sentinel or first deny-all policy) — simpler approach: if after filter empty **and** `Evaluate(..., metadata_list, "*")` is deny with deny-all identity, 403; else empty 200.  
   **Simplest correct approach for P0:**  
   - Require `Evaluate(ctx, id, metadata_list, "*")` or existing global allow (today’s stub allow-all still works).  
   - **Additionally** filter each path; deny rules with `path_pattern` omit rows.  
   - Global deny of `metadata_list` without path still 403 before listing.

- [ ] **Step 1: Failing test — supersecret omitted**

```go
func TestListMetadata_OmitsDeniedPathPattern(t *testing.T) {
    // server with policy:
    // - deny metadata_list path_pattern supersecret/**
    // - allow metadata_list *
    // registry has supersecret/a and UTA/b
    // GET /metadata → only UTA/b
}
```

- [ ] **Step 2: Run — FAIL**

```bash
go test ./internal/api/ -count=1 -run TestListMetadata_OmitsDenied
```

- [ ] **Step 3: Implement per-path filter in `handleListMetadata`**

After building the slice of metadata maps/structs, filter with policy. Never include value fields (existing strip remains).

- [ ] **Step 4: Describe 404 uniformity**

In `handleGetMetadata`, if `!decision.Allow`, return **404** not 403 (change from current 403 if present). Same body shape as not-found. Test both missing path and denied path look identical to client.

- [ ] **Step 5: `go test ./internal/api/ -count=1` PASS + commit**

```bash
git commit -m "feat(api): per-path policy filter on metadata list; describe 404 on deny"
```

---

### Task 3: API — policy filter on GET /credentials/llm (+ synthetic paths)

**Files:**
- Modify: `internal/api/credentials.go` (`handleListLLMProviders`)
- Modify: `internal/api/credentials_test.go`

**Behavior:**
- For each name in `credentials.SupportedProviders`, path = `"llm/" + name`.  
- Include in response only if `Evaluate(ctx, id, metadata_list, path).Allow`.  
- Response shape stays `{ "providers": [...] }` sorted for stability.  
- Do **not** vend keys.  
- Optional: add `GET /metadata/llm/{provider}` alias later; P0 kpm uses providers list + synthetic metadata rows client-side.

- [ ] **Step 1: Failing test**

```go
func TestListLLMProviders_RespectsPathPolicy(t *testing.T) {
    // deny metadata_list path_pattern llm/openai
    // allow metadata_list *
    // GET /credentials/llm → includes anthropic, excludes openai
}
```

- [ ] **Step 2–4: Implement, test, commit**

```bash
go test ./internal/api/ -count=1 -run TestListLLMProviders
git commit -m "feat(api): filter LLM provider list by metadata_list policy per path"
```

---

### Task 4: API — E1 vend without list (regression lock)

**Files:**
- Modify: `internal/api/credentials_test.go` (or new `catalog_policy_test.go`)

**Behavior:** Policy can **deny** `metadata_list` for `llm/anthropic` but **allow** `credential_vend` for same path. GET list omits; GET vend still 200 when key present.

- [ ] **Step 1: Test**

```go
func TestVendAllowedWhenListDenied(t *testing.T) {
    // deny metadata_list path_pattern llm/**
    // allow credential_vend *
    // GET /credentials/llm → empty or no anthropic
    // GET /credentials/llm/anthropic with key → 200
}
```

- [ ] **Step 2: Fix only if vend path incorrectly requires list (should already work)**

- [ ] **Step 3: Commit**

```bash
git commit -m "test(api): vend allowed when metadata_list denied (E1)"
```

---

### Task 5: KPM client — ListLLMProviders + catalog merge types

**Files:**
- Modify: `internal/kpm/client.go` or create `internal/kpm/catalog.go`
- Modify: `internal/kpm/registry.go` if extending `SecretMetadata`
- Test: `internal/kpm/catalog_test.go`

**Interfaces:**

```go
// ListLLMProviders returns provider names from GET /credentials/llm (metadata only).
func (c *Client) ListLLMProviders(ctx context.Context) ([]string, error)

// CatalogItem is a unified list row (no values).
type CatalogItem struct {
    Path    string   // "llm/anthropic" or "UTA/mssql-user"
    Service string
    Name    string
    Type    string   // "generic" | "llm-session" | ...
    Source  string   // "registry" | "llm"
    Version int      // 0 if N/A
    // ... map other SecretMetadata fields when source=registry
}
```

- [ ] **Step 1: Failing unit test with httptest**

```go
func TestListLLMProviders(t *testing.T) {
    // mock server returns {"providers":["anthropic","openai"]}
    // client.ListLLMProviders → two names
}
```

- [ ] **Step 2–4: Implement, test, commit**

```bash
cd /Users/BertSmith/work/kpm && go test ./internal/kpm/ -count=1 -run TestListLLMProviders
git commit -m "feat(kpm): ListLLMProviders client for catalog federation"
```

---

### Task 6: KPM CLI — `list --all` and `list --path`

**Files:**
- Modify: `cmd/kpm/main.go` (flags)
- Modify: `internal/kpm/list_cmd.go` (`RunList` signature)
- Modify: `internal/kpm/cmd_test.go`

**Interfaces:**

```go
func RunList(ctx context.Context, w io.Writer, client *Client,
    service, tag, secretType string,
    includeDeleted, jsonOutput, allSources bool,
    pathPrefix string,
) error
```

**Behavior:**
- `allSources == false` (default): current registry-only behavior.  
- `allSources == true`: registry rows + for each LLM provider a synthetic row `Path=llm/{p}`, `Type=llm-session`, `Service=llm`, `Name={p}`.  
- `pathPrefix != ""`: keep rows whose Path has prefix (normalize: ensure filter works for `llm/` and `llm`).  
- Existing service positional arg still filters registry service name; with `--all`, also filter synthetic rows by Service/Path.  
- Help text: `kpm list --all` / `kpm list --path llm/`.

Flags:

```text
-all
    include LLM catalog (and future sources) after policy-filtered server responses
-path string
    path prefix filter (e.g. llm/ or UTA/)
```

- [ ] **Step 1: Tests for RunList --all and --path**

```go
func TestRunListAllIncludesLLM(t *testing.T) { ... }
func TestRunListPathPrefix(t *testing.T) { ... }
```

- [ ] **Step 2: Implement flags in main.go + RunList**

- [ ] **Step 3:**

```bash
go test ./internal/kpm/ ./cmd/kpm/ -count=1
```

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(kpm): list --all and --path for federated catalog UX"
```

---

### Task 7: Docs + DDR status + example policy

**Files:**
- Modify: `docs/design/2026-07-14-unified-secret-catalog-plugins-policy.md` — Status: **P0 planned**; link this plan; record locked decisions  
- Modify: `work/kpm/README.md` (list section) — `--all` / `--path`  
- Create: `docs/examples/policy-catalog-visibility.yaml` — supersecret deny list + allow vend example  

Example policy snippet:

```yaml
version: "1"
rules:
  - id: deny-list-supersecret
    effect: deny
    match:
      operations: [metadata_list]
      path_pattern: "supersecret/**"
  - id: allow-vend-supersecret-stripe
    effect: allow
    match:
      operations: [credential_vend]
      path_pattern: "supersecret/stripe-master"
  - id: allow-list-default
    effect: allow
    match:
      operations: [metadata_list, credential_vend, secret_write, secret_history]
      identity:
        caller_id_pattern: "*"
```

- [ ] **Step 1: Write example + README**  
- [ ] **Step 2: Update DDR open questions with locked table**  
- [ ] **Step 3: Commit docs**

```bash
git commit -m "docs: catalog P0 visibility policy example and list --all"
```

---

### Task 8: Integration smoke (manual / script)

**Files:** none required; optional `docs/superpowers/plans/…` checklist only

- [ ] **Step 1:** Against local or odev with PE-safe commands:

```bash
# registry only
kpm list
# federation
kpm list --all
kpm list --path llm/
kpm describe UTA/mssql-user   # meta only
```

- [ ] **Step 2:** Record PASS/FAIL in worker return; do not print secret values  

- [ ] **Step 3:** Independent quality: `go test ./internal/policy/ ./internal/api/ -count=1` in agentkms; `go test ./internal/kpm/ -count=1` in kpm  

---

## PR / commit stack (recommended)

1. `agentkms`: Task 1 policy path_pattern  
2. `agentkms`: Tasks 2–4 API filters + tests  
3. `kpm`: Tasks 5–6 client + CLI  
4. Docs Task 7 (either repo or both)  

Ship gate: tests green; no values in list output; E1 test present.

---

## Follow-on plans (do not implement in this plan)

| Plan | Content |
|------|---------|
| P1 | Static-kv optional `VendedCredential` envelope |
| P2 | `sql-dynamic` + MSSQL, paths `db/mssql/{role}` |
| P3 | Oracle/Postgres drivers |
| P4 | `/v1/secrets`, signed policy bundles, client_mode |
| Identity | SE-bound device keys (parallel track) |

---

## Spec coverage (self-check)

| DDR P0 item | Task |
|-------------|------|
| SecretCatalog static-kv + llm (behavior) | 2, 3, 5, 6 |
| Policy filter list/describe | 1, 2 |
| kpm list --all / --path | 6 |
| describe llm metadata | 3 + 6 synthetic rows; full describe llm path optional via list only in P0 |
| Tests supersecret omit, admin see, vend-without-list | 2, 4 |
| No dynamic SQL | Out of scope |

| Placeholder scan | Clean (no TBD steps) |
| Locked OQs | In plan header |

---

## Factory notes for execution

- **Production Engineer** may issue package **v2** if implementers need more of `engine.go` match functions — use Context Request.  
- **Quality lead** ≠ implementer: run Task 8 + full `go test` packages.  
- Plant manager: no “done” until ship gate green on both modules touched.
