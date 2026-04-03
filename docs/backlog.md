# AgentKMS — Backlog

> **Legend**
> - **Status**: `[ ] Todo` · `[~] In Progress` · `[x] Done` · `[!] Blocked`
> - **Priority**: `P0` Critical path · `P1` High · `P2` Medium · `P3` Low / Future
> - **Phase**: `T0` Local Dev · `T1` POC K8s · `T2` Self-Hosted Prod · `T3` Cloud Prod
> - Architecture reference: `docs/architecture.md`

---

## Coordination Tooling

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| CO-01 | P0 | T0 | [x] | `scripts/coordinate.sh` — worktree + tmux + Pi launcher | Done: setup, status, open, teardown commands |
| CO-02 | P0 | T0 | [x] | `.pi/extensions/coordinator.ts` — in-session Pi extension | Done: /coord status\|next\|focus\|gates, session_start context injection |
| CO-03 | P1 | T0 | [ ] | Add `scripts/coordinate.sh` to CI health check (verify worktrees + session integrity) | — |
| CO-04 | P2 | T1 | [ ] | Extend coordinator to track cross-stream dependencies (A-04 + B-01 unblock C-01 full integration) | Currently documented as notes only |

---

## Foundation — Go Project Setup

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| F-01 | P0 | T0 | [x] | Initialise Go module (`go mod init`) with project structure per AGENTS.md | `cmd/`, `internal/`, `pkg/` layout |
| F-02 | P0 | T0 | [x] | Define `Backend` interface (`internal/backend/interface.go`) | Sign, Encrypt, Decrypt, ListKeys, RotateKey — this is the only way crypto ops are called |
| F-03 | P0 | T0 | [x] | Define `Auditor` interface (`internal/audit/interface.go`) | Log, Flush — never call a sink directly from business logic |
| F-04 | P0 | T0 | [x] | Define `AuditEvent` struct (all fields per §9.4) | payload_hash only, never payload |
| F-05 | P0 | T0 | [x] | Implement `dev` backend (`internal/backend/dev.go`) — in-memory, no external deps | Used for local dev and unit tests |
| F-06 | P0 | T0 | [x] | Implement file audit sink (`internal/audit/file.go`) — structured JSON, append-only | Used in local dev mode |
| F-07 | P1 | T0 | [x] | Implement `MultiAuditor` (`internal/audit/multi.go`) — fan-out to N sinks | All audit writes go through this |
| F-08 | P0 | T0 | [x] | Write adversarial tests for Backend interface contract | Test: key material never in return values, error paths don't leak |
| F-09 | P1 | T0 | [ ] | Add `AuditEvent.Validate()` — runtime check that `DenyReason` contains no key material patterns (PEM headers, hex key-length blobs) | Must be wired into all API handlers before C-stream items land. Identified by Opus adversarial review round 2. |

---

## Identity & Authentication

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| A-01 | P0 | T0 | [ ] | Implement mTLS server setup (`pkg/tlsutil/server.go`) | TLS 1.3 minimum, require + verify client cert |
| A-02 | P0 | T0 | [ ] | Implement cert identity extraction (`internal/auth/mtls.go`) | Parse CN, O, OU, SPIFFE SAN URI into `Identity` struct |
| A-03 | P0 | T0 | [ ] | Implement session token issuance (`internal/auth/tokens.go`) | HMAC-signed, 15min TTL, bound to identity |
| A-04 | P0 | T0 | [ ] | Implement token validation middleware | Applied to all endpoints except /auth/session |
| A-05 | P0 | T0 | [ ] | Implement token revocation (in-memory blocklist for T0; persistent for T1+) | Immediate effect on revoke |
| A-06 | P0 | T0 | [ ] | Implement `POST /auth/session` handler | mTLS only, no body, issues token |
| A-07 | P0 | T0 | [ ] | Implement `POST /auth/refresh` handler | Validates existing token, issues new one with fresh TTL |
| A-08 | P0 | T0 | [ ] | Implement `POST /auth/revoke` handler | Adds token to blocklist, 204 response |
| A-09 | P0 | T0 | [ ] | Implement `agentkms-dev enroll` CLI (`cmd/enroll/main.go`) | Generates local dev CA + developer cert + key in `~/.agentkms/dev/` |
| A-10 | P1 | T1 | [ ] | Implement PKI engine integration for cert issuance (OpenBao PKI backend) | Issues team intermediate CAs and developer certs |
| A-11 | P1 | T1 | [ ] | Implement OIDC/SAML SSO flow in `agentkms enroll` | Browser-based enrollment; maps SSO identity to team cert |
| A-12 | P2 | T2 | [ ] | Implement SPIFFE/SVID support for workload identity (K8s service accounts) | Required for CI/CD and service-to-service auth |
| A-13 | P2 | T2 | [ ] | Implement cert revocation (OCSP responder or CRL distribution) | Required for incident response |

---

## Policy Engine

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| P-01 | P0 | T0 | [x] | Define policy rule schema (team, scope, key, operation, rate, time) | `internal/policy/rules.go` — Policy, Rule, Match, IdentityMatch, TimeWindow, RateLimit, Effect, Operation structs + Validate() |
| P-02 | P0 | T0 | [x] | Implement policy loader from local YAML (`internal/policy/loader.go`) | LoadFromFile / LoadFromBytes / LoadFromReader; validates before returning; dep: gopkg.in/yaml.v3 |
| P-03 | P0 | T0 | [x] | Implement policy evaluator (`internal/policy/engine.go`) | First-match semantics; Engine.Evaluate + EvaluateAt; thread-safe Reload; Decision{Allow, DenyReason, MatchedRuleID} |
| P-04 | P0 | T0 | [x] | Enforce deny-by-default — no operation succeeds without explicit allow | TestDenyByDefault_EmptyPolicy: 360 assertions (9 identities × 8 ops × 5 key IDs), both nil and empty-slice rules, all PASS |
| P-05 | P1 | T1 | [ ] | Implement policy loader from OpenBao/Vault policy engine | Replaces local YAML in T1+ |
| P-06 | P1 | T1 | [x] | Implement rate limiting in policy engine | Per-identity, per-time-window; sliding window; rate-limit denial owns match (no fallthrough); state survives Reload; ResetRateLimits() for explicit reset |
| P-07 | P2 | T2 | [ ] | Implement anomaly detection (rules-based) | Spike detection, unusual hours, repeated denials |
| P-08 | P3 | T3 | [ ] | Implement ML-augmented anomaly detection | Baseline normal, flag statistical outliers |

---

## Cryptographic Operations API

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| C-01 | P0 | T0 | [ ] | Implement `POST /sign/{key-id}` handler | Policy check → backend.Sign() → audit → return signature only |
| C-02 | P0 | T0 | [ ] | Implement `POST /encrypt/{key-id}` handler | Policy check → backend.Encrypt() → audit → return ciphertext only |
| C-03 | P0 | T0 | [ ] | Implement `POST /decrypt/{key-id}` handler | Policy check → backend.Decrypt() → audit → return plaintext only |
| C-04 | P0 | T0 | [ ] | Implement `GET /keys` handler | Returns metadata only — id, algorithm, versions, dates. NEVER key material. |
| C-05 | P1 | T1 | [ ] | Implement `POST /keys/{key-id}/rotate` handler | Delegates to backend.RotateKey(), audits, returns new version metadata |
| C-06 | P0 | T0 | [ ] | Adversarial tests: verify no key material in any response, log, or error | Priority 0 — this is the core guarantee |
| C-07 | P1 | T1 | [ ] | Implement request input validation (payload_hash format, algorithm enum, key-id format) | Reject invalid inputs before policy check |

---

## LLM Credential Vending

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| LV-01 | P0 | T1 | [ ] | Implement `GET /credentials/llm/{provider}` handler | Fetches scoped LLM key from backend, returns with 60min TTL |
| LV-02 | P0 | T1 | [ ] | Implement LLM key storage in backend (provider keys stored as secrets, scoped per team) | Supports: anthropic, openai, google, azure, bedrock, mistral, groq |
| LV-03 | P0 | T1 | [ ] | Implement credential scoping (vended key tied to session identity and expiry) | Revocation cascades: revoke session → vended keys invalidated |
| LV-04 | P1 | T1 | [ ] | Implement credential refresh endpoint (`POST /credentials/llm/{provider}/refresh`) | Called by Pi extension when key is < 10min from expiry |
| LV-05 | P1 | T2 | [ ] | Implement master LLM key rotation schedule | Rotates master keys; all new vended keys use new version |
| LV-06 | P2 | T2 | [ ] | Implement credential audit trail (every vend, every use-associated-session logged) | Ties LLM usage back to agent session identity for compliance |

---

## Backend Implementations

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| B-01 | P0 | T1 | [ ] | Implement OpenBao/Vault Transit backend (`internal/backend/openbao.go`) | Supports: sign, encrypt, decrypt, list, rotate |
| B-02 | P1 | T1 | [ ] | Write integration tests against local OpenBao instance | Use `agentkms-dev` to spin up test instance |
| B-03 | P2 | T2 | [ ] | Implement HashiCorp Vault backend (`internal/backend/vault.go`) | Same interface as OpenBao; separate for namespace/config differences |
| B-04 | P2 | T3 | [ ] | Implement AWS KMS backend (`internal/backend/awskms.go`) | Multi-region asymmetric keys; FIPS 140-2 path |
| B-05 | P3 | T3 | [ ] | Implement GCP Cloud KMS backend (`internal/backend/gcpkms.go`) | — |
| B-06 | P3 | T3 | [ ] | Implement Azure Key Vault backend (`internal/backend/azurekv.go`) | — |
| B-07 | P1 | T2 | [ ] | Implement backend feature flag + dual-run mode (old backend for reads, new for writes) | Required for zero-downtime backend migration |

---

## Audit Backends

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| AU-01 | P0 | T0 | [ ] | Implement file audit sink (append-only JSON lines, local dev) | Baseline — always available |
| AU-02 | P1 | T1 | [ ] | Implement ELK audit sink (`internal/audit/elk.go`) — Elasticsearch ingest API | Phase 1 production audit backend |
| AU-03 | P1 | T1 | [ ] | Deploy local ELK stack on K8s (Helm charts) and validate audit event ingestion | — |
| AU-04 | P1 | T1 | [ ] | Build Kibana dashboard: operations by team, denied ops, anomaly timeline | Compliance officer-friendly |
| AU-05 | P2 | T2 | [ ] | Implement Splunk HEC audit sink (`internal/audit/splunk.go`) | — |
| AU-06 | P2 | T2 | [ ] | Implement Datadog audit sink (`internal/audit/datadog.go`) | — |
| AU-07 | P2 | T3 | [ ] | Implement AWS CloudWatch audit sink (`internal/audit/cloudwatch.go`) | — |
| AU-08 | P2 | T2 | [ ] | Implement generic SIEM webhook sink (`internal/audit/siem.go`) | Configurable endpoint + auth |
| AU-09 | P1 | T1 | [ ] | Implement audit event signing (each event HMAC-signed by AgentKMS internal key) | Tamper evidence |
| AU-10 | P2 | T2 | [ ] | Implement audit log export endpoint (for compliance auditor delivery) | Authenticated + audited |

---

## Pi Package (`@org/agentkms`)

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| PI-01 | P0 | T1 | [ ] | Scaffold Pi package (`pi-package/`) with `package.json` (`pi-package` keyword, pi manifest) | See `docs/architecture.md §6.2` |
| PI-02 | P0 | T1 | [ ] | Implement `client.ts` — HTTP client for AgentKMS API over mTLS (Node.js `https` module) | Thin; no crypto logic in this file |
| PI-03 | P0 | T1 | [ ] | Implement `identity.ts` — reads `~/.agentkms/client.crt` and `client.key` | Used by extension to establish mTLS |
| PI-04 | P0 | T1 | [ ] | Implement `session_start` hook — auth, LLM credential injection | See detailed code in §6.2 |
| PI-05 | P0 | T1 | [ ] | Implement provider override via `pi.registerProvider()` + `getApiKey()` reading from runtime map | The core key injection mechanism |
| PI-06 | P0 | T1 | [ ] | Implement `before_provider_request` hook — proactive token + key refresh | TTL thresholds: token < 5min, LLM key < 10min |
| PI-07 | P0 | T1 | [ ] | Implement `session_shutdown` hook — token revocation | Best-effort; natural expiry is fallback |
| PI-08 | P0 | T1 | [ ] | Implement `tool_call` hook — credential path protection (block reads to `.env`, `auth.json`, etc.) | Defence in depth |
| PI-09 | P0 | T1 | [ ] | Implement `model_select` hook — fetch credentials for newly selected provider | Handles mid-session provider switch |
| PI-10 | P1 | T1 | [ ] | Implement `crypto_sign` tool | See §6.2 — payload_hash only in body |
| PI-11 | P1 | T1 | [ ] | Implement `crypto_encrypt` tool | — |
| PI-12 | P1 | T1 | [ ] | Implement `crypto_decrypt` tool | — |
| PI-13 | P1 | T1 | [ ] | Write `skills/agentkms/SKILL.md` | When to use, rules, key ID format |
| PI-14 | P1 | T1 | [ ] | Publish to private npm registry | Pin version in enterprise settings.json |
| PI-15 | P2 | T2 | [ ] | Implement `/agentkms-status` Pi command (token TTL, connected identity, active providers) | Developer visibility |
| PI-16 | P2 | T2 | [ ] | Write enterprise `settings.json` template + AGENTS.md template for distribution | Via `agentkms enroll` CLI output |

---

## Local Dev Mode (`agentkms-dev`)

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| D-01 | P0 | T0 | [ ] | Implement `agentkms-dev server` command — starts local service with in-memory backend | Mirrors production API surface exactly |
| D-02 | P0 | T0 | [ ] | Implement `agentkms-dev enroll` — generates local dev CA + developer cert | Writes to `~/.agentkms/dev/` |
| D-03 | P1 | T0 | [ ] | Implement `agentkms-dev key create` — creates personal key in dev backend | `--name`, `--algorithm` flags |
| D-04 | P1 | T0 | [ ] | Implement dev policy loader from `~/.agentkms/dev-policy.yaml` | Same schema as production policy |
| D-05 | P2 | T3 | [ ] | Implement `agentkms-dev sync` — pull key metadata + policy from central (read-only) | Stretch goal; see §4.6 |

---

## Infrastructure & Deployment

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| IN-01 | P0 | T1 | [ ] | Write Dockerfile for AgentKMS service (multi-stage, minimal base image) | Distroless or scratch + CA certs |
| IN-02 | P0 | T1 | [ ] | Write Helm chart for AgentKMS service (3 replicas, pod anti-affinity, HPA) | — |
| IN-03 | P0 | T1 | [ ] | Deploy OpenBao via Helm (HA Raft, 3 replicas, mTLS listener) | See `security_arch.md` Helm snippet |
| IN-04 | P0 | T1 | [ ] | Configure OpenBao Transit + PKI secrets engines | Transit: asymmetric keys; PKI: team intermediate CAs |
| IN-05 | P1 | T1 | [ ] | Deploy ELK stack via Helm (Elasticsearch + Logstash + Kibana) | Phase 1 audit sink |
| IN-06 | P1 | T1 | [ ] | Write CI pipeline (lint, vet, test, build, Docker push) | GitHub Actions or equivalent |
| IN-07 | P2 | T2 | [ ] | Configure HPA for AgentKMS (CPU + RPS metrics) | — |
| IN-08 | P2 | T2 | [ ] | Deploy Prometheus + Grafana (latency p99, error rate, audit volume dashboards) | — |
| IN-09 | P2 | T3 | [ ] | EKS deployment with IRSA for AWS KMS access | — |
| IN-10 | P2 | T3 | [ ] | AWS KMS multi-region key setup + Route 53 failover | — |
| IN-11 | P3 | T3 | [ ] | FedRAMP control mapping document (evidence collection for each control) | Required for government sales |

---

## Compliance & Documentation

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| CX-01 | P1 | T1 | [ ] | Write compliance control mapping (architecture.md §8 → testable evidence) | Investor + auditor artifact |
| CX-02 | P1 | T2 | [ ] | Write security runbook (incident response for: cert compromise, token leak, audit failure) | Required for SOC 2 |
| CX-03 | P1 | T2 | [ ] | Write key rotation runbook (schedule, steps, rollback procedure) | Required for PCI-DSS |
| CX-04 | P2 | T2 | [ ] | Write GDPR data flow diagram (where key metadata lives, retention, erasure procedure) | — |
| CX-05 | P2 | T2 | [ ] | Write Colorado AI Act transparency statement (how agent operations are attributed + audited) | — |
| CX-06 | P1 | T1 | [ ] | API documentation (OpenAPI spec for all AgentKMS endpoints) | — |
| CX-07 | P1 | T1 | [ ] | Write developer onboarding guide (enroll → first sign operation in < 15min) | Target: zero calls to platform team |

---

## Backlog / Future

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| FX-01 | P2 | T3 | [ ] | gRPC API option (in addition to REST) | Lower latency for high-throughput workloads |
| FX-02 | P2 | T3 | [ ] | Sub-agent identity scoping (agent spawns sub-agent with reduced key scope) | Needed for multi-agent orchestration |
| FX-03 | P2 | T3 | [ ] | Key ceremony tooling for HSM-backed root keys | Investor-grade provenance for root CA |
| FX-04 | P3 | T3 | [ ] | Personal key offline support (local sync of personal key material to dev backend) | Requires careful threat modelling |
| FX-05 | P3 | T3 | [ ] | Automated SOC 2 evidence collection (exports audit records mapped to controls) | Reduces auditor prep from weeks to hours |
| FX-06 | P3 | T3 | [ ] | Web UI for key management, audit browsing, team policy editing | Non-developer enterprise admin UX |

---

## How to Use This Backlog

1. Start with the Foundation + Identity sections (T0). Nothing else works without these.
2. Pick items in ID order within each section — they are sequenced by dependency.
3. Set `[~] In Progress` when you start. Set `[x] Done` when tests pass. Note blockers with `[!]`.
4. All security-critical items (C-06, F-08, A-04) require adversarial tests before marking done.
5. Never mark an item done because the happy path works. The unhappy path is what matters here.
