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
| CO-03 | P1 | T0 | [x] | Add `scripts/coordinate.sh` to CI health check (verify worktrees + session integrity) | `health` subcommand: checks worktree exists, correct branch, clean tree (warn), go build passes |
| CO-04 | P2 | T1 | [x] | Extend coordinator to track cross-stream dependencies (A-04 + B-01 unblock C-01 full integration) | Currently documented as notes only |

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
| F-09 | P1 | T0 | [x] | Add `AuditEvent.Validate()` — runtime check that `DenyReason` contains no key material patterns (PEM headers, hex key-length blobs) | Wired into MultiAuditor.Log(); fail closed — invalid events rejected before any sink is called |

---

## Identity & Authentication

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| A-01 | P0 | T0 | [x] | Implement mTLS server setup (`pkg/tlsutil/server.go`) | TLS 1.3 minimum, require + verify client cert |
| A-02 | P0 | T0 | [x] | Implement cert identity extraction (`internal/auth/mtls.go`) | Parse CN, O, OU, SPIFFE SAN URI into `Identity` struct |
| A-03 | P0 | T0 | [x] | Implement session token issuance (`internal/auth/tokens.go`) | HMAC-signed, 15min TTL, bound to identity |
| A-04 | P0 | T0 | [x] | Implement token validation middleware | Applied to all endpoints except /auth/session; cert-binding replay protection |
| A-05 | P0 | T0 | [x] | Implement token revocation (in-memory blocklist for T0; persistent for T1+) | Immediate effect on revoke; TTL-based pruning |
| A-06 | P0 | T0 | [x] | Implement `POST /auth/session` handler | mTLS only, no body, issues token |
| A-07 | P0 | T0 | [x] | Implement `POST /auth/refresh` handler | Validates existing token, issues new one with fresh TTL |
| A-08 | P0 | T0 | [x] | Implement `POST /auth/revoke` handler | Adds token to blocklist, 204 response |
| A-09 | P0 | T0 | [x] | Implement `agentkms-dev enroll` CLI | Implemented as `agentkms-dev enroll` subcommand in `cmd/dev/main.go`; `cmd/enroll/main.go` remains a stub for production SSO (A-11) |
| A-10 | P1 | T1 | [x] | Implement PKI engine integration for cert issuance (OpenBao PKI backend) | Issues team intermediate CAs and developer certs |
| A-11 | P1 | T1 | [x] | Implement OIDC/SAML SSO flow in `agentkms enroll` | Browser-based enrollment; maps SSO identity to team cert |
| A-12 | P2 | T2 | [x] | Implement SPIFFE/SVID support for workload identity (K8s service accounts) | Required for CI/CD and service-to-service auth |
| A-13 | P2 | T2 | [x] | Implement cert revocation (OCSP responder or CRL distribution) | Required for incident response |

---

## Policy Engine

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| P-01 | P0 | T0 | [x] | Define policy rule schema (team, scope, key, operation, rate, time) | YAML + Go structs in `rules.go` |
| P-02 | P0 | T0 | [x] | Implement policy loader from local YAML (`internal/policy/loader.go`) | Used in T0/dev mode |
| P-03 | P0 | T0 | [x] | Implement policy evaluator (`internal/policy/engine.go`) | Returns allow/deny + reason for every (identity, operation, key-id) triple |
| P-04 | P0 | T0 | [x] | Enforce deny-by-default — no operation succeeds without explicit allow | Test: empty policy = all operations denied |
| P-05 | P1 | T1 | [x] | Implement policy loader from OpenBao/Vault policy engine | Replaces local YAML in T1+ |
| P-06 | P1 | T1 | [x] | Implement rate limiting in policy engine | Per (rule, callerID) sliding-window counter; conservative shared budget |
| P-07 | P2 | T2 | [x] | Implement anomaly detection (rules-based) | Spike detection, unusual hours, repeated denials |
| P-08 | P3 | T3 | [x] | Implement ML-augmented anomaly detection | Baseline normal, flag statistical outliers |

---

## Cryptographic Operations API

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| C-01 | P0 | T0 | [x] | Implement `POST /sign/{key-id}` handler | Policy check → backend.Sign() → audit → return signature only |
| C-02 | P0 | T0 | [x] | Implement `POST /encrypt/{key-id}` handler | Policy check → backend.Encrypt() → audit → return ciphertext only |
| C-03 | P0 | T0 | [x] | Implement `POST /decrypt/{key-id}` handler | Policy check → backend.Decrypt() → audit → return plaintext only |
| C-04 | P0 | T0 | [x] | Implement `GET /keys` handler | Returns metadata only — id, algorithm, versions, dates. NEVER key material. |
| C-05 | P1 | T1 | [x] | Implement `POST /keys/{key-id}/rotate` handler | Full implementation; delegates to backend.RotateKey; audit before response |
| C-06 | P0 | T0 | [x] | Adversarial tests: verify no key material in any response, log, or error | handlers_test.go: PEM scan, binary scan, audit field checks, panic recovery |
| C-07 | P1 | T1 | [x] | Implement request input validation (payload_hash format, algorithm enum, key-id format) | validation.go; rejects malformed input before policy check |

---

## LLM Credential Vending

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| LV-01 | P0 | T1 | [x] | Implement `GET /credentials/llm/{provider}` handler | Fetches scoped LLM key from backend, returns with 60min TTL |
| LV-02 | P0 | T1 | [x] | Implement LLM key storage in backend (provider keys stored as secrets, scoped per team) | Supports: anthropic, openai, google, azure, bedrock, mistral, groq |
| LV-03 | P0 | T1 | [x] | Implement credential scoping (vended key tied to session identity and expiry) | Revocation cascades: revoke session → vended keys invalidated |
| LV-04 | P1 | T1 | [x] | Implement credential refresh endpoint (`POST /credentials/llm/{provider}/refresh`) | Called by Pi extension when key is < 10min from expiry |
| LV-05 | P1 | T2 | [x] | Implement master LLM key rotation schedule | Rotates master keys; all new vended keys use new version |
| LV-06 | P2 | T2 | [x] | Implement credential audit trail (every vend, every use-associated-session logged) | Ties LLM usage back to agent session identity for compliance |

---

## Backend Implementations

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| B-01 | P0 | T1 | [x] | Implement OpenBao/Vault Transit backend (`internal/backend/openbao.go`) | Supports: sign, encrypt, decrypt, list, rotate; unit tests + integration test skeleton (build tag: integration) |
| B-02 | P1 | T1 | [x] | Write integration tests against local OpenBao instance | Use `agentkms-dev` to spin up test instance |
| B-03 | P2 | T2 | [x] | Implement HashiCorp Vault backend (`internal/backend/vault.go`) | Same interface as OpenBao; separate for namespace/config differences |
| B-04 | P2 | T3 | [ ] | Implement AWS KMS backend (`internal/backend/awskms.go`) | Multi-region asymmetric keys; FIPS 140-2 path |
| B-05 | P3 | T3 | [ ] | Implement GCP Cloud KMS backend (`internal/backend/gcpkms.go`) | — |
| B-06 | P3 | T3 | [ ] | Implement Azure Key Vault backend (`internal/backend/azurekv.go`) | — |
| B-07 | P1 | T2 | [x] | Implement backend feature flag + dual-run mode (old backend for reads, new for writes) | Required for zero-downtime backend migration |

---

## Audit Backends

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| AU-01 | P0 | T0 | [x] | Implement file audit sink (append-only JSON lines, local dev) | Done as F-06; `internal/audit/file.go` |
| AU-02 | P1 | T1 | [x] | Implement ELK audit sink (`internal/audit/elk.go`) — Elasticsearch ingest API | Phase 1 production audit backend |
| AU-03 | P1 | T1 | [x] | Deploy local ELK stack on K8s (Helm charts) and validate audit event ingestion | — |
| AU-04 | P1 | T1 | [x] | Build Kibana dashboard: operations by team, denied ops, anomaly timeline | Compliance officer-friendly |
| AU-05 | P2 | T2 | [x] | Implement Splunk HEC audit sink (`internal/audit/splunk.go`) | — |
| AU-06 | P2 | T2 | [x] | Implement Datadog audit sink (`internal/audit/datadog.go`) | — |
| AU-07 | P2 | T3 | [ ] | Implement AWS CloudWatch audit sink (`internal/audit/cloudwatch.go`) | — |
| AU-08 | P2 | T2 | [x] | Implement generic SIEM webhook sink (`internal/audit/siem.go`) | Configurable endpoint + auth |
| AU-09 | P1 | T1 | [x] | Implement audit event signing (each event HMAC-signed by AgentKMS internal key) | EventSigner + SigningAuditor; HMAC-SHA256; sig: tag in ComplianceTags |
| AU-10 | P2 | T2 | [x] | Implement audit log export endpoint (for compliance auditor delivery) | Authenticated + audited |

---

## Pi Package (`@org/agentkms`)

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| PI-01 | P0 | T1 | [x] | Scaffold Pi package (`pi-package/`) with `package.json` (`pi-package` keyword, pi manifest) | See `docs/architecture.md §6.2` |
| PI-02 | P0 | T1 | [x] | Implement `client.ts` — HTTP client for AgentKMS API over mTLS (Node.js `https` module) | Thin; no crypto logic in this file |
| PI-03 | P0 | T1 | [x] | Implement `identity.ts` — reads `~/.agentkms/client.crt` and `client.key` | Used by extension to establish mTLS |
| PI-04 | P0 | T1 | [x] | Implement `session_start` hook — auth, LLM credential injection | See detailed code in §6.2 |
| PI-05 | P0 | T1 | [x] | Implement provider override via `pi.registerProvider()` + `getApiKey()` reading from runtime map | The core key injection mechanism |
| PI-06 | P0 | T1 | [x] | Implement `before_provider_request` hook — proactive token + key refresh | TTL thresholds: token < 5min, LLM key < 10min |
| PI-07 | P0 | T1 | [x] | Implement `session_shutdown` hook — token revocation | Best-effort; natural expiry is fallback |
| PI-08 | P0 | T1 | [x] | Implement `tool_call` hook — credential path protection (block reads to `.env`, `auth.json`, etc.) | Blocks read + write + edit to credential paths |
| PI-09 | P0 | T1 | [x] | Implement `model_select` hook — fetch credentials for newly selected provider | Handles mid-session provider switch |
| PI-10 | P1 | T1 | [x] | Implement `crypto_sign` tool | payload_hash only in body; key_version in response |
| PI-11 | P1 | T1 | [x] | Implement `crypto_encrypt` tool | — |
| PI-12 | P1 | T1 | [x] | Implement `crypto_decrypt` tool | — |
| PI-13 | P1 | T1 | [x] | Write `skills/agentkms/SKILL.md` | When to use, rules, key ID format |
| PI-14 | P1 | T1 | [x] | Publish to private npm registry | Pin version in enterprise settings.json |
| PI-15 | P2 | T2 | [x] | Implement `/agentkms-status` Pi command (token TTL, connected identity, active providers) | Developer visibility |
| PI-16 | P2 | T2 | [x] | Write enterprise `settings.json` template + AGENTS.md template for distribution | Via `agentkms enroll` CLI output |

---

## Local Dev Mode (`agentkms-dev`)

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| D-01 | P0 | T0 | [x] | Implement `agentkms-dev server` command — starts local service with in-memory backend | Mirrors production API surface exactly; loopback-only enforcement |
| D-02 | P0 | T0 | [x] | Implement `agentkms-dev enroll` — generates local dev CA + developer cert | Writes to `~/.agentkms/dev/` |
| D-03 | P1 | T0 | [x] | Implement `agentkms-dev key create` — creates personal key in dev backend | `--name`, `--algorithm` flags |
| D-04 | P1 | T0 | [x] | Implement dev policy loader from `~/.agentkms/dev-policy.yaml` | Same schema as production policy |
| D-05 | P2 | T3 | [ ] | Implement `agentkms-dev sync` — pull key metadata + policy from central (read-only) | Stretch goal; see §4.6 |

---

## Infrastructure & Deployment

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| IN-01 | P0 | T1 | [x] | Write Dockerfile for AgentKMS service (multi-stage, minimal base image) | Multi-stage: Go build → CA certs → distroless/static-debian12:nonroot; TARGETOS/TARGETARCH from buildx |
| IN-02 | P0 | T1 | [x] | Write Helm chart for AgentKMS service (3 replicas, pod anti-affinity, HPA) | deploy/helm/agentkms/; deployed to odev k3s cluster |
| IN-03 | P0 | T1 | [x] | Deploy OpenBao via Helm (HA Raft, 3 replicas, mTLS listener) | Running on odev (openbao namespace); initialized, unsealed, HA active |
| IN-04 | P0 | T1 | [x] | Configure OpenBao Transit + PKI secrets engines | transit/: agentkms-signing (ES256), agentkms-encrypt (AES256GCM), platform-signing; pki/: AgentKMS Intermediate CA + agentkms role; kv/: LLM creds; k8s auth role for agentkms SA |
| IN-05 | P1 | T1 | [x] | Deploy ELK stack via Helm (Elasticsearch + Logstash + Kibana) | Phase 1 audit sink |
| IN-06 | P1 | T1 | [x] | Write CI pipeline (lint, vet, test, build, Docker push) | .github/workflows/ci.yml: quality + build + health + integration jobs |
| IN-07 | P2 | T2 | [x] | Configure HPA for AgentKMS (CPU + RPS metrics) | — |
| IN-08 | P2 | T2 | [x] | Deploy Prometheus + Grafana (latency p99, error rate, audit volume dashboards) | — |
| IN-09 | P2 | T3 | [ ] | EKS deployment with IRSA for AWS KMS access | — |
| IN-10 | P2 | T3 | [ ] | AWS KMS multi-region key setup + Route 53 failover | — |
| IN-11 | P3 | T3 | [ ] | FedRAMP control mapping document (evidence collection for each control) | Required for government sales |

---

## Compliance & Documentation

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| CX-01 | P1 | T1 | [x] | Write compliance control mapping (architecture.md §8 → testable evidence) | Investor + auditor artifact |
| CX-02 | P1 | T2 | [x] | Write security runbook (incident response for: cert compromise, token leak, audit failure) | Required for SOC 2 |
| CX-03 | P1 | T2 | [x] | Write key rotation runbook (schedule, steps, rollback procedure) | Required for PCI-DSS |
| CX-04 | P2 | T2 | [x] | Write GDPR data flow diagram (where key metadata lives, retention, erasure procedure) | — |
| CX-05 | P2 | T2 | [x] | Write Colorado AI Act transparency statement (how agent operations are attributed + audited) | — |
| CX-06 | P1 | T1 | [x] | API documentation (OpenAPI spec for all AgentKMS endpoints) | — |
| CX-07 | P1 | T1 | [x] | Write developer onboarding guide (enroll → first sign operation in < 15min) | Target: zero calls to platform team |

---

## Backlog / Future

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| FX-01 | P2 | T3 | [ ] | gRPC API option (in addition to REST) | Lower latency for high-throughput workloads |
| FX-02 | P2 | T3 | [x] | Sub-agent identity scoping (agent spawns sub-agent with reduced key scope) | Needed for multi-agent orchestration |
| FX-03 | P2 | T3 | [ ] | Key ceremony tooling for HSM-backed root keys | Investor-grade provenance for root CA |
| FX-04 | P3 | T3 | [ ] | Personal key offline support (local sync of personal key material to dev backend) | Requires careful threat modelling |
| FX-05 | P3 | T3 | [x] | Automated SOC 2 evidence collection (exports audit records mapped to controls) | Reduces auditor prep from weeks to hours |
| FX-06 | P3 | T3 | [x] | Web UI for key management, audit browsing, team policy editing | Non-developer enterprise admin UX |

---

---

## Code Quality & Security

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| QS-01 | P0 | T0 | [x] | Wire real token-validation middleware — replace A-04 stub; add `*auth.TokenService` to `NewServer` signature | Security: API endpoints bypass token auth without this |
| QS-02 | P0 | T0 | [x] | Align `NewAuthHandler` to 4-arg canonical signature — add `policy.EngineI` parameter for delegate-scope validation | Signature diverged from canonical module |
| QS-03 | P1 | T1 | [x] | N/A — already had 3-arg `NewOpenBaoKV` prior to this fix signature — add `*tls.Config`; current 2-arg variant has no TLS verification to OpenBao KV | gosec G402; credential-store connection unverified |
| QS-04 | P0 | T0 | [x] | Fix integer overflow `int → uint32` in `internal/backend/dev.go` — bounds-check before `PutUint32` | gosec G115; version wrap → wrong decryption key → permanent data loss |
| QS-05 | P1 | T0 | [x] | Fix file write permissions in `cmd/enroll/main.go` — CA cert written 0644, should be 0600 | gosec G306 |
| QS-06 | P1 | T1 | [x] | Guard `TLSInsecureSkipVerify` in audit sinks — only legal in non-production; add env assertion | gosec G402; audit MITM vector if misconfigured |
| QS-07 | P2 | T0 | [x] | Remove dead code — unused const `defaultVaultPolicyPath`; dead methods `bucketCount`, `mountPath`; dead test helper `generateTestPayload` | staticcheck U1000 across all modules |
| QS-08 | P2 | T0 | [x] | Fix silently ignored errors — `_ = s.f.Close()`, `_ = json.NewEncoder(w).Encode(...)`, flush errors on shutdown | Swallowed errors mask audit log failures |
| QS-09 | P2 | T0 | [x] | Replace `panic()` in `NewServer` and `VaultPolicyLoader.Engine()` with returned `error` | Library code must not panic; goroutine panic crashes whole process |
| QS-10 | P3 | T0 | [x] | Fix all `gofmt` formatting violations (~25-44 files per module) | Required for CI lint gate |
| QS-11 | P3 | T0 | [x] | Fix staticcheck style: `rr.Body.String()` idiom; loop `append` spread (S1011); struct conversion (S1016); duplicate import (ST1019); error string punctuation (ST1005) | — |


## Forensics Track — v0.3 + post-launch monthly plugins

> See `docs/design/2026-04-16-v0.3-scope-lock.md` for the ring-fence decision and launch narrative. `docs/design/2026-04-16-forensics-v0.3.md` for product direction, `docs/design/2026-04-16-audit-schema-migration.md` for the schema plan, and `docs/design/2026-04-16-oss-vs-paid-surface.md` for the plugin + OSS/Pro split.
>
> **Column `v0.3?`** — `✓` = must ship for launch. `→N` = post-launch month N plugin release. Items without the column default to `✓`.

### Bucket A — Additive Audit Fields (done)

| ID | Pri | Phase | Status | Task | Notes |
|----|-----|-------|--------|------|-------|
| FO-A1 | P0 | T0 | [x] | Add `SchemaVersion`, `CredentialUUID`, `RuleID`, `CertFingerprint`, `CallerOU`, `CallerRole`, `CredentialType`, `ProviderTokenHash` to AuditEvent | Additive, backwards-compatible. Commits 294850c0 + 945f3495. |
| FO-A2 | P2 | T0 | [ ] | Add `RequestPath` / `MCPToolName` to AuditEvent | Additive; fold into Bucket B when convenient. |
| ~~FO-A3~~ | — | — | ~~[ ]~~ | ~~Tag v0.1.1~~ | **Dropped:** no mid-version tag, everything ships in v0.3. |

### Bucket B — Core Lifecycle + Dynamic Secrets

| ID | Pri | Phase | v0.3? | Status | Task | Notes |
|----|-----|-------|-------|--------|------|-------|
| FO-B1 | P0 | T1 | ✓ | [ ] | Scoped credential vending — replace master-credential return with per-session scope computation | `credentials/vend.go:8` notes LV-03/T2. Required for "scope at issuance" to mean anything. |
| FO-B2 | P0 | T1 | ✓ | [ ] | Implement revocation handler + `OperationRevoke` emission | Defined at `audit/events.go:34`, never emitted. |
| FO-B3 | P0 | T1 | ✓ | [ ] | Emit expiry events when TTLs lapse | Currently implicit; needs explicit event. |
| FO-B4 | P0 | T1 | ✓ | [ ] | Add `InvalidationReason` enum to audit events | `expired` / `revoked-user` / `revoked-policy` / `revoked-leak`. |
| FO-B5 | P0 | T1 | ✓ | [ ] | Harden `cmd/mcp/main.go` — tests, docs, version handshake | 593-line scaffold exists; needs productionization. |
| FO-B6 | P0 | T1 | ✓ | [ ] | `dynsecrets-github` plugin — GitHub App ephemeral PAT **(launch demo lead)** | Leads the launch narrative — Cursor/Claude vibe-coder fit. Depends on FO-D1/D2. |
| FO-B7 | P0 | T1 | ✓ | [ ] | `dynsecrets-aws` plugin — AWS STS AssumeRole **(serious-enterprise follow-up)** | Demo second; biggest blast radius. Depends on FO-D1/D2. |
| FO-B8 | P1 | T1 | →1 | [ ] | `dynsecrets-anthropic` plugin — Anthropic Admin API | Post-launch month 1 — per-user LLM attribution is its own news cycle. |
| FO-B9 | P1 | T1 | →1 | [ ] | `dynsecrets-postgres` plugin — Postgres dynamic roles | Post-launch month 1 — Vault parity. |
| FO-B10 | P1 | T1 | ✓ | [ ] | Request-coalescing layer in `CredentialVender` plugin interface | Rate-limit resilience; shared infrastructure usable by all engines. |

### Bucket C — Forensics UX & Launch

| ID | Pri | Phase | v0.3? | Status | Task | Notes |
|----|-----|-------|-------|--------|------|-------|
| FO-C1 | P0 | T1 | ✓ | [ ] | `akms forensics inspect` CLI — single-credential report | The headline demo. Under-30s end-to-end. |
| FO-C2 | P0 | T1 | ✓ | [ ] | Post-hoc detection enrichment API — PATCH credential record with `DetectedAt` + reason | Webhook-compatible. |
| FO-C3 | P0 | T1 | ✓ | [ ] | GitHub secret scanning webhook receiver | Free leak intel, immediate ticket creation. |
| FO-C4 | P0 | T1 | ✓ | [ ] | Upstream usage ingestion worker — GitHub audit log | Correlation by `ProviderTokenHash`. Single-provider launch. |
| FO-C5 | P1 | T1 | →2 | [ ] | Upstream usage ingestion worker — Anthropic Admin usage API | Post-launch month 2. |
| FO-C6 | P1 | T1 | →2 | [ ] | Upstream usage ingestion worker — AWS CloudTrail | Post-launch month 2. |
| FO-C7 | P1 | T1 | →4 | [ ] | Engineering-manager dashboard — ships as `c9-web-ui` Pro plugin | Second buyer persona. Static HTML report (FO-D9) covers OSS need at launch. |
| FO-C8 | P1 | T1 | →3 | [ ] | Rolling-average anomaly detection in OSS; ML in `c9-anomaly-ml` | Post-launch month 3. |
| FO-C9 | P1 | T1 | →3 | [ ] | Honeytoken issuance + alert pipeline | Post-launch. Cool but additive to launch narrative. |
| FO-C10 | P0 | T1 | ✓ | [ ] | Corp VPC deployment guide — Terraform / Helm, IRSA / EC2 role examples | The artifact that sells "no hosted dependency". |
| FO-C11 | P0 | T1 | ✓ | [ ] | Blog posts 5-7 for v0.3 launch — Dynamic Secrets, Forensics, Incident Response | Bundle-publish with release. |

### Bucket D — Plugin Ecosystem

> See `docs/design/2026-04-16-oss-vs-paid-surface.md`. **One `agentkms` binary, built-in plugin host, Pro = plugins.** Using `hashicorp/go-plugin` (same as Vault / Terraform / Packer — RPC over subprocess, process isolation, version independence).

| ID | Pri | Phase | v0.3? | Status | Task | Notes |
|----|-----|-------|-------|--------|------|-------|
| FO-D1 | P0 | T1 | ✓ | [ ] | Plugin host + discovery + lifecycle using `hashicorp/go-plugin` | Core infrastructure; everything else in Bucket D / Dynamic Secrets depends on this. |
| FO-D2 | P0 | T1 | ✓ | [ ] | Plugin API definitions — public interfaces (`CredentialVender`, `AuditSink`, `Anomaly`, `Ingester`, `Scope` extension points) | Locked forever at v0.3; breaking changes require major-version bump. |
| FO-D3 | P0 | T1 | ✓ | [ ] | Plugin versioning contract — semver on plugin API, load-time compatibility check | Plugins declare supported API range; core refuses mismatched plugins cleanly. |
| FO-D4 | P0 | T1 | ✓ | [ ] | 24h audit-retention pruning in OSS core + teaser footer on `akms forensics inspect` | OSS constraint; `c9-retention-unlimited` plugin lifts it. |
| FO-D5 | P0 | T1 | ✓ | [ ] | Honeytoken hard-cap at 5 active in OSS core with clear error on 6th | Hard limit; enforced, not nudged. |
| FO-D6 | P0 | T1 | ✓ | [ ] | Teaser library — shared helper for footer placement, formatting, suppression via `--no-upgrade-hints` / `AGENTKMS_HINTS=off` / config | Always respected; no loopholes. One place to tune messaging. |
| FO-D7 | P0 | T1 | ✓ | [ ] | `akms plugin` CLI — `list`, `install`, `remove`, `search` | User-facing plugin management. |
| FO-D8 | P0 | T1 | ✓ | [ ] | Plugin signing + verification (Catalyst9 plugins signed, third-party self-signed, unsigned works with warning) | Trust model for the registry. |
| FO-D9 | P0 | T1 | ✓ | [ ] | Static-HTML report generator plugin (`akms report html`) — OSS dashboard alternative | OSS-bundled; `c9-web-ui` is the Pro upgrade (post-launch). |
| FO-D10 | P1 | T1 | →3 | [ ] | Reference paid plugin — `c9-retention-unlimited` scaffold with license-file check | Post-launch; proves Pro plugin path end-to-end. |
| FO-D11 | P1 | T1 | →2 | [ ] | Plugin development guide (docs/plugin-developer.md) | Post-launch; docs can land when third parties start asking. |
| FO-D12 | P1 | T1 | →2 | [ ] | Plugin registry manifest format + static hosting at catalyst9.ai/plugins | Post-launch; bundled + known-signed plugins work without it. |
| FO-D13 | P2 | T1 | →3 | [ ] | License file format + validation library used by Pro plugins | Post-launch; needed when first commercial Pro plugin ships. |

---

## How to Use This Backlog

1. Start with the Foundation + Identity sections (T0). Nothing else works without these.
2. Pick items in ID order within each section — they are sequenced by dependency.
3. Set `[~] In Progress` when you start. Set `[x] Done` when tests pass. Note blockers with `[!]`.
4. All security-critical items (C-06, F-08, A-04) require adversarial tests before marking done.
5. Never mark an item done because the happy path works. The unhappy path is what matters here.
