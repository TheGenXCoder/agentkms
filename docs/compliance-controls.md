# AgentKMS — Compliance Control Mapping

**Version:** T1 POC · April 2026  
**Frameworks:** SOC 2 Type 2 · PCI-DSS Level 1 · ISO 27001 · GDPR · CCPA · Colorado AI Act · SLG/FedRAMP-Ready

Each control is mapped to: the architectural mechanism that satisfies it, the code location that implements it, and how compliance can be evidenced (tested, audited, or demonstrated).

---

## SOC 2 Type 2

| Control | ID | Mechanism | Code Location | Evidence |
|---------|----|-----------|--------------|-|
| Logical access controls | CC6.1 | mTLS cert validation + short-lived session tokens (15min TTL) | `internal/auth/mtls.go`, `internal/auth/tokens.go` | Show that `POST /sign` with no `Authorization` header returns 401. Token validation test suite in `internal/auth/*_test.go` |
| System credentials not in env vars | CC6.2 | LLM keys in OpenBao KV; never in env vars or config files | `internal/credentials/vend.go`, `cmd/server/main.go` | Show `env | grep -i key` on running pod returns no API keys. Check `ANTHROPIC_API_KEY` is not set |
| Least-privilege access removal | CC6.3 | Session token TTL=15min; `POST /auth/revoke` immediately invalidates; `RevocationList` in `internal/auth/revocation.go` | `internal/auth/revocation.go`, `internal/api/auth.go` | Test: revoke a token, verify next request returns 401. Check revocation is effective within one request latency |
| System monitoring | CC7.2 | Every operation audited to ELK (`internal/audit/elk.go`) + local file; signed with HMAC (AU-09) | `internal/audit/elk.go`, `internal/audit/signing.go` | Count Elasticsearch docs: `GET /agentkms-audit/_count`. Show events include caller_id, outcome, timestamp |
| Change management | CC8.1 | Backend abstraction + key versioning in `RotateKey`; all rotations audited | `internal/backend/interface.go`, `internal/api/keys.go` | Show audit trail of a `POST /rotate/{key-id}`; verify `key_version` increments |
| Availability | A1.2 | Single-replica T1; HPA + pod anti-affinity in Helm chart for T2 | `deploy/helm/agentkms/values.yaml` | k3s single-node for POC; Helm chart ready to scale to 3 replicas |

---

## PCI-DSS Level 1

| Requirement | Mechanism | Code Location | Evidence |
|-------------|-----------|--------------|---------|
| Req 3 — Protect stored data | Private keys never in application layer; in OpenBao Transit only | `internal/backend/interface.go` (no key material in returns) | Adversarial test suite: `TestAdversarial_*` in `internal/backend/dev_test.go` |
| Req 4 — Encrypt in transit | mTLS (TLS 1.3 min) enforced at `pkg/tlsutil/server.go` | `pkg/tlsutil/server.go` (`MinVersion: tls.VersionTLS13`, `RequireAndVerifyClientCert`) | Show `openssl s_client` negotiates TLS 1.3 to the server port |
| Req 7 — Restrict access | Policy engine deny-by-default; per-identity, per-key, per-operation rules | `internal/policy/engine.go` (`denyByDefaultReason`) | Test: empty policy denies all. `TestDenyByDefault_EmptyPolicy` in policy tests |
| Req 8 — Identify and authenticate | Per-session identity from mTLS cert; HMAC-signed tokens bound to cert fingerprint | `internal/auth/middleware.go` (`verifyCertBinding`) | Test: token from cert A is rejected on connection authenticated with cert B |
| Req 10 — Track and monitor | Every operation logged with caller, key, outcome, timestamp to ELK + local file | `internal/audit/elk.go`, `internal/api/sign.go` | Show sign operation produces audit event in Elasticsearch with all required fields |
| Req 11.6 — Detect tampering | Audit events HMAC-signed (`sig:` tag in ComplianceTags); append-only file sink | `internal/audit/signing.go`, `internal/audit/file.go` | Verify `compliance_tags` field in ES doc contains `sig:` prefix; validate HMAC with known key |

---

## ISO 27001

| Control | Mechanism | Code Location | Evidence |
|---------|-----------|--------------|---------|
| A.9 — Access Control | mTLS + session tokens + policy engine | `internal/auth/`, `internal/policy/engine.go` | See SOC 2 CC6.1 above |
| A.10 — Cryptography | OpenBao Transit backend (ECDSA P-256, AES-256-GCM, RSA-2048, Ed25519) | `internal/backend/openbao.go` | `GET /keys` returns key algorithm metadata; show no key material returned |
| A.12.4 — Logging | HMAC-signed structured NDJSON to ELK + local file | `internal/audit/` | Show events in Kibana at `http://10.2.10.152:30561` |
| A.14 — Secure Development | AGENTS.md enforces adversarial review before merge; quality gate ≥ 85% coverage on security packages | `AGENTS.md`, `scripts/quality_check.sh` | Run `bash scripts/quality_check.sh` to show coverage thresholds pass |
| A.18 — Compliance | This document | `docs/compliance-controls.md` | — |

---

## GDPR

| Requirement | Mechanism | Code Location | Evidence |
|-------------|-----------|--------------|---------|
| Data Residency | Backend selection (OpenBao on odev; future: AWS KMS with regional restrictions) | `internal/backend/interface.go` | Show OpenBao pod runs in cluster on `odev` (on-premises); no data leaves network boundary |
| Right to Erasure | Key deletion in OpenBao renders all encrypted data inaccessible | OpenBao Transit: `DELETE /transit/keys/{key}` | Document key erasure procedure: delete key → all ciphertext produced with it becomes unrecoverable |
| Privacy by Design | Audit events store `payload_hash` (SHA-256), never the payload itself | `internal/audit/events.go` (`PayloadHash` field, `AuditEvent.Validate()`) | Show audit event: `payload_hash: sha256:...` — no raw payload. Validate() rejects any event containing key material patterns in DenyReason |
| Data Processor Agreements | AgentKMS acts as processor for LLM provider credentials; credentials are scoped, short-lived, and revoked on session end | `internal/credentials/vend.go` | Show credential TTL=3600s; token revocation cascades (session revoke → credential invalidated at natural TTL) |

---

## CCPA

CCPA controls are satisfied by the same mechanisms as GDPR (access control, data minimisation, right to deletion via key erasure). See GDPR section above.

---

## Colorado AI Act (SB 205)

| Requirement | Mechanism | Code Location | Evidence |
|-------------|-----------|--------------|---------|
| AI System Transparency | Every LLM API call is traceable to an AgentSession identifier in the audit log | `internal/audit/events.go` (`AgentSession` field) | Show audit event with `agent_session` field correlating Pi session to LLM call |
| High-Risk AI Disclosure | Audit trail captures model, timestamp, identity for every AI operation | `internal/audit/events.go` (`UserAgent`, `Timestamp`, `CallerID`) | Show audit event for a credential vend: includes `user_agent` (Pi extension version) and `agent_session` |
| Human Oversight | Policy engine can require explicit allow rules; deny-by-default means no operation happens without policy approval | `internal/policy/engine.go` | Show empty policy → all operations denied. Show policy with explicit team-level allow rules |
| Bias/Impact Auditing | Audit trail provides data foundation for impact assessments; all operations attributable to identity + session | `internal/audit/elk.go` | Query Elasticsearch for operations by `caller_id` and `team_id` to reconstruct impact scope |

---

## SLG / FedRAMP-Ready

| Requirement | Mechanism | Code Location | Evidence |
|-------------|-----------|--------------|---------|
| FIPS 140-2 Validated Crypto | OpenBao Transit uses FIPS-validated HSM paths when configured; Go standard library crypto for dev backend | Architecture §8.7; backend abstraction allows targeting FIPS backends at T3 | Backend swap: replace `internal/backend/openbao.go` config with FIPS-enabled endpoint. DevBackend used only in dev/test |
| Data Sovereignty | Single-cluster deployment on `odev`; no external calls except to OpenBao (same cluster) | `cmd/server/main.go` | Network policy: no egress from `agentkms` namespace except to `openbao` and `logging` namespaces |
| FedRAMP Controls | Architecture designed for FedRAMP Moderate/High; full authorisation package requires engagement-specific work | `docs/architecture.md §8.7` | This document maps controls; full evidence package requires System Security Plan (SSP) |

---

## Testable Evidence Summary

All compliance claims above are mechanically testable. Run the following to generate evidence:

```bash
# 1. Quality gate (coverage, vet, skip audit)
bash scripts/quality_check.sh

# 2. Adversarial test suite (key material never exposed)
go test -race -count=1 -run TestAdversarial ./...

# 3. Integration tests (real OpenBao)
AGENTKMS_VAULT_ADDR=http://127.0.0.1:8210 \
AGENTKMS_VAULT_TOKEN=$(kubectl get secret -n openbao openbao-init \
  -o jsonpath='{.data.root-token}' | base64 -d) \
go test -race -tags=integration ./internal/backend/

# 4. Audit event in Elasticsearch
kubectl run probe -n agentkms --image=curlimages/curl --restart=Never \
  --command -- curl -sf \
    -X POST -H "Content-Type: application/json" \
    -d '{"payload_hash":"sha256:a3f4b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3","algorithm":"ES256"}' \
    http://agentkms.agentkms.svc.cluster.local:8200/sign/agentkms-signing
# Then check: curl http://127.0.0.1:9200/agentkms-audit/_search?size=1

# 5. Denial audit trail
curl -sf \
  -H "Content-Type: application/json" \
  -d '{"payload_hash":"sha256:a3f4b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3","algorithm":"ES256"}' \
  http://127.0.0.1:8200/sign/nonexistent-key
# Returns 404; audit event with outcome=error is written to Elasticsearch
```
