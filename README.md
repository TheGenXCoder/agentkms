# AgentKMS

**Stop putting LLM API keys in .env files.**

AgentKMS is a cryptographic proxy and credential vending service that keeps secrets out of your code, off your disk, and away from attackers. Agents and applications receive short-lived, scoped credentials over mTLS — never raw keys.

```
Your App  ──mTLS──▶  AgentKMS  ──▶  Vault Backend
                        │
                        ├── POST /auth/session        → session token (15-min TTL)
                        ├── GET  /credentials/llm/anthropic → short-lived API key
                        ├── POST /sign/{key-id}       → signature (no private key exposed)
                        ├── POST /encrypt/{key-id}    → ciphertext
                        └── POST /decrypt/{key-id}    → plaintext
```

**Private key material never leaves the backend. No exceptions.**

## Why

Every team using LLMs has the same problem: API keys in environment variables, `.env` files, or config maps. One compromised laptop, one leaked container image, one careless `git push` — and those keys are gone.

AgentKMS eliminates this by design:
- **Zero secrets on disk** — credentials are vended at runtime, held in memory, and revoked when done
- **mTLS everywhere** — every connection is mutually authenticated
- **Short-lived tokens** — 15-minute session TTL, per-request credential scoping
- **Deny-by-default policy** — no operation succeeds without an explicit allow rule
- **Full audit trail** — every credential vend, every crypto operation, signed and logged

## Quick Start (5 minutes)

```bash
# Clone and build
git clone https://github.com/catalyst9ai/agentkms.git
cd agentkms
go build ./cmd/dev

# Enroll (generates local dev PKI — CA, server cert, client cert)
./dev enroll

# Store an LLM API key securely
./dev secrets set llm/anthropic api_key=sk-ant-your-key-here
./dev secrets set llm/openai api_key=sk-your-key-here

# Start the server (mTLS on 127.0.0.1:8443)
./dev serve
```

That's it. Your keys are now vended over mTLS, not sitting in a file.

### Make a request

```bash
# Authenticate (uses client cert from ~/.agentkms/dev/)
TOKEN=$(curl -s --cert ~/.agentkms/dev/clients/default/client.crt \
             --key ~/.agentkms/dev/clients/default/client.key \
             --cacert ~/.agentkms/dev/ca.crt \
             -X POST https://127.0.0.1:8443/auth/session | jq -r .token)

# Fetch a credential
curl -s --cert ~/.agentkms/dev/clients/default/client.crt \
        --key ~/.agentkms/dev/clients/default/client.key \
        --cacert ~/.agentkms/dev/ca.crt \
        -H "Authorization: Bearer $TOKEN" \
        https://127.0.0.1:8443/credentials/llm/anthropic

# {"provider":"anthropic","api_key":"sk-ant-...","expires_at":"..."}
```

## Backend Tiers

AgentKMS uses dependency injection for its vault backend. Swap backends without changing your application code.

| Tier | Backend | Use Case |
|------|---------|----------|
| **Dev** | In-memory (built-in) | Local development, testing, CI |
| **Self-Hosted** | [OpenBao](https://openbao.org) | Open source server deployments |
| **Enterprise** | [HashiCorp Vault](https://www.vaultproject.io) | Production with existing Vault infrastructure |
| **Cloud** | AWS KMS, GCP Cloud KMS, Azure Key Vault | Cloud-native deployments *(coming soon)* |

All backends implement the same 5-method interface:

```go
type Backend interface {
    Sign(ctx, keyID, payloadHash, alg)  → signature only
    Encrypt(ctx, keyID, plaintext)      → ciphertext only
    Decrypt(ctx, keyID, ciphertext)     → plaintext only
    ListKeys(ctx, scope)                → metadata only
    RotateKey(ctx, keyID)               → metadata only
}
```

No method ever returns key material. This is enforced at the type level.

## Features

### Security
- **mTLS with TLS 1.3** — client certificate required on every connection
- **Session tokens** — HMAC-signed, 15-minute TTL, revocable
- **Deny-by-default policy engine** — YAML rules with team, scope, key, and operation constraints
- **Credential path protection** — blocks reads to `.env`, private keys, auth files
- **Rate limiting** — per-caller, per-provider sliding window
- **Anomaly detection** — statistical outlier flagging for unusual access patterns

### Credential Vending
- **LLM providers** — Anthropic, OpenAI, Google, Azure, Bedrock, Mistral, Groq, xAI
- **Generic secrets** — vend any key/value secret via `GET /credentials/generic/{path}`
- **Auto-rotation** — master key rotation on configurable schedule
- **Zero persistence** — credentials exist in memory only, zeroed after HTTP response

### Audit & Compliance
- **HMAC-signed audit events** — tamper-evident logging on every operation
- **Multiple sinks** — File (NDJSON), Elasticsearch, Splunk HEC, Datadog, generic SIEM webhook
- **SOC 2 evidence export** — automated compliance report generation
- **GDPR/CCPA endpoints** — data export, deletion, and anonymization

### Operations
- **Helm chart** — deploy to Kubernetes with `helm install`
- **Health checks** — `/healthz` and `/readyz` for liveness/readiness probes
- **Prometheus metrics** — built-in `/metrics` endpoint
- **Dual-run mode** — migrate between backends with zero downtime

## API Reference

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/session` | Authenticate via mTLS → receive session token |
| `POST` | `/auth/refresh` | Refresh expiring session token |
| `POST` | `/auth/revoke` | Revoke session token |
| `POST` | `/auth/delegate` | Mint scoped sub-agent token |

### Credentials
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/credentials/llm` | List supported LLM providers |
| `GET` | `/credentials/llm/{provider}` | Vend short-lived LLM API key |
| `POST` | `/credentials/llm/{provider}/refresh` | Refresh expiring credential |
| `GET` | `/credentials/generic/{path}` | Vend arbitrary secret |

### Cryptographic Operations
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/sign/{key-id}` | Sign payload hash → returns signature |
| `POST` | `/encrypt/{key-id}` | Encrypt plaintext → returns ciphertext |
| `POST` | `/decrypt/{key-id}` | Decrypt ciphertext → returns plaintext |
| `GET` | `/keys` | List key metadata (never key material) |
| `POST` | `/rotate/{key-id}` | Rotate key, retain historical versions |

## Architecture

```
┌─────────────┐     mTLS      ┌──────────────┐            ┌─────────────────┐
│  Your App   │──────────────▶│   AgentKMS   │───────────▶│  Vault Backend  │
│  (any lang) │◀──────────────│              │◀───────────│  (OpenBao/HC/…) │
└─────────────┘   tokens +    │  ┌─────────┐ │  Transit   └─────────────────┘
                  credentials │  │ Policy  │ │  API only
                              │  │ Engine  │ │
                              │  └─────────┘ │
                              │  ┌─────────┐ │
                              │  │  Audit  │ │──▶ SIEM / ELK / Splunk
                              │  │  Trail  │ │
                              │  └─────────┘ │
                              └──────────────┘
```

## Production Deployment

### With OpenBao (recommended for self-hosted)

```bash
# Deploy OpenBao (Helm)
helm repo add openbao https://openbao.github.io/openbao-helm
helm install openbao openbao/openbao --set server.ha.enabled=true

# Deploy AgentKMS
helm install agentkms ./deploy/helm/agentkms/ \
  --set backend.type=openbao \
  --set backend.address=http://openbao:8200
```

### With HashiCorp Vault

```bash
helm install agentkms ./deploy/helm/agentkms/ \
  --set backend.type=vault \
  --set backend.address=https://vault.example.com:8200
```

## Integrations

AgentKMS exposes a standard REST API over mTLS. Integrate from any language:

- **Go** — see `examples/go-client/`
- **Python** — see `examples/python-client/`
- **curl** — see Quick Start above
- **AI Agent Frameworks** — optional extensions available for specific frameworks

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — design decisions and security model
- [`docs/compliance-controls.md`](docs/compliance-controls.md) — SOC 2 / PCI-DSS / GDPR evidence
- [`docs/security-runbook.md`](docs/security-runbook.md) — incident response procedures
- [`docs/rotation-runbook.md`](docs/rotation-runbook.md) — key rotation guide

## Security

AgentKMS enforces these invariants at every layer:

1. No backend method returns, logs, or exposes private key material
2. No credential is written to disk — in-memory only, zeroed after use
3. No operation succeeds without mTLS authentication + valid session token + policy allow
4. Every operation is audit-logged with HMAC signature before the response is sent
5. Error messages contain only key IDs and status codes — never key bytes

Found a vulnerability? Email security@catalyst9.ai.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Built by [Catalyst9](https://catalyst9.ai)

AgentKMS is the security foundation for the Catalyst9 AI security platform. Learn more at [catalyst9.ai](https://catalyst9.ai).
