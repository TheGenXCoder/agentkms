# AgentKMS

**AgentKMS is the secret-issuing authority for AI coding agents.** It vends scoped, short-lived credentials, enforces policy, and produces a forensic chain-of-custody when credentials leak.

Stop putting LLM API keys in `.env` files.

## Quick Start (local dev — 5 minutes)

**Unified binary** (v0.6.0+):

```bash
git clone https://github.com/TheGenXCoder/agentkms.git
cd agentkms
go build -o agentkms ./cmd/agentkms

agentkms init --dev
agentkms serve
```

**Legacy dev binary** (still supported):

```bash
go build -o agentkms-dev ./cmd/dev/
./agentkms-dev enroll
./agentkms-dev serve
```

```bash
# Verify
curl -sk https://localhost:8443/healthz
```

### Store secrets and fetch them

```bash
# Authenticate — uses client cert from ~/.agentkms/dev/
TOKEN=$(curl -s \
  --cert ~/.agentkms/dev/clients/default/client.crt \
  --key  ~/.agentkms/dev/clients/default/client.key \
  --cacert ~/.agentkms/dev/ca.crt \
  -X POST https://127.0.0.1:8443/auth/session | jq -r .token)

# Fetch a credential
curl -s \
  --cert ~/.agentkms/dev/clients/default/client.crt \
  --key  ~/.agentkms/dev/clients/default/client.key \
  --cacert ~/.agentkms/dev/ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  https://127.0.0.1:8443/credentials/llm/anthropic

# {"provider":"anthropic","api_key":"sk-ant-...","expires_at":"...","scope":"..."}
```

## Use It in Claude Code (30 seconds)

```jsonc
// Add to your Claude Code MCP settings:
{
  "mcpServers": {
    "agentkms": {
      "command": "agentkms-mcp"
    }
  }
}
```

That's it. Claude Code can now securely fetch LLM keys, sign payloads, and encrypt data — all over mTLS, zero secrets on disk. Also works with **Cursor**, **Windsurf**, and any MCP-compatible tool.

## Architecture

```
AI Tool (Claude Code, Cursor, Windsurf)
    ↓ MCP (stdio JSON-RPC)
agentkms-mcp  (local binary, cmd/mcp)
    ↓ mTLS
AgentKMS  (laptop / corp VPC, cmd/server or cmd/dev)
    ↓ plugin API (gRPC, api/plugin/v1/plugin.proto)
dynsecrets-github | dynsecrets-aws | community plugins
    ↓
GitHub App API | AWS STS | ...
```

**Private key material never leaves the backend. No exceptions.**

## Key Features

### v0.6 — Unified CLI & invite flow
- `agentkms init --dev | --prod --host <fqdn>`
- `agentkms invite <user>` → `kpmi1_…` codes for `kpm login`
- `agentkms serve` — single production entrypoint
- Remote invite minting via authenticated admin API

### v0.3 — Dynamic secrets & MCP

Short-lived credentials generated on demand — not stored, not rotatable, not leakable in the traditional sense.
- **GitHub App PAT** — scoped installation tokens, auto-expired
- **AWS STS** — assumed-role session credentials with configurable TTL

See [`docs/design/2026-04-16-dynamic-secrets.md`](docs/design/2026-04-16-dynamic-secrets.md).

### Scoped Credential Vending Pipeline
Every credential vend passes through scope binding, policy evaluation, and forensics tagging before it leaves the server. Deny-by-default, first-match-wins, bounds enforcement.

See [`docs/design/2026-04-16-scoped-credential-vending.md`](docs/design/2026-04-16-scoped-credential-vending.md).

### MCP Server
Full MCP server (`cmd/mcp`) for Claude Code, Cursor, and any MCP-compatible tool.

| Tool | What it does |
|------|-------------|
| `agentkms_get_credential` | Fetch a short-lived LLM API key (Anthropic, OpenAI, Google, etc.) |
| `agentkms_list_providers` | List providers with stored credentials |
| `agentkms_get_secret` | Fetch any generic secret by path |
| `agentkms_sign` | Sign data — returns signature only, key stays in vault |
| `agentkms_encrypt` | Encrypt data — returns ciphertext only |
| `agentkms_decrypt` | Decrypt data — returns plaintext only |

### Plugin Architecture
Hashicorp `go-plugin` host with discovery, versioning, and signing. Multi-language support via protobuf — write plugins in Go, Python, or any language with gRPC support.

- Plugin contract: [`api/plugin/v1/plugin.proto`](api/plugin/v1/plugin.proto)
- Example plugin: [`examples/plugins/python-honeytoken-validator/`](examples/plugins/python-honeytoken-validator/)
- Plugin SDK docs: [`api/plugin/v1/README.md`](api/plugin/v1/README.md)

> **Pro feature.** Plugin discovery, signing enforcement, and the community plugin registry require a Catalyst9 Pro license.

### Forensics Chain-of-Custody
46µs credential inspection. Every vended credential carries `CredentialUUID`, `ProviderTokenHash`, `Scope`, and `ScopeHash` in the audit record. When a secret leaks, you know exactly which agent vended it and when.

See [`docs/design/2026-04-16-forensics-v0.3.md`](docs/design/2026-04-16-forensics-v0.3.md).

### Audit Ingestion & Webhook Receiver
- HMAC-signed audit events to File (NDJSON), Elasticsearch, Splunk HEC, Datadog, generic SIEM webhook
- Webhook receiver for real-time leak detection (GitHub secret scanning, etc.)

### OSS vs Pro
See [`docs/design/2026-04-16-oss-vs-paid-surface.md`](docs/design/2026-04-16-oss-vs-paid-surface.md) for the full split. Short version: local dev, self-hosted REST API, OSS backends, and single-node operation are free forever. Plugin signing, corp VPC HA, enterprise backends, and forensics dashboard are Pro.

## Deployment

### Local Dev
`cmd/dev` is a single binary with an encrypted file store — no external dependencies.

```bash
./agentkms-dev enroll   # one-time PKI bootstrap
./agentkms-dev serve    # starts mTLS server on 127.0.0.1:8443
```

**Sovereignty statement: Catalyst9 never custodies your secrets.** The server runs on your hardware. Keys never leave your environment.

### Corp VPC
See [`docs/deployment-guide.md`](docs/deployment-guide.md) for production deployment on Kubernetes with OpenBao or HashiCorp Vault.

```bash
# Quick Helm deploy (OpenBao backend)
helm repo add openbao https://openbao.github.io/openbao-helm
helm install openbao openbao/openbao --set server.ha.enabled=true

helm install agentkms ./deploy/helm/agentkms/ \
  --set backend.type=openbao \
  --set backend.address=http://openbao:8200
```

### Production golden path (invite + KPM)

On the server (or admin machine with access):

```bash
agentkms init --prod --host agentkms.example.com
agentkms invite alice
# → prints: kpm login kpmi1_…
agentkms serve
```

On each client (laptop, CI runner, second machine):

```bash
kpm update -y                    # v0.6.2+ recommended
kpm login kpmi1_…                # enroll + write ~/.kpm/config.yaml + session
kpm list
```

Certs land in `~/.kpm/identity/<server>/`. Re-run `agentkms invite` for additional devices or users.

### Remote access (Cloudflare Tunnel)

Use when clients are **off VPN** but should reach a k8s or odev-hosted AgentKMS with **mTLS intact**.

**Server side** (tunnel host + Zero Trust):

1. Tunnel TCP ingress: `agentkms-mstr.example.com` → `tcp://<cluster-ip>:8443`
2. DNS CNAME to the tunnel (remotely managed config — local `cloudflared/config.yml` alone is not enough)

**Client side** (every machine running KPM):

```bash
cloudflared access tcp --hostname agentkms-mstr.example.com --url localhost:8443
# run via launchd (macOS) or systemd user (Linux); KeepAlive
```

KPM config uses the **local** dial address, not the public hostname:

```yaml
default_backend: mstr
backends:
  mstr:
    server: https://localhost:8443
```

Cloudflare TCP does not expose raw mTLS on a public port — the `cloudflared access tcp` process on the client is required. On LAN/VPN, prefer internal DNS straight to the cluster (no tunnel).

**TLS SAN:** server cert should include the hostname clients verify. For `localhost` dial URLs, ensure `localhost` is in the cert SAN (or enroll with a matching invite URL).

See also: [KPM multi-backend docs](https://github.com/TheGenXCoder/kpm#multi-backend-v062).

---

## Backend Tiers

AgentKMS uses dependency injection for its vault backend — swap without changing application code.

| Tier | Backend | Use Case |
|------|---------|----------|
| **Dev** | Encrypted file store (built-in) | Local development, testing, CI |
| **Self-Hosted** | [OpenBao](https://openbao.org) | OSS server deployments |
| **Enterprise** | [HashiCorp Vault](https://www.vaultproject.io) | Existing Vault infrastructure |
| **Cloud** | AWS KMS, GCP Cloud KMS, Azure Key Vault | Cloud-native *(coming soon)* |

All backends implement the same 5-method interface — no method ever returns key material.

## KPM — The Local Secrets CLI

[KPM](https://github.com/TheGenXCoder/kpm) v0.6.2+ is the companion CLI — encrypted templates, JIT decrypt, multi-backend config.

```bash
# Install / upgrade (all platforms)
curl -sL kpm.catalyst9.ai/install | bash
kpm update -y

# Local dev (no server setup)
kpm quickstart

# Production — after agentkms invite
kpm login kpmi1_…
kpm list
kpm get @mstr/cloudflare/dns-token    # multi-backend (v0.6.2+)
```

**Multi-backend** — personal (`mstr`), team (`uta`), and local dev in one config:

```yaml
default_backend: mstr
backends:
  mstr:
    server: https://localhost:8443   # via cloudflared access tcp when remote
  uta:
    server: https://agentkms-uta.example.com:8443
```

KPM replaces `.env` files with encrypted templates — secrets are ciphertext in your repo, decrypted only at the moment your app needs them.

## Security Invariants

1. No backend method returns, logs, or exposes private key material
2. No credential is written to disk — in-memory only, zeroed after response
3. No operation succeeds without mTLS authentication + valid session token + policy allow
4. Every operation is audit-logged with HMAC signature before the response is sent
5. Error messages contain only key IDs and status codes — never key bytes

Found a vulnerability? See [SECURITY.md](SECURITY.md) or email security@catalyst9.ai.

## Documentation

| Doc | Purpose |
|-----|---------|
| [`docs/design/README.md`](docs/design/README.md) | All v0.3 design decisions |
| [`docs/deployment-guide.md`](docs/deployment-guide.md) | Corp VPC deployment (K8s, HA, TLS) |
| [`docs/deployment-windows.md`](docs/deployment-windows.md) | Windows dev server + UTA sandbox pilot |
| [`docs/backlog.md`](docs/backlog.md) | Roadmap and known gaps |
| [`docs/architecture.md`](docs/architecture.md) | Security model and component overview |
| [`docs/compliance-controls.md`](docs/compliance-controls.md) | SOC 2 / PCI-DSS / GDPR evidence |
| [`docs/security-runbook.md`](docs/security-runbook.md) | Incident response |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute |
| [KPM client](https://github.com/TheGenXCoder/kpm) | Companion CLI |

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## About

AgentKMS is built and maintained by [@TheGenXCoder](https://github.com/TheGenXCoder). It serves as the security foundation for [Catalyst9](https://catalyst9.ai), an AI security platform for regulated industries.

Enterprise support and professional services available — [get in touch](mailto:security@catalyst9.ai).
