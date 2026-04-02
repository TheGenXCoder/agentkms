# AgentKMS: Enterprise Cryptographic Services for Agentic Platforms

**Version:** 1.0 — April 2026
**Owner:** Bert Smith
**Status:** Authoritative design document. All implementation decisions must be reconcilable with this document.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Design Philosophy](#2-design-philosophy)
3. [System Architecture](#3-system-architecture)
4. [Components](#4-components)
5. [Identity Model](#5-identity-model)
6. [Pi Integration — Deep Dive](#6-pi-integration--deep-dive)
7. [Key & Credential Lifecycle](#7-key--credential-lifecycle)
8. [Compliance Coverage](#8-compliance-coverage)
9. [Audit Backend Strategy](#9-audit-backend-strategy)
10. [Deployment Tiers](#10-deployment-tiers)
11. [Enterprise Distribution via Pi](#11-enterprise-distribution-via-pi)
12. [Developer Experience](#12-developer-experience)
13. [Threat Model](#13-threat-model)
14. [API Reference](#14-api-reference)
15. [Roadmap](#15-roadmap)

---

## 1. Executive Summary

AgentKMS is a hardened cryptographic proxy and credential vending service purpose-built for agentic AI platforms. Its fundamental guarantee is simple and absolute: **private key material never leaves the service**. Agents, developers, and applications call a narrow API to get signatures, ciphertext, and short-lived scoped credentials. They never receive keys.

AgentKMS is not a feature or a module inside another product. It is the enterprise security foundation. Every agentic workload — whether a Pi coding session on a developer laptop, a CI/CD pipeline, or a production multi-agent orchestrator — authenticates through AgentKMS before any cryptographic operation or LLM API call occurs.

This document covers:
- Why the architecture is built this way
- How every component fits together
- How Pi (the coding agent framework) integrates with AgentKMS specifically
- How the system satisfies SOC 2 Type 2, PCI-DSS, ISO 27001, GDPR, CCPA, Colorado AI Act, and SLG/FedRAMP compliance requirements
- How it deploys from a developer's laptop to globally distributed cloud infrastructure
- How it distributes to thousands of developers across an enterprise without friction

The target audience for this document is: engineers building AgentKMS, engineers integrating against it, compliance officers reviewing it, and investors evaluating the security posture of the platform.

---

## 2. Design Philosophy

### 2.1 Zero Key Exposure — No Exceptions

This is the most important rule in the entire system. It has no carve-outs.

**What it means in practice:**
- Private key material exists only inside the crypto backend (OpenBao Transit, AWS KMS, etc.)
- AgentKMS itself never holds decrypted private key material in process memory beyond the duration of a single operation
- API responses contain only: signatures, ciphertext, public key metadata, or short-lived scoped credentials
- No key material in: logs, error messages, stack traces, debug output, HTTP headers, environment variables, config files, or agent tool call results
- LLM provider API keys are treated as key material. They are fetched at runtime, injected in-process for the duration of a session, and revoked server-side when the session ends

This rule applies to production, staging, CI/CD, and local development. There is no "dev mode" that weakens key exposure controls.

### 2.2 Zero Trust

No component, network segment, or identity is trusted implicitly. Every call is authenticated, every operation is authorised against policy, and every event is audited regardless of where it originates.

This means:
- mTLS on every network connection, including localhost in development
- Short-lived tokens — nothing is "logged in forever"
- Per-agent, per-operation policy checks — broad service accounts with catch-all permissions are not allowed
- Network adjacency confers zero privilege

### 2.3 AgentKMS is a Proxy, Not a Vault

AgentKMS does not store keys. It is a thin, opinionated policy and audit layer that proxies cryptographic operations to a backend. This design choice has several consequences:

1. **Backend is swappable** — OpenBao today, AWS KMS tomorrow, without changing any caller code
2. **AgentKMS stays simple** — it enforces policy, audits, and issues credentials. It does not implement cryptography
3. **Compliance burden is distributed** — the backend (e.g., AWS KMS) handles FIPS 140-2 compliance; AgentKMS handles access control, audit, and identity mapping
4. **Operational risk is bounded** — a compromise of AgentKMS grants an attacker access to the API, not to key material

### 2.4 Single Crypto Surface

All cryptographic operations and all LLM credential vending flow through AgentKMS. There is no "other path" for getting a key or calling an LLM API directly. This is enforced in three ways:

1. **Pi extension** intercepts all LLM calls and injects credentials fetched from AgentKMS (not from env vars)
2. **Policy** rejects unauthenticated or out-of-scope operations at the API level
3. **Audit** makes every attempt to bypass visible

### 2.5 Built for Enterprise Day One

The system is designed for thousands of developers, dozens of teams, and multiple compliance frameworks simultaneously. Features that would typically be "phase 2" (multi-tenancy, FIPS paths, GDPR data residency, FedRAMP-ready controls) are designed in from the beginning, even if not all are activated immediately.

---

## 3. System Architecture

### 3.1 High-Level Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     CONSUMER LAYER                                   │
│                                                                      │
│  ┌─────────────────────┐   ┌──────────────────┐   ┌──────────────┐  │
│  │   Pi Coding Agent   │   │  Project Puma     │   │  CI/CD       │  │
│  │   (developer)       │   │  (Next.js PWA)    │   │  Pipeline    │  │
│  │                     │   │                  │   │              │  │
│  │ ┌─────────────────┐ │   │ ┌──────────────┐ │   │ ┌──────────┐ │  │
│  │ │@org/agentkms    │ │   │ │ AgentKMS SDK │ │   │ │ AgentKMS │ │  │
│  │ │ Pi Package      │ │   │ │ (Go client)  │ │   │ │ Go client│ │  │
│  │ │ (TS extension)  │ │   │ └──────────────┘ │   │ └──────────┘ │  │
│  │ └─────────────────┘ │   └──────────────────┘   └──────────────┘  │
│  └─────────────────────┘                                             │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ mTLS (client cert per identity)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     AGENTKMS SERVICE (Go)                            │
│                                                                      │
│  ┌───────────────┐  ┌──────────────────┐  ┌───────────────────────┐ │
│  │  API Layer    │  │  Policy Engine   │  │  Audit Layer          │ │
│  │               │  │                  │  │                       │ │
│  │  REST / gRPC  │  │  Per-agent       │  │  ┌─────┐ ┌─────────┐ │ │
│  │               │  │  Per-team        │  │  │ ELK │ │ Splunk  │ │ │
│  │  /sign        │  │  Per-scope       │  │  └─────┘ └─────────┘ │ │
│  │  /encrypt     │  │  Per-key         │  │  ┌──────┐ ┌───────┐  │ │
│  │  /decrypt     │  │  Rate limits     │  │  │ CW   │ │ SIEM  │  │ │
│  │  /credentials │  │  Anomaly detect  │  │  └──────┘ └───────┘  │ │
│  │  /keys        │  └──────────────────┘  └───────────────────────┘ │
│  └───────────────┘                                                   │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │               Identity & Auth Layer                           │  │
│  │                                                               │  │
│  │  mTLS Validation → Workload Identity → Token Issuance         │  │
│  │  OIDC/SAML SSO → Developer Enrollment → Cert Management       │  │
│  │  Short-TTL Tokens (15min) → Revocation → Audit                │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │               Backend Abstraction Layer                       │  │
│  │                                                               │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────┐ ┌────────┐ │  │
│  │  │ OpenBao  │ │  Vault   │ │ AWS KMS  │ │ GCP  │ │ Azure  │ │  │
│  │  │(self-host│ │(cloud)   │ │(managed) │ │ KMS  │ │ Key    │ │  │
│  │  │ HA Raft) │ │          │ │FIPS/multi│ │      │ │ Vault  │ │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────┘ └────────┘ │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                               │
                 (Backend calls are also mTLS)
```

### 3.2 Data Flow: LLM Credential Vending

This is the most common flow — a Pi developer session starting and calling an LLM.

```
Developer opens Pi
  │
  ├─1─► Pi loads @org/agentkms Pi package (extension auto-discovered)
  │
  ├─2─► Extension: session_start event fires
  │       └─► Read mTLS client cert from ~/.agentkms/client.crt
  │       └─► POST /auth/session (mTLS authenticated)
  │       └─► AgentKMS validates cert identity → issues session token (15min TTL)
  │       └─► GET /credentials/llm/anthropic (token-authenticated)
  │       └─► AgentKMS fetches scoped LLM key from backend → returns short-lived key
  │       └─► authStorage.setRuntimeApiKey("anthropic", key) [in-memory, not persisted]
  │
  ├─3─► Developer sends message to Pi
  │
  ├─4─► Pi calls LLM (Anthropic)
  │       └─► before_provider_request event fires
  │       └─► Extension checks: is session token still valid? (< 5min remaining → refresh)
  │       └─► Extension checks: is LLM key still valid? (< 10min remaining → refresh)
  │       └─► Request proceeds with in-memory key (never an env var)
  │
  └─5─► Developer closes Pi / session ends
          └─► session_shutdown event fires
          └─► POST /auth/revoke (invalidates session token server-side)
          └─► All LLM keys scoped to this session are invalidated
```

### 3.3 Data Flow: Explicit Crypto Operation

```
Agent needs to sign a payload (e.g., a transaction, a document hash, a JWT)
  │
  ├─1─► Agent calls crypto_sign tool (registered by AgentKMS extension)
  │       OR invokes /skill:agentkms and requests a signing operation
  │
  ├─2─► Extension validates: does caller's session token allow signing with key-id?
  │       └─► If not: block with reason, log to audit
  │
  ├─3─► Extension calls AgentKMS: POST /sign/{key-id}
  │       Body: { payload_hash: "sha256:...", algorithm: "ES256" }
  │       Auth: session token (mTLS already established)
  │
  ├─4─► AgentKMS:
  │       └─► Validate token scope covers key-id
  │       └─► Check policy: is this agent allowed to sign with this key?
  │       └─► Call Backend: backend.Sign(keyId, payloadHash, algorithm)
  │       └─► Write audit: { caller, key_id, payload_hash, algorithm, timestamp, outcome }
  │       └─► Return: { signature: "base64...", key_version: 3 }
  │
  └─5─► Tool returns signature to agent (private key never appears at any layer)
```

---

## 4. Components

### 4.1 AgentKMS Service (Go)

**Purpose:** The core service binary. Enforces policy, audits all operations, and proxies crypto requests to a backend.

**Language:** Go. Chosen for: small binary size, minimal runtime, strong standard library crypto support, easy static linking, resistance to dependency supply chain attacks.

**Directory structure:**
```
cmd/
  server/     main.go          # Production server
  dev/        main.go          # Local dev server (in-memory backend, no Raft)
  enroll/     main.go          # Developer enrollment CLI

internal/
  api/                         # HTTP/gRPC handlers
    sign.go
    encrypt.go
    decrypt.go
    credentials.go
    keys.go
    auth.go
  auth/                        # mTLS validation, token lifecycle
    mtls.go                    # Client cert validation, identity extraction
    tokens.go                  # Short-lived token issuance + revocation
    session.go                 # Session lifecycle
  policy/                      # Policy engine
    engine.go                  # Evaluates: can identity X do Y with key Z?
    rules.go                   # Rule types (team, scope, key, rate)
    loader.go                  # Loads policy from config / backend
  audit/                       # Pluggable audit sinks
    interface.go               # Auditor interface
    elk.go                     # Elasticsearch/Logstash
    splunk.go                  # Splunk HEC
    cloudwatch.go              # AWS CloudWatch Logs
    datadog.go                 # Datadog Events/Logs
    siem.go                    # Generic SIEM webhook
    multi.go                   # Fan-out to multiple sinks
  backend/                     # Crypto backend abstraction
    interface.go               # Backend interface
    openbao.go                 # OpenBao / Vault Transit
    awskms.go                  # AWS KMS
    gcpkms.go                  # GCP Cloud KMS
    azurekv.go                 # Azure Key Vault
    dev.go                     # In-memory dev backend
  credentials/                 # LLM credential vending
    vend.go                    # Issues scoped, short-lived LLM keys
    providers.go               # Provider-specific key formats

pkg/
  identity/                    # Identity model types
  tlsutil/                     # mTLS helpers, SPIFFE/cert parsing
```

**Key interfaces:**

```go
// Backend is the only way to perform crypto operations. 
// Implementations are in internal/backend/.
type Backend interface {
    Sign(ctx context.Context, keyID string, payloadHash []byte, alg Algorithm) (*SignResult, error)
    Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptResult, error)
    Decrypt(ctx context.Context, keyID string, ciphertext []byte) (*DecryptResult, error)
    ListKeys(ctx context.Context, scope KeyScope) ([]*KeyMeta, error)
    RotateKey(ctx context.Context, keyID string) (*KeyMeta, error)
}

// Auditor writes structured audit events. All audit writes go here.
// Never call a specific sink directly from business logic.
type Auditor interface {
    Log(ctx context.Context, event AuditEvent) error
    Flush(ctx context.Context) error
}

// AuditEvent is the canonical audit record.
// payload_hash, never payload. key_id, never key material.
type AuditEvent struct {
    EventID      string
    Timestamp    time.Time
    CallerID     string    // From mTLS cert CN or workload identity
    TeamID       string
    AgentSession string    // Per-Pi-session identifier
    Operation    string    // "sign", "encrypt", "decrypt", "credential_vend", "auth"
    KeyID        string
    PayloadHash  string    // SHA-256 of input, never the input itself
    Algorithm    string
    Outcome      string    // "success", "denied", "error"
    DenyReason   string
    SourceIP     string
    UserAgent    string
}
```

### 4.2 AgentKMS Pi Package (TypeScript)

**Purpose:** Thin client extension that wires Pi into AgentKMS. Contains zero crypto logic — it calls the AgentKMS service for everything. Distributed as a Pi package installable with one command.

**What it is NOT:** This is not a crypto library, not a key store, not a secrets manager. It is a client SDK packaged as a Pi extension.

**Package structure:**
```
pi-package/
  package.json             # { "keywords": ["pi-package"], "pi": {...} }
  extensions/
    index.ts               # Main extension: session auth, LLM credential injection
    tools.ts               # crypto_sign, crypto_encrypt, crypto_decrypt tools
    provider.ts            # registerProvider() overrides for each LLM provider
    client.ts              # HTTP client for AgentKMS API (uses mTLS via Node TLS)
    identity.ts            # Reads ~/.agentkms/ cert + config
  skills/
    agentkms/
      SKILL.md             # When to use AgentKMS, explicit crypto workflows
```

**Extension hooks used:**

| Pi Event | What the Extension Does |
|---|---|
| `session_start` | Reads mTLS cert → authenticates → gets session token → fetches LLM credentials → injects via `authStorage.setRuntimeApiKey()` |
| `before_provider_request` | Checks token/key TTLs, refreshes proactively if needed |
| `tool_call` | If any tool attempts to read a path matching credential patterns (e.g., `.env`, `auth.json`), blocks with an audit log |
| `session_shutdown` | Revokes session token server-side |
| `model_select` | On provider switch, fetches credentials for the new provider |

**Why TypeScript for the Pi package, and why that's acceptable:**
The Pi extension is a client — it makes HTTP calls over mTLS to the AgentKMS service. It contains no cryptographic code. The supply chain risk of the TypeScript package is limited to the HTTP transport layer, which is a well-understood surface. The actual crypto happens in Go on the server side. If the Pi extension package is compromised, an attacker gets network access to make authenticated AgentKMS API calls — which is bounded by the per-session identity and policy.

**Installation:**
```bash
# Enterprise-wide (admin pushes to settings.json)
pi install npm:@org/agentkms

# Project-scoped
pi install -l npm:@org/agentkms

# Pinned version (recommended for enterprise)
pi install npm:@org/agentkms@2.1.0
```

**Service vs. Package (the tradeoff):**

| Dimension | Pi Package Only | AgentKMS Service + Pi Package |
|---|---|---|
| Crypto happens | In Pi process (TypeScript) | In Go service (outside Pi process) |
| Key exposure risk | Higher — keys in Node.js heap | Lower — keys never leave Go service |
| Multi-agent support | One session per Pi instance | All sessions share one service |
| Audit trail | Per-extension log | Centralised, tamper-evident |
| Offline support | Possible (local keys in package) | Requires local dev service |
| Enterprise controls | Difficult to enforce | Policy engine in service |
| **Verdict** | **Not acceptable for production** | **Required** |

The Pi package is the **client interface** to the AgentKMS service. It is never a standalone replacement.

### 4.3 Backend Abstraction Layer

**Purpose:** Isolates all crypto operations behind a single Go interface. Swapping backends (OpenBao → AWS KMS) requires no changes to API handlers, policy engine, or audit layer.

**Backends:**

| Backend | Use Case | Phase |
|---|---|---|
| `dev` (in-memory) | Local developer machine, CI unit tests | Always available |
| OpenBao (HA Raft) | Self-hosted POC and MVP | Phase 1 + 2 |
| HashiCorp Vault | Enterprises with existing Vault investment | Phase 2 |
| AWS KMS (multi-region) | Cloud production, FIPS 140-2 | Phase 3 |
| GCP Cloud KMS | GCP-primary deployments | Phase 3 |
| Azure Key Vault | Azure-primary deployments | Phase 3 |

**Backend selection:** Configured via environment variable or config file. Only one backend is active at runtime. Migration between backends is done via dual-run (see §10).

### 4.4 Identity & Authentication Layer

**Trust hierarchy:**

```
Enterprise Root CA
  └─► Team Intermediate CA (one per team)
        └─► Developer Certificate (one per human identity)
        └─► Service Certificate (one per workload/CI/CD runner)
        └─► Agent Certificate (one per Pi session, short-TTL)
```

**Certificate fields (encoded in Subject / SANs):**
- `CN`: Identity name (user@team.org or service-name@team.org)
- `O`: Team identifier
- `OU`: Role (developer, service, agent)
- `SAN URI`: SPIFFE ID — `spiffe://agentkms.org/team/{teamID}/identity/{identityID}`

**Auth flow:**
1. Client presents mTLS certificate on TCP connection
2. AgentKMS validates cert against team Intermediate CA
3. Identity extracted from cert fields
4. Short-lived session token issued (15min, signed with AgentKMS signing key)
5. All subsequent requests authenticated via session token + existing mTLS connection
6. Token revocation is immediate and server-side

**Developer enrollment (first-time setup):**
```bash
agentkms enroll --team=platform-team
# Opens browser → OIDC/SAML SSO login
# AgentKMS issues: ~/.agentkms/client.crt + ~/.agentkms/client.key
# Pi extension auto-discovers these paths
```

**Workload identity (CI/CD, services):**
- Kubernetes: uses projected service account tokens (OIDC) to obtain a cert from AgentKMS PKI
- AWS: uses IAM role identity + STS to obtain a cert
- Generic: pre-issued service cert, rotated on schedule

### 4.5 Policy Engine

**Policy is evaluated on every operation.** There is no "always allow" wildcard for any identity.

**Policy dimensions:**

| Dimension | Example Rules |
|---|---|
| Identity | Team `platform-team` may sign with keys prefixed `platform/*` |
| Key scope | Key `payments/signing-key` may only be used for `sign` operations |
| Operation | Individual developers may not call `decrypt` on production keys |
| Rate | Max 100 sign operations per session token |
| Time | Service certs may not operate outside 06:00–22:00 UTC |
| Environment | Dev keys are not accessible from production agent identity |

**Policy storage:** Loaded from the active backend (OpenBao/Vault policy engine) OR from a local policy file for the dev backend.

**Anomaly detection (rules-based, Phase 2; ML-augmented, Phase 3):**
- Spike in operation volume from a single identity
- Operations at unusual hours for a given identity
- Repeated denied operations (possible probing)
- Cross-environment key access attempts

### 4.6 Local Dev Mode (`agentkms-dev`)

**Purpose:** Allows individual developers to work with AgentKMS on a local machine — including offline — without running Kubernetes or connecting to a central service.

**What it is:**
- A single Go binary: `agentkms-dev server`
- Uses the in-memory `dev` backend (no Raft, no remote calls)
- Enforces the same mTLS + token model as production (no shortcuts)
- Generates a local self-signed dev CA and developer cert on first run
- Policy is loaded from `~/.agentkms/dev-policy.yaml`

**What it is NOT:**
- A replacement for the production service
- A way to access production keys
- A way to skip authentication

**Central sync (stretch goal — Phase 3):**
```bash
agentkms-dev sync
# Pulls: team policy, key metadata (not material), approved key IDs
# Pushes: nothing (sync is read-only for the dev instance)
# Result: local dev operations use the same key IDs and policy as production
```

**Developer identity in dev mode:**
```bash
agentkms-dev enroll
# Generates: ~/.agentkms/dev/client.crt, ~/.agentkms/dev/client.key
# This cert is only trusted by the local dev server
# It has no authority in staging or production
```

---

## 5. Identity Model

The identity model has four tiers. Every operation is attributed to all four simultaneously in the audit log.

```
Enterprise
  └─► Team (e.g., "platform-team", "payments-team", "ml-team")
        └─► Individual Builder (human developer identity)
              └─► Agent Session (per Pi session, ephemeral)
```

### 5.1 Enterprise Identity

- The root of the PKI trust chain
- Controls: which teams exist, which backends are available, global rate limits
- Represented by: the Enterprise Root CA certificate
- Managed by: the platform security team

### 5.2 Team Identity

- Owns a namespace of keys (e.g., `payments/*`, `ml-signing/*`)
- Has a team Intermediate CA that issues developer and service certs
- Team leads can define team-scoped policies (within enterprise bounds)
- Represented by: team Intermediate CA + team config in policy store

### 5.3 Individual Builder Identity

- A human developer enrolled via SSO
- Has a personal developer certificate (issued by team Intermediate CA)
- May have personal keys under `personal/{user-id}/*` (their own key namespace)
- Personal keys are their responsibility; key metadata syncs to central for backup
- Can work offline with local dev service (dev keys only; production keys require connectivity)

**Personal key use cases:**
- Signing personal commits or artifacts
- Personal JWT signing for local development
- Encrypting personal local data

**Personal key guarantees:**
- Even personal keys never leave AgentKMS — the developer gets signatures, not key material
- Key metadata (key ID, algorithm, created date) is synced to central; key material stays in the backend

### 5.4 Agent Session Identity

- Ephemeral identity representing a single Pi session (or API call session)
- Derived from: the developer or service identity that initiated it
- Scoped to: only the operations that session type is authorised to perform
- TTL: the session token TTL (15min, renewable)
- Revocable immediately: shutting down Pi or calling `/auth/revoke` invalidates all operations from that session

**Why agent sessions have their own identity:**
- Enables per-session audit trails: "session X from user Y called sign on key Z"
- Enables per-session rate limiting
- Enables immediate revocation if a session is suspected of compromise
- Supports future multi-agent scenarios where sub-agents inherit a scoped-down identity

---

## 6. Pi Integration — Deep Dive

### 6.1 How Pi Fits

Pi is used in two distinct ways in this ecosystem:

**As a development tool for building AgentKMS:**
- Pi runs in the `agentkms/` project directory
- `AGENTS.md` gives Pi full context on the security requirements, constraints, and architecture
- Pi's session branching (`/tree`, `/fork`) is used for exploring implementation alternatives without losing history
- Skills are created for common AgentKMS development tasks (running test suites, checking compliance headers, etc.)

**As a consumer of AgentKMS via the Pi package:**
- The `@org/agentkms` Pi package is installed by developers and teams
- It wires Pi's extension system to route all LLM credentials and crypto operations through AgentKMS
- Every Pi user in the enterprise gets enterprise-grade security with one install command

### 6.2 Pi Extension Architecture

The extension (`extensions/index.ts`) is the core of the Pi package. It hooks into Pi's lifecycle:

#### `session_start` — Authentication & Credential Injection

```typescript
pi.on("session_start", async (_event, ctx) => {
  // 1. Locate identity (mTLS cert)
  const identity = await loadIdentity(); // reads ~/.agentkms/client.crt
  if (!identity) {
    ctx.ui.notify("AgentKMS: no identity found. Run `agentkms enroll`", "error");
    return;
  }

  // 2. Authenticate to AgentKMS
  const sessionToken = await client.auth(identity); // POST /auth/session over mTLS
  storeSessionToken(sessionToken); // in-memory only

  // 3. Inject LLM credentials for each configured provider
  for (const provider of MANAGED_PROVIDERS) {
    const cred = await client.getLLMCredential(provider, sessionToken);
    // authStorage is accessible via the provider override registered at load time
    runtimeKeys.set(provider, cred); // in-memory, not on disk
  }

  ctx.ui.notify("AgentKMS: authenticated ✓", "info");
});
```

#### `before_provider_request` — Token Freshness

```typescript
pi.on("before_provider_request", async (_event, _ctx) => {
  const token = getSessionToken();
  if (!token) return; // AgentKMS not active

  // Proactively refresh if token is within 5min of expiry
  if (token.expiresAt - Date.now() < 5 * 60 * 1000) {
    const refreshed = await client.refreshToken(token);
    storeSessionToken(refreshed);
  }

  // Refresh any LLM keys expiring within 10min
  for (const [provider, cred] of runtimeKeys) {
    if (cred.expiresAt - Date.now() < 10 * 60 * 1000) {
      const newCred = await client.getLLMCredential(provider, getSessionToken());
      runtimeKeys.set(provider, newCred);
      // The provider override's getApiKey() reads from runtimeKeys,
      // so the new key is used on the next call automatically
    }
  }
});
```

#### Provider Override — The Key Injection Mechanism

```typescript
// At extension load time, override each managed LLM provider
// so that getApiKey() reads from runtimeKeys (fetched from AgentKMS)
// instead of env vars or auth.json
for (const provider of MANAGED_PROVIDERS) {
  pi.registerProvider(provider, {
    oauth: {
      name: `${provider} (via AgentKMS)`,
      async login(_callbacks) {
        // Login is handled by session_start, not interactively
        // Return a placeholder — real key is in runtimeKeys
        return { refresh: "agentkms", access: runtimeKeys.get(provider)?.key ?? "", expires: 0 };
      },
      async refreshToken(_creds) {
        const cred = runtimeKeys.get(provider);
        return { refresh: "agentkms", access: cred?.key ?? "", expires: cred?.expiresAt ?? 0 };
      },
      getApiKey(_creds) {
        return runtimeKeys.get(provider)?.key ?? "";
      }
    }
  });
}
```

#### Custom Crypto Tools

```typescript
pi.registerTool({
  name: "crypto_sign",
  label: "Sign Payload",
  description: "Sign a payload hash using an AgentKMS-managed key. Returns only the signature.",
  parameters: Type.Object({
    key_id: Type.String({ description: "AgentKMS key identifier, e.g. payments/signing-key" }),
    payload_hash: Type.String({ description: "Hex-encoded SHA-256 hash of the payload" }),
    algorithm: StringEnum(["ES256", "RS256", "EdDSA"] as const),
  }),
  async execute(toolCallId, params, signal, _onUpdate, _ctx) {
    const token = getSessionToken();
    if (!token) throw new Error("AgentKMS session not established");

    const result = await client.sign(params.key_id, params.payload_hash, params.algorithm, token, signal);

    return {
      content: [{ type: "text", text: `Signature: ${result.signature}\nKey version: ${result.key_version}` }],
      details: { key_id: params.key_id, key_version: result.key_version },
      // Note: payload_hash is logged but NOT included in details to prevent
      // accumulation of sensitive input material in session history
    };
  },
});
```

#### `session_shutdown` — Token Revocation

```typescript
pi.on("session_shutdown", async (_event, _ctx) => {
  const token = getSessionToken();
  if (!token) return;

  try {
    await client.revokeToken(token); // POST /auth/revoke
  } catch {
    // Best-effort. Token expires naturally in 15min regardless.
  } finally {
    clearSessionToken();
    runtimeKeys.clear();
  }
});
```

#### Path Protection (defence in depth)

```typescript
pi.on("tool_call", async (event, ctx) => {
  if (event.toolName === "read" && isToolCallEventType("read", event)) {
    const credentialPaths = [".env", "auth.json", ".agentkms/", "credentials"];
    if (credentialPaths.some(p => event.input.path?.includes(p))) {
      await auditClient.log({ operation: "blocked_read", path: event.input.path, ... });
      return { block: true, reason: "AgentKMS: credential path access blocked" };
    }
  }
});
```

### 6.3 AgentKMS Skill

The skill provides the agent with explicit guidance on when and how to use crypto operations:

```markdown
<!-- skills/agentkms/SKILL.md -->
---
name: agentkms
description: Cryptographic operations via AgentKMS. Use when signing payloads, encrypting data,
  decrypting data, listing available keys, or working with authenticated LLM credentials.
  AgentKMS ensures no private key material is ever exposed.
---
# AgentKMS Skill

## When to Use
- Signing: documents, transactions, JWTs, artifact hashes
- Encryption: sensitive data that must be stored or transmitted securely
- Decryption: reading data encrypted by AgentKMS
- Key listing: discovering available key IDs for a given scope

## Rules
- NEVER attempt to read key material from files, env vars, or the backend directly
- ALWAYS use the crypto_sign / crypto_encrypt / crypto_decrypt tools
- payload_hash must be the SHA-256 hash of the actual payload, not the payload itself
- Report the returned key_version alongside every signature for verification purposes
```

### 6.4 Using Pi to Build AgentKMS

When Pi is running inside the `agentkms/` project, it uses the project `AGENTS.md` for context. Key Pi features that are particularly useful here:

**Session branching (`/tree`, `/fork`):**
Use when exploring alternative implementations of the policy engine or backend interface. Branch before a large refactor so earlier working state is preserved and navigable.

**Session compaction (`/compact`):**
Long Go implementation sessions accumulate a lot of context. Use `/compact "focus on the backend abstraction interface and policy engine"` to keep context tight and relevant.

**Thinking levels (`Shift+Tab`):**
Set to `high` or `xhigh` when working on the threat model, policy rules, or audit event schema. These are areas where subtle mistakes have serious consequences.

**`/skill:agentkms` (once built):**
The AgentKMS team uses the skill itself during development — dogfooding the crypto operations in the development workflow validates the integration continuously.

**AGENTS.md tiering:**
```
~/.pi/agent/AGENTS.md          # Global: developer identity, personal conventions
agentkms/AGENTS.md             # Project: security constraints, architecture, no-shortcuts rule
agentkms/.pi/AGENTS.md         # (optional) Sprint-specific context, current focus area
```

---

## 7. Key & Credential Lifecycle

### 7.1 LLM Provider Credentials

| Property | Value |
|---|---|
| Storage | Backend (OpenBao/KMS) — scoped LLM key, not the master key |
| Vending TTL | 60 minutes |
| Scope | Per-session-identity + per-provider |
| Revocation | Immediate (on session revoke) or natural expiry |
| Rotation | Master LLM keys rotate on schedule; vended keys are always fresh |

### 7.2 Asymmetric Signing Keys (Team/Service)

| Property | Value |
|---|---|
| Algorithm | ECDSA P-256 (ES256) by default; EdDSA and RSA2048 available |
| Versioning | Backend-managed (OpenBao/KMS); old versions retained for verification |
| Rotation | On-demand or scheduled (configurable per key) |
| Access | Team policy — explicit allow list of identities and operations |
| Audit | Every use logged with key_id + key_version |

### 7.3 Personal Developer Keys

| Property | Value |
|---|---|
| Namespace | `personal/{user-id}/*` |
| Created by | Developer via `agentkms-dev key create` or UI |
| Access | Only the individual developer's identity |
| Material | Never leaves AgentKMS backend |
| Backup | Key metadata synced to central; material stays local dev backend until promoted |
| Offline | Dev backend holds keys for offline operation (stretch goal) |

### 7.4 Session Tokens

| Property | Value |
|---|---|
| TTL | 15 minutes |
| Refresh | Proactive (< 5min remaining), transparent to user |
| Revocation | Immediate (server-side blocklist) |
| Binding | Bound to mTLS connection identity — cannot be replayed on a different connection |
| Storage | In-memory in Pi extension only — never written to disk |

---

## 8. Compliance Coverage

### 8.1 SOC 2 Type 2

| Control | How AgentKMS Satisfies It |
|---|---|
| CC6.1 — Logical Access | mTLS + short-lived tokens enforce strict identity verification on every request |
| CC6.2 — System Credentials | Zero key exposure — no credentials in env vars, config files, or agent memory |
| CC6.3 — Unnecessary Access Removed | Token revocation on session end; key access scoped to minimum required |
| CC7.2 — System Monitoring | Pluggable audit layer captures all operations; anomaly detection in Phase 2 |
| CC8.1 — Change Management | Backend abstraction — key operations versioned; migrations audited |
| A1.2 — Availability | HA Raft in Phase 2; multi-region KMS in Phase 3 |

### 8.2 PCI-DSS Level 1

| Requirement | Coverage |
|---|---|
| Req 3 — Protect stored data | Keys never stored in application layer; encrypted at rest in backend |
| Req 4 — Encrypt transmission | mTLS on all connections (TLS 1.3 minimum) |
| Req 7 — Restrict access | Policy engine enforces least-privilege per operation |
| Req 8 — Identify and authenticate | Per-session identity, mTLS cert, short-lived tokens |
| Req 10 — Track and monitor access | Audit layer; all operations logged with identity + outcome |
| Req 11.6 — Detect tampering | Audit log integrity (append-only; SIEM integration for alerting) |

### 8.3 ISO 27001

| Control | Coverage |
|---|---|
| A.9 — Access Control | Identity model + policy engine |
| A.10 — Cryptography | Backend abstraction supports FIPS 140-2 validated backends (AWS KMS, Azure Key Vault) |
| A.12.4 — Logging | Pluggable audit layer; structured, tamper-evident logs |
| A.14 — Secure Development | AGENTS.md enforces security review in development; adversarial test suite |
| A.18 — Compliance | Compliance coverage documented per framework; controls mapped and testable |

### 8.4 GDPR

| Requirement | Coverage |
|---|---|
| Data Residency | Backend selection determines key storage region; AWS KMS multi-region keys can be restricted to specific regions |
| Right to Erasure | Key deletion renders all data encrypted with that key inaccessible; documented as part of erasure workflow |
| Privacy by Design | Keys scoped to minimum necessary use; no payload data stored — only payload hashes in audit log |
| Data Processor Agreements | AgentKMS acts as a processor for LLM provider credentials; DPA-friendly by design |

### 8.5 CCPA

Covered by the same controls as GDPR for access control, data minimisation, and the right to deletion via key erasure.

### 8.6 Colorado AI Act (SB 205)

| Requirement | Coverage |
|---|---|
| AI System Transparency | Every AI-driven operation (LLM call) is traceable to an agent session identity in the audit log |
| High-Risk AI Disclosure | Audit events include enough context to reconstruct which AI model was used, when, and by whom |
| Human Oversight | Policy engine can require human approval for specific key operations (e.g., production signing keys) |
| Bias/Impact Auditing | Audit trail provides the data foundation for impact assessments |

### 8.7 SLG / FedRAMP-Ready

| Requirement | Coverage |
|---|---|
| FIPS 140-2 Validated Crypto | AWS KMS and Azure Key Vault both use FIPS-validated HSMs; backend abstraction allows targeting FIPS backends |
| FedRAMP Moderate/High Controls | Architecture is designed to support FedRAMP controls; authorisation package work needed per engagement |
| Data Sovereignty | Backend selection + regional key restrictions ensure data stays within required boundaries |

---

## 9. Audit Backend Strategy

### 9.1 Architecture

All audit writes go through the `Auditor` interface. The `MultiAuditor` fans out to N configured sinks. Adding a new sink requires implementing one interface; zero changes to business logic.

```go
type Auditor interface {
    Log(ctx context.Context, event AuditEvent) error
    Flush(ctx context.Context) error
}
```

### 9.2 Phase 1 — Local ELK

**Elasticsearch + Logstash + Kibana** self-hosted on Kubernetes.

- AgentKMS writes structured JSON audit events to Logstash (via HTTP or filebeat)
- Logstash indexes into Elasticsearch
- Kibana provides dashboards: operations by team, denied operations, anomaly timelines
- Retention: configurable (90 days default)

### 9.3 Phase 2 — Extended Sinks

| Sink | Notes |
|---|---|
| Splunk HEC | HTTP Event Collector; token-authenticated |
| Datadog Logs | API key authenticated; supports structured attributes |
| AWS CloudWatch Logs | IRSA-authenticated; native for AWS deployments |
| GCP Cloud Logging | Workload identity authenticated |
| Generic SIEM Webhook | Configurable endpoint + auth; fallback for any SIEM |

### 9.4 Audit Event Schema

```json
{
  "event_id": "01HXYZ...",
  "timestamp": "2026-04-01T14:23:01.123Z",
  "caller_id": "bert@platform-team",
  "team_id": "platform-team",
  "agent_session": "pi-session-abc123",
  "operation": "sign",
  "key_id": "payments/signing-key",
  "key_version": 3,
  "algorithm": "ES256",
  "payload_hash": "sha256:a3f4b2...",
  "outcome": "success",
  "deny_reason": null,
  "source_ip": "10.0.1.42",
  "user_agent": "agentkms-pi-extension/2.1.0",
  "compliance_tags": ["pci-dss", "soc2"],
  "environment": "production"
}
```

### 9.5 Audit Integrity

- Audit events are append-only; no update or delete operations
- Events are signed with an AgentKMS internal signing key (not accessible to callers)
- SIEM integration enables real-time alerting on anomalous patterns
- Audit log export (for compliance auditors) is authenticated and itself audited

---

## 10. Deployment Tiers

### 10.1 Tier 0 — Local Dev (`agentkms-dev`)

**Target:** Individual developer laptop, offline work, development credentials.

```
Developer machine
├── agentkms-dev server     (single binary, in-memory backend, local dev CA)
├── ~/.agentkms/
│   ├── dev/client.crt      (dev identity cert, trusted only by local server)
│   ├── dev/client.key
│   └── dev-policy.yaml     (local policy — mirrors production schema)
└── Pi extension             (connects to localhost:8200)
```

**Characteristics:**
- No Kubernetes, no Raft, no remote dependencies
- mTLS enforced using locally generated dev CA
- Same token lifecycle as production (15min TTL, refresh, revoke)
- Policy loaded from local YAML file
- Audit logs written to local file (not shipped to ELK in dev mode)
- Dev credentials cannot be used with any non-local AgentKMS instance

### 10.2 Tier 1 — Self-Hosted POC (Local Kubernetes)

**Target:** Proving the full stack, team evaluations, integration testing.

```
kind / k3s / multi-node minikube
├── OpenBao (Helm, HA Raft, 3 replicas)
│   ├── Transit secrets engine
│   └── PKI secrets engine
├── AgentKMS service (3 replicas, pod anti-affinity)
├── ELK stack (Elasticsearch + Logstash + Kibana)
└── AgentKMS PKI (CA for developer and service certs)
```

### 10.3 Tier 2 — Self-Hosted MVP (Production Kubernetes)

**Target:** Enterprise production deployment, all compliance controls active.

```
Kubernetes (3+ nodes across 3 AZs)
├── OpenBao HA Raft (3-5 replicas, AZ-spread, horizontal read scaling)
├── AgentKMS service (HPA, AZ-spread, zero-downtime deploys)
├── ELK stack (HA mode, ILM for retention)
├── AgentKMS PKI (Intermediate CA per team)
└── Monitoring: Prometheus + Grafana (latency, error rates, audit volume)
```

### 10.4 Tier 3 — Cloud Production (AWS KMS)

**Target:** Full managed infrastructure, FIPS compliance, investor-grade reliability.

```
AWS (multi-region)
├── AWS KMS (multi-region asymmetric keys, automatic multi-AZ)
├── AgentKMS service (EKS, IRSA, multi-AZ HPA)
├── CloudWatch Logs (audit sink, retention policies)
├── Route 53 + Global Accelerator (failover)
└── AWS Private CA (or continued OpenBao PKI)
```

**Migration from Tier 2:**
1. Create equivalent keys in AWS KMS
2. Enable dual-run via feature flag in AgentKMS backend config
3. New operations use AWS KMS; old data decryptable via OpenBao during transition
4. Validate fully; retire OpenBao

---

## 11. Enterprise Distribution via Pi

### 11.1 The Distribution Model

```
Enterprise Platform Team
  │
  ├─► Publishes: @org/agentkms (npm, private registry)
  ├─► Maintains: enterprise ~/.pi/agent/AGENTS.md template
  └─► Pushes:    global settings.json with agentkms package pinned
        │
        ├─► Team Leads receive pinned version in project .pi/settings.json
        │     └─► pi install -l npm:@org/agentkms@2.1.0
        │
        └─► Individual Builders get it automatically
              (project settings.json is committed to repo)
              └─► pi starts → detects missing package → installs automatically
```

### 11.2 AGENTS.md Strategy

**Global (`~/.pi/agent/AGENTS.md`):**
Generated by `agentkms enroll` and placed by the enrollment CLI. Contains:
- Developer's team identity
- AgentKMS service URL for their environment
- Key namespaces they have access to
- Enterprise-wide security conventions

**Project-level (`<project>/AGENTS.md`):**
Maintained by team lead. Contains:
- Project-specific key IDs used in this codebase
- Allowed crypto operations for this project
- Any project-specific policy exceptions (approved and documented)

**Pi Session Integration:**
Pi loads all AGENTS.md files from global → project → cwd. AgentKMS context is always present. The agent understands the security constraints without being told in every prompt.

### 11.3 Pi Package Versioning Strategy

```json
// Enterprise global settings.json
// (distributed via MDM, dotfiles repo, or enrollment CLI)
{
  "packages": [
    {
      "source": "npm:@org/agentkms@2.1.0",
      "extensions": ["extensions/index.ts"],
      "skills": ["skills/agentkms"]
    }
  ]
}
```

Pinned version: `pi update` skips pinned packages. The enterprise controls when the AgentKMS package version advances. Security updates are pushed by bumping the pinned version in the distributed settings.json.

---

## 12. Developer Experience

### 12.1 Enterprise Security Admin

**Day 1:**
1. Deploy AgentKMS service (Tier 1 → Tier 2 → Tier 3 as project matures)
2. Configure team structure and key namespaces
3. Publish `@org/agentkms` Pi package to private npm registry
4. Distribute global `settings.json` with pinned package version

**Ongoing:**
- Monitor audit dashboards in Kibana/Splunk
- Rotate master keys on schedule
- Review anomaly alerts
- Approve key namespace requests from teams
- Advance pinned package version for security updates

### 12.2 Team Lead

**Day 1:**
```bash
# Add AgentKMS to project
pi install -l npm:@org/agentkms@2.1.0

# Commit .pi/settings.json — all team members get it on next pi start
git add .pi/settings.json && git commit -m "chore: add AgentKMS Pi package"
```

**Ongoing:**
- Define team key policy (which agents can use which keys)
- Review team audit events (filtered to team scope)
- Add project-level key IDs to project AGENTS.md

### 12.3 Individual Builder

**Day 1:**
```bash
# One-time enrollment (opens SSO browser window)
agentkms enroll --team=my-team

# That's it. Pi picks up the identity automatically from ~/.agentkms/
pi
# "AgentKMS: authenticated ✓" appears in startup header
```

**Ongoing:**
- Just use Pi normally. LLM credentials and crypto operations are handled invisibly.
- For local dev: `agentkms-dev server` (in another terminal or as a background service)
- For personal keys: `agentkms-dev key create --name my-signing-key --algorithm ES256`

---

## 13. Threat Model

### 13.1 Assets

| Asset | Classification |
|---|---|
| Private key material | Critical — never leaves backend |
| LLM provider API keys | High — short-lived, scoped, revocable |
| Session tokens | High — short-lived, bound to mTLS identity |
| Developer mTLS certs | High — used to establish identity; cert compromise = identity compromise |
| Audit log integrity | High — tampering undermines compliance |
| Policy configuration | Medium — policy bypass could enable privilege escalation |
| Key metadata (IDs, versions) | Low — not sensitive on its own |

### 13.2 Threats and Mitigations

| Threat | Mitigation |
|---|---|
| **Env var compromise** | No keys in env vars at any tier. Zero key exposure by design. |
| **Agent process compromise (RCE)** | Keys never in Pi process. Attacker gets API access bounded by session policy. Session revocable immediately. |
| **Session token theft** | Token bound to mTLS connection. Replay on a different connection fails cert validation. 15min TTL limits blast radius. |
| **Developer cert compromise** | Cert revocation via OCSP/CRL. Short-TTL session tokens limit window. Incident response: revoke cert, re-enroll. |
| **AgentKMS service compromise** | Service holds no key material — compromise grants API access, not keys. Audit trail preserved. Backend-level key access requires backend credentials (separate blast radius). |
| **Backend compromise** | Backend (OpenBao/KMS) is the last line. AWS KMS uses HSMs — key material is never extractable. OpenBao: key material encrypted at rest with master seal key. |
| **Supply chain attack on Pi package** | Package is a thin client with no crypto code. Compromised package can make authenticated API calls bounded by session policy. Pinned versioning limits propagation window. |
| **Audit log tampering** | Append-only audit log. Events signed by AgentKMS internal key. SIEM integration for real-time alerting on anomalies. |
| **Insider threat** | Per-operation policy. Every operation audited with caller identity. Anomaly detection on unusual patterns. No "super admin" key access path. |
| **Policy misconfiguration** | Policy changes are audited. Policy-as-code with review process. Deny-by-default (no operation succeeds without explicit allow). |

---

## 14. API Reference

All endpoints require mTLS + valid session token (except `/auth/session` which requires mTLS only).

### Authentication

```
POST /auth/session
  Request: (mTLS cert identity used, no body)
  Response: { token: "...", expires_at: "2026-04-01T14:38:00Z", identity: { ... } }

POST /auth/refresh
  Auth: Bearer {session_token}
  Response: { token: "...", expires_at: "..." }

POST /auth/revoke
  Auth: Bearer {session_token}
  Response: 204 No Content
```

### Cryptographic Operations

```
POST /sign/{key-id}
  Auth: Bearer {session_token}
  Body: { payload_hash: "hex-encoded-sha256", algorithm: "ES256" }
  Response: { signature: "base64...", key_version: 3 }

POST /encrypt/{key-id}
  Auth: Bearer {session_token}
  Body: { plaintext: "base64-encoded-bytes", context: "optional-aad" }
  Response: { ciphertext: "base64...", key_version: 3 }

POST /decrypt/{key-id}
  Auth: Bearer {session_token}
  Body: { ciphertext: "base64...", context: "optional-aad" }
  Response: { plaintext: "base64-encoded-bytes" }
```

### Key Management

```
GET /keys
  Auth: Bearer {session_token}
  Query: scope=team (optional)
  Response: { keys: [{ id, algorithm, versions, created_at, rotated_at }] }

POST /keys/{key-id}/rotate
  Auth: Bearer {session_token}
  Response: { key_id, new_version, rotated_at }
```

### Credential Vending

```
GET /credentials/llm/{provider}
  Auth: Bearer {session_token}
  Providers: anthropic, openai, google, azure, bedrock, ...
  Response: { key: "sk-...", expires_at: "...", scope: "session:{id}" }
```

### Developer Key Management

```
POST /dev/keys
  Auth: Bearer {session_token}
  Body: { name: "my-signing-key", algorithm: "ES256", namespace: "personal/{user-id}" }
  Response: { key_id: "personal/bert/my-signing-key", ... }

GET /dev/keys
  Auth: Bearer {session_token}
  Response: { keys: [...] }
```

---

## 15. Roadmap

### Phase 1 — Local K8s POC
Core: AgentKMS service, OpenBao HA Raft, Pi package (extension + skill), mTLS, session auth, sign/encrypt/decrypt, LLM credential vending, local ELK audit, `agentkms-dev` binary.

### Phase 2 — Self-Hosted Production
Additional: Multi-AZ deployment, HPA, horizontal read scaling on OpenBao, team namespacing, personal developer keys, anomaly detection (rules-based), Splunk + Datadog audit sinks, `agentkms enroll` CLI, Pi package published to private npm, enterprise AGENTS.md distribution.

### Phase 3 — Cloud Production
Additional: AWS KMS backend, multi-region replication, IRSA, FedRAMP control mapping, FIPS path validation, central dev sync for local dev mode, Phase 1 ML-augmented anomaly detection, gRPC API option, SLA-backed availability metrics.

### Future
- Azure Key Vault backend
- GCP Cloud KMS backend
- Personal key offline support (local dev sync)
- Sub-agent identity scoping (agent spawns sub-agent with reduced key scope)
- Key ceremony tooling (for HSM-backed root keys)
- Compliance report generation (automated evidence collection for SOC 2 auditors)
