# Security Policy

## Reporting a Vulnerability

**Do not file security vulnerabilities as public GitHub issues.**

Email security reports to: `security@catalyst9.ai`

Include:
- A description of the vulnerability
- Steps to reproduce (a minimal example, if possible)
- The version or commit hash where you observed the issue
- Your assessment of impact and affected components

You should receive an acknowledgment within 72 hours. Coordinated disclosure is appreciated.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | Security fixes only |
| < 0.1.0 | No        |

## Security Model

AgentKMS is the server that backs the [KPM](https://github.com/TheGenXCoder/kpm) client. It handles authentication, policy evaluation, credential vending, audit logging, and key storage.

### Defenses

**Mutual TLS on every request**
No bearer tokens for initial authentication. Clients must present a certificate signed by AgentKMS's trust root. Server identity is validated by the client.

**Policy engine evaluates every operation**
Deny-by-default. Policy rules match on caller identity (from the cert), team, role, machine, operation type, and target path. Rules apply in order with first-match-wins semantics.

**Audit logging cannot be bypassed**
Every operation — successful, denied, or errored — produces an audit event. Events are written via `context.WithoutCancel(ctx)` so they survive client disconnection. Audit events never contain secret values; they store SHA-256 hashes of payloads when correlation is needed.

**Secrets and metadata are stored separately**
The registry uses two distinct KV paths: `kv/secrets/{path}` for values and `kv/metadata/{path}` for metadata. List and describe endpoints query the metadata store only. They physically cannot return values.

**Versioning is immutable**
Every secret write creates a new version. Previous versions are preserved (default: last 10 retained). Soft-delete marks metadata as deleted but retains values for audit. Hard-delete (`?purge=true`) requires a separate policy operation.

**Rate limiting**
Configurable interval between credential vends from the same caller for the same path. Default 60 seconds in production, disableable in dev (`--rate-limit 0`).

**Encrypted at-rest storage (dev mode)**
The `agentkms-dev` server encrypts its on-disk secret store with AES-256-GCM. The key is derived from the server's EC private key via HKDF-SHA256. The encrypted file has 0600 permissions. Writes are atomic (temp file + rename). See `internal/credentials/encrypted_kv.go`.

**Adversarial tests**
The test suite includes fuzz tests that add known-plaintext secrets and verify the plaintext never appears in the output of list/describe/history endpoints.

### Not defended against

**Compromise of the server's private key**
If an attacker obtains the server's EC private key, they can decrypt the dev store. Hardware key storage (Secure Enclave, PKCS#11) is supported for production.

**Compromise of the CA**
If the CA that signs client certificates is compromised, an attacker can forge client identities. Protect the CA accordingly — offline in a cold store, or in a hardware HSM.

**Malicious CA-signed client certs**
Anyone with a valid client cert can authenticate. Policy restricts what they can do. The combination of cert issuance controls (who gets a cert) and policy (what a cert can do) is the defense. Both must be configured properly.

**Timing and other side channels**
The implementation uses the Go standard library where possible, which provides constant-time operations for sensitive comparisons. Explicit timing hardening beyond that is not implemented.

**Backend compromise**
If the Vault/OpenBao backend is compromised, all secrets are compromised. Backend security is outside AgentKMS's scope; it's the backend's responsibility.

## Cryptographic Primitives

| Primitive | Use | Library |
|-----------|-----|---------|
| AES-256-GCM | At-rest encryption (dev mode), transit encryption (TLS 1.3) | `crypto/aes`, `crypto/cipher` (stdlib), `crypto/tls` (stdlib) |
| HKDF-SHA256 | Key derivation from server private key | `golang.org/x/crypto/hkdf` |
| ECDSA P-256 | Server identity, CA signing | `crypto/ecdsa` (stdlib) |
| TLS 1.3 | All transport | `crypto/tls` (stdlib) — min version enforced |
| HMAC-SHA256 | Session token signing | `crypto/hmac` (stdlib) |
| WebAuthn / FIDO2 | Optional second factor | `github.com/go-webauthn/webauthn` |

All primitives use the Go standard library where available.

## Testing

Security-critical coverage (as of v0.2.0):

- `internal/api/` — 84.1% (134 tests, includes adversarial fuzz)
- `internal/audit/` — 85.6%
- `internal/auth/` — 82.1%
- `internal/credentials/` — 77.8% (95%+ on encrypted KV store, including bit-flip, wrong-key, and truncation tests)
- `internal/policy/` — 86.1%
- `pkg/tlsutil/` — 84.9%

Run:

```bash
go test ./... -count=1 -cover
```

## Disclosed Vulnerabilities

None yet. This list will be updated if/when vulnerabilities are disclosed.

---

**Last updated:** 2026-04-15 (v0.2.0 release)
