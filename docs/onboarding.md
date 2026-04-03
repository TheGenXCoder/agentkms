# AgentKMS Developer Onboarding

**Target:** From zero to your first successful sign operation in under 15 minutes.  
**Audience:** Individual developers joining a team that runs AgentKMS.

---

## Prerequisites

- `agentkms-dev` binary in your PATH (`go install github.com/agentkms/agentkms/cmd/dev@latest` or download from releases)
- Go 1.21+ (for the local dev server)
- Pi coding agent installed (`npm install -g @mariozechner/pi-coding-agent`)

---

## Step 1 — Enroll (one-time, ~2 minutes)

```bash
# For LOCAL DEV (no network required):
agentkms-dev enroll

# You will see:
# ✓ Generated dev CA at ~/.agentkms/dev/ca.crt
# ✓ Generated server cert at ~/.agentkms/dev/server.crt
# ✓ Generated client cert at ~/.agentkms/dev/client.crt
# ✓ Written dev config to ~/.agentkms/dev/config.yaml
```

**What this does:** Creates a local self-signed CA, a server certificate for
the dev server, and a client certificate for your identity. These are trusted
only by the local dev server — they have no authority against staging or production.

> **Production enrollment** (your platform team will provide the server URL):
> ```bash
> agentkms enroll --team=your-team
> # Opens browser → SSO login → issues your certificate
> ```

---

## Step 2 — Start the local dev server (~30 seconds)

```bash
agentkms-dev server
```

Expected output:
```
{"level":"INFO","msg":"agentkms starting","addr":"127.0.0.1:8200","env":"dev"}
{"level":"INFO","msg":"audit sink ready","path":"/tmp/agentkms-dev-audit.log"}
{"level":"INFO","msg":"backend: DevBackend (in-memory)"}
{"level":"INFO","msg":"policy loaded","path":"~/.agentkms/dev/policy.yaml"}
{"level":"INFO","msg":"listening","addr":"127.0.0.1:8200"}
```

Leave this running in a separate terminal.

---

## Step 3 — Create a key (~10 seconds)

```bash
agentkms-dev key create --name my-signing-key --algorithm ES256
```

Expected output:
```
✓ Created key "my-signing-key" (ES256, version 1)
```

---

## Step 4 — Authenticate and sign something (~1 minute)

```bash
# 1. Get a session token (exchange your client cert for a bearer token)
TOKEN=$(curl -sf \
  --cert ~/.agentkms/dev/client.crt \
  --key  ~/.agentkms/dev/client.key \
  --cacert ~/.agentkms/dev/ca.crt \
  -X POST \
  http://127.0.0.1:8200/auth/session | jq -r .token)

echo "Session token: ${TOKEN:0:20}..."

# 2. Hash something
HASH="sha256:$(echo -n 'hello agentkms' | sha256sum | awk '{print $1}')"

# 3. Sign it
curl -sf \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"payload_hash\":\"$HASH\",\"algorithm\":\"ES256\"}" \
  http://127.0.0.1:8200/sign/my-signing-key | jq .
```

Expected output:
```json
{
  "signature": "MEUCIBgQ1xXq...",
  "key_version": 1
}
```

**That's it.** You just cryptographically signed data without ever seeing or
handling a private key.

---

## Step 5 — List your keys

```bash
curl -sf \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8200/keys | jq .
```

---

## Using Pi with AgentKMS

Once you have the `@org/agentkms` Pi package installed (your platform team
distributes this via `settings.json`), Pi authenticates automatically when
it starts:

```
AgentKMS: authenticated ✓  (session: pi-session-abc123, expires: 14:57)
```

LLM credentials are injected transparently — you do not need API keys in
environment variables or `.env` files. If Pi can't reach AgentKMS, it will
notify you and fall back to your normal credential configuration.

To use the crypto tools from a Pi session:

```
Use the crypto_sign tool to sign the hash of this document.
```

Pi will use the `crypto_sign` tool registered by the AgentKMS extension,
which calls `/sign/{key-id}` on your behalf.

---

## Troubleshooting

### "client certificate required" (401)

The dev server requires mTLS. Make sure you:
1. Ran `agentkms-dev enroll` first
2. Are passing `--cert`, `--key`, and `--cacert` to curl
3. The server is running (`agentkms-dev server`)

### "operation denied by policy" (403)

Your dev policy at `~/.agentkms/dev/policy.yaml` doesn't allow the operation.
Edit it to add an allow rule for your caller ID:

```yaml
version: 1
rules:
  - id: dev-allow-all
    effect: allow
    match:
      identity:
        caller_id_pattern: "*"
      operations: ["sign", "encrypt", "decrypt", "list_keys", "rotate_key"]
```

Then restart the dev server.

### Token expired (401 after 15 minutes)

Session tokens expire after 15 minutes. Call `POST /auth/session` again to
get a fresh token. In production, the Pi extension does this automatically.

### "credential vending not configured" (503)

The `/credentials/llm/*` endpoints require the ELK/OpenBao KV backend to be
configured. For local dev, set a placeholder key:

```bash
# Set a real (or test) Anthropic key for local dev
# This is only stored in the in-memory dev backend — not persisted
agentkms-dev key-set-llm anthropic sk-ant-your-key-here
```

---

## Architecture in one paragraph

AgentKMS sits between every caller and every cryptographic operation. Your
client certificate identifies you. AgentKMS validates it, issues a short-lived
session token (15 min), checks your policy, and then either calls the crypto
backend (OpenBao Transit for sign/encrypt/decrypt) or reads from the KV store
(for LLM credentials). You get back a signature, ciphertext, or API key.
Private key material never leaves the backend. Every operation is audited.

---

## Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/session` | POST | Get session token (mTLS) |
| `/auth/refresh` | POST | Refresh expiring token |
| `/auth/revoke` | POST | Revoke token |
| `/sign/{key-id}` | POST | Sign a payload hash |
| `/encrypt/{key-id}` | POST | Encrypt plaintext |
| `/decrypt/{key-id}` | POST | Decrypt ciphertext |
| `/keys` | GET | List key metadata |
| `/rotate/{key-id}` | POST | Rotate a key |
| `/credentials/llm/{provider}` | GET | Vend LLM credential |
| `/credentials/llm/{provider}/refresh` | POST | Refresh LLM credential |
| `/healthz` | GET | Liveness probe |
| `/readyz` | GET | Readiness probe |

Full OpenAPI spec: `docs/api/openapi.yaml`
