# AgentKMS — curl Examples

All examples assume you've run `agentkms-dev enroll` and `agentkms-dev serve`.

```bash
# Set up cert paths (adjust if your client dir name differs)
export AKMS=https://127.0.0.1:8443
export CLIENT_DIR=~/.agentkms/dev/clients/$(ls ~/.agentkms/dev/clients/ | head -1)
export CERT="--cert $CLIENT_DIR/client.crt --key $CLIENT_DIR/client.key --cacert ~/.agentkms/dev/ca.crt"
```

## Authenticate

```bash
# Get a session token (15-minute TTL)
TOKEN=$(curl -s $CERT -X POST $AKMS/auth/session | jq -r .token)
echo "Token: ${TOKEN:0:20}..."
```

## Fetch LLM Credentials

```bash
# List supported providers
curl -s $CERT -H "Authorization: Bearer $TOKEN" $AKMS/credentials/llm | jq

# Get an Anthropic API key
curl -s $CERT -H "Authorization: Bearer $TOKEN" $AKMS/credentials/llm/anthropic | jq

# Get an OpenAI API key
curl -s $CERT -H "Authorization: Bearer $TOKEN" $AKMS/credentials/llm/openai | jq
```

## Cryptographic Operations

```bash
# List available keys
curl -s $CERT -H "Authorization: Bearer $TOKEN" $AKMS/keys | jq

# Sign a payload (SHA-256 hash, base64-encoded)
HASH=$(echo -n "hello world" | shasum -a 256 | cut -d' ' -f1 | xxd -r -p | base64)
curl -s $CERT -H "Authorization: Bearer $TOKEN" \
  -X POST $AKMS/sign/my-signing-key \
  -H "Content-Type: application/json" \
  -d "{\"payload_hash\": \"$HASH\", \"algorithm\": \"ES256\"}" | jq

# Encrypt
curl -s $CERT -H "Authorization: Bearer $TOKEN" \
  -X POST $AKMS/encrypt/my-encryption-key \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "c2Vuc2l0aXZlIGRhdGE="}' | jq

# Decrypt (use ciphertext from encrypt response)
curl -s $CERT -H "Authorization: Bearer $TOKEN" \
  -X POST $AKMS/decrypt/my-encryption-key \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "<from-encrypt-response>"}' | jq
```

## Session Management

```bash
# Refresh token before it expires
curl -s $CERT -H "Authorization: Bearer $TOKEN" -X POST $AKMS/auth/refresh | jq

# Revoke token when done
curl -s $CERT -H "Authorization: Bearer $TOKEN" -X POST $AKMS/auth/revoke
```
