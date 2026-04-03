# Enterprise AgentKMS — Developer Context

## Your Identity
You are authenticated via AgentKMS. Your mTLS certificate identifies you.
Your LLM credentials are managed by AgentKMS — no API keys in environment variables.

## Key Namespaces You Have Access To
(Your platform team will fill this in during enrollment)

## Security Rules
- NEVER read `~/.agentkms/client.key` — it is your private key
- NEVER set `ANTHROPIC_API_KEY` or similar env vars — AgentKMS manages these
- Sign operations use `crypto_sign` tool — ALWAYS pass the SHA-256 hash, never the raw payload

## AgentKMS Service
- Dev server: http://127.0.0.1:8200 (start with `agentkms-dev server`)
- Production: https://agentkms.internal:8200 (auto-configured by enrollment)

## Useful Commands
- `agentkms-dev server` — start local dev service
- `agentkms-dev key create --name my-key --algorithm ES256` — create a key
- `/credentials/llm/anthropic` — check vended credentials status
