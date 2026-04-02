# AgentKMS — Pi Agent Context

## What This Project Is
AgentKMS is a hardened enterprise cryptographic proxy service. It sits between every agent, developer, and application that needs key material and the backend that holds it. Private keys **never** leave AgentKMS. Callers receive only signatures, ciphertext, or short-lived scoped credentials — never raw key material.

This is a **security-critical production service**. There are no exceptions, no dev shortcuts, and no carve-outs. If a shortcut is tempting, that is exactly where an attacker will look.

## Primary Language
**Go** for the service binary, CLI tooling, and all cryptographic code. TypeScript only for the Pi extension client package (thin client, no crypto). If there is a compelling reason to deviate from Go, discuss it explicitly before writing code.

## Absolute Constraints — Read Before Writing Any Code
- **Zero key exposure**: No key material in logs, env vars, responses, memory dumps, stack traces, or tool call outputs. Ever.
- **mTLS everywhere**: All service-to-service and client-to-service traffic uses mutual TLS. No plaintext, no self-signed-without-PKI.
- **Short TTLs**: Session tokens max 15 minutes. LLM credentials max 60 minutes. Crypto keys versioned with rotation built-in.
- **Audit everything**: Every crypto operation, every credential issuance, every auth event is logged with: caller identity, operation, key-id, payload hash (not payload), timestamp, outcome. No silent failures.
- **Backend abstraction**: All crypto operations go through the `Backend` interface. Never call OpenBao, Vault, or AWS KMS SDK directly from API handlers.
- **Pluggable audit**: All audit writes go through the `Auditor` interface. Never write to a specific sink directly from business logic.
- **No supply chain surprises**: Minimise external Go dependencies. Every dependency needs a documented reason. Use `go mod verify` and pin hashes.

## Compliance Requirements (all must be satisfiable, not all activated at once)
- SOC 2 Type 2
- PCI-DSS Level 1
- ISO 27001
- GDPR (data residency controls required)
- CCPA
- Colorado AI Act (AI transparency, audit trails for AI-driven decisions)
- SLG / FedRAMP-Ready (FIPS 140-2 crypto paths must be available)

## Architecture Docs
- Full architecture: `docs/architecture.md` — read this before making structural decisions
- Backlog: `docs/backlog.md`

## Project Structure (target)
```
agentkms/
├── cmd/server/          # Main service entrypoint
├── cmd/dev/             # Local dev server (single binary, in-memory backend)
├── cmd/enroll/          # Developer enrollment CLI
├── internal/
│   ├── api/             # HTTP handlers (REST + gRPC future)
│   ├── auth/            # mTLS validation, token issuance/revocation
│   ├── policy/          # Per-agent, per-team, per-scope policy engine
│   ├── audit/           # Pluggable audit (ELK, Splunk, CloudWatch, Datadog)
│   ├── backend/         # Crypto backend abstraction (OpenBao, Vault, AWS KMS, GCP KMS)
│   └── credentials/     # LLM provider credential vending
├── pkg/
│   ├── identity/        # Identity model (enterprise/team/builder/agent)
│   └── tlsutil/         # mTLS helpers, cert validation
├── pi-package/          # TypeScript Pi extension + skill (thin client)
│   ├── extensions/
│   ├── skills/
│   └── package.json
└── docs/
```

## Testing Standards
- Every exported function has a test.
- Security-critical paths (auth, crypto dispatch, policy evaluation, audit) have adversarial test cases — not just happy paths.
- No `t.Skip()` without a linked issue and expiry date.
- Integration tests use a local `agentkms-dev` instance, not mocks of the crypto backend.

## Validation Rule — Independent Review Required
**Never validate your own work.** After completing any task, an independent Pi session running a different model must review the implementation before the backlog item is marked `[x]`. Self-review has the same blind spots as the code that produced the bug.

The review has **two components**. Both must pass.

### Component 1 — Adversarial Security Review

Workflow:
1. Complete implementation, run tests locally (`go test -race ./...`).
2. Run `/coord review` — it prints a complete adversarial + quality brief.
3. Open a **new Pi session** (`/new` or fresh terminal) with no prior context.
4. Paste the brief. Let the independent session review and report findings.
5. Address all findings. Only then mark the backlog item `[x]`.

This applies to: all security-critical items (all A-*, C-*, P-* items), all D-* items (the dev server is the thing all other streams depend on), and any change that touches auth, policy, audit, or backend.

### Component 2 — Code Quality Gate

Run before every commit. All checks must pass:

```bash
# 1. Tests + race detector (mandatory — no exceptions)
go test -race -count=1 ./...

# 2. Coverage threshold (minimum 80% per package with tests)
go test -race -count=1 -coverprofile=cover.out ./...
go tool cover -func=cover.out | awk 'END { if ($3+0 < 80.0) exit 1 }'

# 3. Every exported function must have at least one test
#    Run the quality script:
bash scripts/quality_check.sh

# 4. t.Skip audit — every skip must have a linked issue and expiry comment
grep -rn 't\.Skip\|t\.Skipf' . --include='*.go' | grep -v '_test.go:.*TODO(#'
# ^^^ must produce no output

# 5. vet
go vet ./...
```

**Coverage thresholds by package type:**
- `internal/auth`, `internal/policy`, `internal/audit` — ≥ 85%
- `internal/api`, `internal/backend` (non-integration) — ≥ 80%
- `pkg/` packages — ≥ 80%
- Integration-only code (build tag `integration`) — exempt from non-integration coverage

**t.Skip rule:** Any `t.Skip` or `t.Skipf` must have a comment on the preceding line in the format:
```go
// TODO(#<issue-number>): skip until <YYYY-MM-DD> — <reason>
t.Skipf("...")
```

**Exported function test rule:** Every exported function in `internal/` and `pkg/` must be called by at least one test. The quality script checks this automatically.
