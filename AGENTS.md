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

## Dependency Policy

**Foundation layer (credentials, crypto, audit, policy engine) stays zero-dep.** Only the Go standard library.

**Infrastructure layers** (plugin host, observability, webhooks, external integrations) may adopt battle-tested deps when necessary. Each addition requires:
1. Justification commit message citing what was evaluated and why this dep specifically.
2. An entry below.

### Build-time dependencies (not in go.mod / not runtime)

These tools are required to regenerate code from `.proto` files. They are **not**
runtime dependencies and do not appear in `go.mod`. Install them once per dev machine.

- `protoc` — protobuf compiler. Install: `brew install protobuf`
  Required by: multi-language plugin support (Go, Python, Rust plugins must share
  the same wire format). Using standard protobuf binary encoding instead of a
  custom JSON codec is the only way to make Python plugins work "with zero changes
  on the Python side" (Blog Part 7 promise).

- `protoc-gen-go` — Go protobuf code generator.
  Install: `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`

- `protoc-gen-go-grpc` — Go gRPC service stub generator.
  Install: `go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest`

To regenerate stubs after changing `api/plugin/v1/plugin.proto`:

```bash
protoc \
  -I /opt/homebrew/Cellar/protobuf/34.1/include \
  -I api/plugin/v1 \
  --go_out=api/plugin/v1 \
  --go_opt=paths=source_relative \
  --go-grpc_out=api/plugin/v1 \
  --go-grpc_opt=paths=source_relative \
  api/plugin/v1/plugin.proto
```

Commit `plugin.pb.go` and `plugin_grpc.pb.go` — they are generated artifacts that
belong in the repo so consumers do not need protoc to use the package.

**Historical note:** `api/plugin/v1/plugin.go` previously contained a hand-written
`jsonCodec` that overrode gRPC's default "proto" codec with JSON encoding to avoid
the protoc build-time dep. That codec was removed in the commit that added this
entry because it broke Python interop — Python plugins produced by `grpc_tools.protoc`
use standard protobuf binary, not JSON. The custom codec made the "zero Python-side
changes" promise false. Standard protoc stubs are the correct solution.

### Approved runtime deps

- `github.com/hashicorp/go-plugin` — P-01, plugin subprocess host. Adopted v1.6.2 in v0.3.1.
  Saves ~2 weeks of reimplementing subprocess lifecycle, address negotiation, magic cookie
  handshake, and health checking. Used by Terraform, Vault, Packer. The Python reference
  plugin already speaks this protocol. Alternatives evaluated: raw gRPC (no handshake
  protocol), net/rpc (deprecated path, no gRPC). go-plugin was the only choice that made
  the Python plugin immediately connectable without Python-side changes.

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
bash scripts/quality_check.sh
```

This project wraps the global quality gate skill (`~/.pi/agent/skills/quality-gate`). For configuration options, run `/skill:quality-gate`.

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
