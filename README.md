# AgentKMS

**Enterprise cryptographic proxy and credential vending service for agentic AI platforms.**

Private key material never leaves this service. Agents, developers, and applications receive signatures, ciphertext, and short-lived scoped credentials — never keys.

## Core Guarantee

```text
Agent calls AgentKMS → receives signature
Agent calls AgentKMS → receives ciphertext
Agent calls AgentKMS → receives short-lived LLM API key (in-memory, not persisted)

Private key material: stays in the backend (OpenBao / AWS KMS / etc.)
                      always
                      no exceptions
```

## Features (T1 - T3 Complete)

- **Cloud-Native Backends**: Full integration with OpenBao / HashiCorp Vault Transit engine with Zero-Downtime Dual-Run migration support.
- **Enterprise Audit Logging**: Streaming NDJSON exports, Splunk HEC, Datadog, ELK, and Generic SIEM Webhook integration with cryptographic HMAC-SHA256 signature verification.
- **Agentic Identity & Orchestration**: Sub-Agent Identity Scoping via `POST /auth/delegate` (minting short-lived, permission-restricted Macaroons for sub-agents).
- **High-Performance APIs**: Parallel REST and gRPC endpoints for zero-latency cryptographic operations at swarm-scale.
- **Automated Security Operations**: ML-augmented statistical anomaly detection (flagging token velocity spikes and unusual access patterns), automated SOC 2 HTML compliance reports, and an embedded Enterprise Admin Web UI.
- **Pi Integration**: A lightweight TypeScript extension (`@org/agentkms`) that enforces credential path protection, seamless provider model switching, and real-time connection visibility via `/agentkms-status`.

## Docs

- **Architecture**: [`docs/architecture.md`](docs/architecture.md) — read this first
- **Backlog**: [`docs/backlog.md`](docs/backlog.md)
- **Compliance & Runbooks**: [`docs/compliance-controls.md`](docs/compliance-controls.md), [`docs/security-runbook.md`](docs/security-runbook.md), [`docs/rotation-runbook.md`](docs/rotation-runbook.md)
- **Pi context**: [`AGENTS.md`](AGENTS.md) — constraints for Pi agent sessions on this project

## Quick Start (Local Dev)

```bash
# Start local dev service (in-memory backend, local dev CA)
go run ./cmd/dev server

# Enroll as a developer (generates ~/.agentkms/dev/ certs)
go run ./cmd/enroll

# Install Pi package (routes Pi LLM calls through AgentKMS)
pi install npm:@org/agentkms
```

## Language

**Go** — service, CLI, all crypto logic.
**TypeScript** — Pi extension client only (thin HTTP client, zero crypto).

## Compliance

SOC 2 Type 2 · PCI-DSS · ISO 27001 · GDPR · CCPA · Colorado AI Act · SLG/FedRAMP-Ready

See [`docs/compliance-controls.md`](docs/compliance-controls.md) for testable evidence.
