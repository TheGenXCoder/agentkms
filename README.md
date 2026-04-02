# AgentKMS

**Enterprise cryptographic proxy and credential vending service for agentic AI platforms.**

Private key material never leaves this service. Agents, developers, and applications receive signatures, ciphertext, and short-lived scoped credentials — never keys.

## Core Guarantee

```
Agent calls AgentKMS → receives signature
Agent calls AgentKMS → receives ciphertext
Agent calls AgentKMS → receives short-lived LLM API key (in-memory, not persisted)

Private key material: stays in the backend (OpenBao / AWS KMS / etc.)
                      always
                      no exceptions
```

## Docs

- **Architecture**: [`docs/architecture.md`](docs/architecture.md) — read this first
- **Backlog**: [`docs/backlog.md`](docs/backlog.md)
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

See [`docs/architecture.md#8-compliance-coverage`](docs/architecture.md#8-compliance-coverage).
