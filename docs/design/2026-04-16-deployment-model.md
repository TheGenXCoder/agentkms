# Deployment Model & Sovereignty Principle

**Date:** 2026-04-16
**Owner:** Bert Smith
**Status:** Positioning locked — no customer secrets in Catalyst9 infrastructure
**Related:** [2026-04-16-dynamic-secrets.md](2026-04-16-dynamic-secrets.md) · [architecture.md §10](../architecture.md#10-deployment-tiers)

## Sovereignty principle

**Catalyst9 does not custody customer secrets.** Ever. Under any pricing tier. Under any hosted offering.

This is the philosophical anchor the product was built around: the "life-changing devastation" from secrets leaks via agentic harnesses exists because developers trusted external stores. KPM/AgentKMS exists so they don't have to. Violating that principle in pursuit of revenue destroys the narrative and the trust that makes the product worth buying.

What we *can* offer as a paid service: **operation** of AgentKMS for teams that don't want to run it themselves — the same business model as HashiCorp Vault Enterprise. AgentKMS runs in the customer's VPC, connected to the customer's backends (their AWS account, their OpenBao, their KMS). Catalyst9 provides the binary, the updates, the support, and the paid backend adapters. Customer secrets never touch Catalyst9 infrastructure.

## Three deployment tiers

| Tier | Privileged credential lives | Developer-side trust surface | Who the customer trusts |
|---|---|---|---|
| **Laptop (`agentkms-dev`)** | Local encrypted store (AES-256-GCM, key derived via HKDF from EC private key in OS keychain) | MCP over localhost | Their disk encryption, their laptop |
| **Corp VPC (self-hosted)** | IAM role on the instance (EC2 profile, EKS IRSA, K8s service account) | MCP over mTLS to corp endpoint | Their infosec team's deployment posture |
| **Hosted by Catalyst9 (paid ops)** | Runs in customer-owned VPC via Terraform/Helm drop-in; Catalyst9 operates it | MCP over mTLS to corp endpoint | Catalyst9 for operational quality; customer retains data sovereignty |

Note: there is no tier where customer secrets live in Catalyst9-owned storage. "Hosted" means we run the software for you, in your cloud account. We don't run a multi-tenant secret store.

## Why the corp VPC tier is the strongest enterprise story

1. **No long-lived credentials anywhere.** Developer laptops have empty `~/.aws/credentials`. AgentKMS running on EKS with IRSA → STS → 15-min session. Attacker steals laptop → nothing to exfiltrate.
2. **Existing infrastructure.** Buyers already run K8s. Helm chart drops in like any other service. No new vendor infrastructure to review.
3. **Audit centralization.** One AgentKMS instance = one audit stream. Forensics queries are answerable.
4. **Policy uniformity.** One policy engine, one rule set, consistent enforcement across all developers.
5. **Compliance story.** Audit log is in the customer's environment, queryable by the customer's SIEM, exportable in whatever format their auditor wants. No cross-boundary data flow.

This is the story infosec buyers already understand because it's how Vault Enterprise is deployed. We don't have to sell a new concept — we deliver a better version of a known pattern, for the AI era.

## The laptop tier

For individual developers, OSS users, the local-dev workflow. `agentkms-dev` binary, single-file encrypted state, zero setup beyond `kpm quickstart`.

Trade-offs acknowledged:
- The admin credentials for upstream providers (AWS IAM user with `sts:AssumeRole`, Anthropic admin key, GitHub App private key) live on the laptop. Same threat surface as a developer's `.aws/credentials` today.
- **The win is not reducing that surface — it's keeping the surface out of agent processes.** The long-lived credential stays with AgentKMS; agents only see short-lived session tokens. If a compromised npm postinstall dumps the environment, it gets ciphertext and expired tokens, not the admin credential.

## The hosted operator tier (future paid offering)

"We run AgentKMS for you, in your cloud." Pricing model: per-seat or per-credential-issued + support retainer.

What Catalyst9 provides:
- Terraform/Helm modules for deployment
- Managed updates (subject to customer's change-control window)
- 24/7 on-call for the AgentKMS instance
- Paid backend adapters (AWS KMS integration, CloudHSM, on-prem HSMs, custom audit sinks)
- Compliance attestations for the software (SOC 2 Type 2 for the binary/process, not for customer data)

What Catalyst9 does NOT provide:
- A multi-tenant hosted secret store
- Any infrastructure where customer secrets live

## Implications for the OSS roadmap

The OSS core must remain fully functional at the laptop and corp-VPC tiers without any Catalyst9 cloud dependency. That means:

- No phone-home telemetry beyond opt-in crash reporting
- No license check against a Catalyst9 endpoint
- No required connection to a Catalyst9-hosted update server (updates via GitHub releases)
- No "cloud config" that routes policy or audit through Catalyst9 infra

Paid features = additional backend adapters, additional audit sinks, additional compliance tooling, additional CLI/UI. Not "the same thing but we can also see it."

## Open questions

- **Backend adapters as paid modules.** Which adapters are OSS (openbao, AWS STS, GitHub App) and which are paid (CloudHSM, PKCS#11, custom SIEM audit export)? Lean: anything that requires HSM or enterprise SIEM integration = paid; anything that targets a common open-source backend = OSS.
- **Hosted operator minimum contract size.** At what team size does the hosted offering make financial sense vs. the customer running it themselves? Needs pricing model work before we solicit pilot customers.
