# Design Decision Records

Dated design decisions and strategy docs. Each file is a self-contained decision with context, rationale, and open questions. New decisions get a new dated file rather than editing old ones — the record shows how thinking evolved.

## Index

### 2026-04-16 — v0.3 product direction

Conversation with Grok, review, strategic alignment. These four docs capture the pivot to forensics-as-the-announcement-target.

- [**Forensics as the v0.3 Product Target**](2026-04-16-forensics-v0.3.md) — why v0.3 is the announcement, what the forensics report looks like, engineering-manager vs. security-engineer lenses.
- [**Dynamic Secrets — AgentKMS as Secret-Issuing Authority**](2026-04-16-dynamic-secrets.md) — provider admin API landscape, three attribution granularities, implementation priority.
- [**Deployment Model & Sovereignty Principle**](2026-04-16-deployment-model.md) — three tiers, why Catalyst9 never custodies customer secrets, Vault Enterprise business model.
- [**Audit Schema Migration — v0.1 → v0.3 Forensics**](2026-04-16-audit-schema-migration.md) — gap analysis, Bucket A/B/C plan, migration strategy.
- [**OSS Core + Plugin Ecosystem**](2026-04-16-oss-vs-paid-surface.md) — plugin architecture (`hashicorp/go-plugin`), concrete per-feature limits, teaser placement rules, what's locked-in OSS forever.
- [**v0.3 Scope Lock**](2026-04-16-v0.3-scope-lock.md) — ring-fenced launch scope (what ships, what lands post-launch as monthly plugin releases), sharpened demo.

## Reading order for someone new

1. **architecture.md** (parent dir) — current authoritative design. Read this first.
2. **forensics-v0.3.md** — where we're headed, and why.
3. **dynamic-secrets.md** — the mechanism.
4. **deployment-model.md** — how it ships.
5. **audit-schema-migration.md** — what has to change in the data model to support it.

## How to add a new decision record

File naming: `YYYY-MM-DD-short-slug.md`. Date is the day the decision was made, not implemented.

Required sections:
- **Date, Owner, Status, Related** (frontmatter as markdown list at top)
- **Context** — what triggered this decision
- **Decision** — what we're doing (not just the options considered)
- **Open questions** — explicit list of what's unresolved

Cross-reference other decision records with relative links. Don't duplicate content — link and summarize.

If a decision is superseded, add a `**Superseded by:**` line at the top pointing at the new doc. Don't delete the old one.

## Relationship to other docs

- **`architecture.md`** — authoritative system design. Design decisions feed back into this when they're implemented and stable.
- **`backlog.md`** — work items with priorities and phases. Design decisions generate backlog items; backlog items reference the decision docs that motivated them.
- **Blog posts (`docs/blog/`)** — user-facing narrative. Design decisions inform blog content, but blogs are not design records.
