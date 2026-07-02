# UX Consolidation — One Path In, CA Transparency, Local-First Reads

**Date:** 2026-07-01
**Owner:** Bert Smith
**Status:** Implemented (2026-07-01) — agentkms `cmd/agentkms` + kpm `kpm login <invitecode>`
**Related:** [2026-04-16-deployment-model.md](2026-04-16-deployment-model.md) · [KPM README — Authentication & Enrollment](https://github.com/TheGenXCoder/kpm#authentication--enrollment)

## Context

P0 (Windows platform) and the UTA adapter integration (P1) proved the machinery works. What they also proved is that the **operator UX does not**. Evidence from a single power-user machine after ~2 months of daily use:

- `~/.kpm/` contains **5 config YAMLs + 3 timestamped backups** and two cert directories (`certs/`, `certs-odev/`).
- The "default" config's first 25 lines are comments explaining how server selection works.
- There are **4 ways to select a remote**: `config.yaml` default, `KPM_CONFIG=` env var, `--config` flag, `KPM_DEV=1` / `--dev`.
- There are **4 ways to get enrolled**: `kpm quickstart`, `kpm enroll <bootstrap-token>`, legacy `kpm enroll <url> --invite <token>`, and manual cert copying from the cluster.
- AgentKMS ships **3 binaries** (`agentkms-dev`, `cmd/server`, `cmd/enroll`) with different bootstrap stories.
- CA material is fully user-visible: `cert:`/`key:`/`ca:` paths in every config; a hostname-only server cert caused a multi-hour DNS/SAN debugging session (2026-06-30) that ended with a "do NOT add the IP" warning comment living permanently in a user config file.

The features are not the problem — enrollment, device identity, revocation, WebAuthn, fallback mirroring all exist. The problem is **too many overlapping entry points**. Adoption test: if the author struggles to log in and switch remotes, other developers will not use the product.

## Decision

Six decisions, ordered by dependency. D1/D2 are agentkms work; D3–D5 are kpm work downstream of D1; D6 is a scope cut.

### D1 — One AgentKMS binary, two modes: `agentkms init --dev | --prod`

Collapse `agentkms-dev`, `cmd/server`, and `cmd/enroll` into a single `agentkms` binary.

- **`agentkms init --dev`** — loopback-only (`127.0.0.1`), encrypted file store, PKI bootstrapped silently. **Dev mode must not accept remote connections** — this is a hard property, not a default.
- **`agentkms init --prod --host <fqdn>`** — binds the hostname, generates CA + server cert for that FQDN, and finishes by printing the **CA fingerprint and a first admin invite code**. That final output is what makes D3 possible.
- `agentkms invite <user>` mints subsequent invite codes (absorbs today's `kpm admin inviteuser` server-side flow).
- Distribution via package managers: brew tap, winget, AUR, plus the existing curl/PowerShell installers. Packaging work only — no architecture change.

Existing Helm/K8s deployment (corp VPC tier) is unchanged; `init --prod` is the bare-metal/VM path (e.g. Windows sandbox, odev).

### D2 — Keep the user/device account model; expose exactly one enrollment path

Device certs, bootstrap tokens, per-device revocation, and WebAuthn step-up all stay. What changes: **`kpm login <invitecode>` becomes the only documented enrollment path.** `kpm quickstart` remains for local dev only (pairs with `init --dev`). The legacy `kpm enroll <url> --invite <token>` path and manual cert copying are deprecated and removed after one release of warnings.

### D3 — `kpm login <invitecode>`: server URL and CA fingerprint travel inside the code

The invite code is a self-contained blob (base64url; format draft below) encoding:

| Field | Purpose |
|---|---|
| `server_url` | No separate `<serverpath>` argument to mistype |
| `ca_fingerprint` (SHA-256) | Client fetches the CA over TLS and verifies against this pin — no TOFU ambiguity, no cert files handed around |
| `token` | One-time bootstrap token (existing mechanism) |
| `expires_at` | Short validity window (default 24h) |

`kpm login <invitecode>` then does, in one step: fetch + pin CA → generate keypair locally → CSR (SPIFFE identity, existing flow) → receive device cert → write the single config file with this server as the default remote. Private keys never leave the machine (unchanged invariant).

**CA transparency principle:** after login, the user never sees a `.crt` path. Certs live under `~/.kpm/identity/<server>/` managed entirely by kpm. `cert:`/`key:`/`ca:` keys disappear from user-visible config.

### D4 — One config file, one default remote, `--dev` as the only escape hatch

`~/.kpm/config.yaml` is the only config file, written by `kpm login` (or `kpm quickstart` for dev). It contains the default remote and preferences — no cert paths, no server-selection commentary. Deprecated: `KPM_CONFIG=` multi-config workflow, `config-<name>.yaml` sprawl, hand-copying configs to switch remotes. `--dev` / `KPM_DEV=1` remains as the explicit "local store only, never touch hosted" override. Named multi-remote support is **deferred** (open question below) — most developers have one remote plus local dev.

### D5 — Local-first reads: pull-through cache with TTL + explicit `kpm sync`

Formalize the existing `fallback:` + `mirror_to_fallback: true` mechanism into a first-class read path:

1. `kpm get` checks the local encrypted store first.
2. On miss (or TTL expiry), pull from the default remote and cache.
3. `kpm sync` forces a full re-sync on demand.
4. Writes (`kpm add`) go to the remote and mirror locally (today's behavior, kept).

Constraints:

- Cache is encrypted at rest with the same key-derivation posture as the dev store (HKDF from OS-keychain-held key).
- **`--strict` bypasses the cache entirely** — strict mode's contract is "no key material on the client", and caching would silently break it.
- Default TTL: 15 minutes (tunable). Rotation is rare and operator-initiated; TTL staleness bounded at minutes is acceptable.

### D6 — No near-real-time push subscription (deferred, not designed)

Server-push value updates were considered and **rejected for now**: persistent connections, subscription state, reconnect logic, and per-client delivery guarantees are real distributed-systems surface, purchased to solve a problem we do not have. TTL + `kpm sync` covers rotation propagation; `--strict` covers instant-revocation needs. Revisit only if TTL staleness produces a concrete incident.

## Golden paths (the whole mental model after this lands)

```bash
# Server operator, once
agentkms init --prod --host agentkms.example.com    # prints CA fingerprint + first invite code
agentkms invite alice                               # more invites later

# Every developer, once per machine
kpm login <invitecode>

# Daily — zero server/config/cert awareness
kpm add service/name
kpm get service/name        # local cache first, remote on miss
kpm run -- <cmd>

# Local-only, no server
kpm --dev ...               # or: agentkms init --dev, then same commands
```

## Deprecations

| Deprecated | Replaced by |
|---|---|
| `agentkms-dev`, `cmd/enroll` as separate binaries | `agentkms init --dev` / `--prod` |
| `kpm enroll <url> --invite <token>` (legacy) | `kpm login <invitecode>` |
| Manual cert copying between machines | CA pin inside invite code |
| `KPM_CONFIG=` + `config-<name>.yaml` sprawl | Single `~/.kpm/config.yaml` written by login |
| `cert:`/`key:`/`ca:` in user-visible config | `~/.kpm/identity/<server>/` (kpm-managed) |
| Ad-hoc `fallback:`/`mirror_to_fallback:` config | First-class cache semantics (D5) |

## Sequencing

1. **agentkms**: D1 (`init`/`invite`, richer invite codes) — everything else is downstream.
2. **kpm**: D3 + D4 (`login`, single config, identity dir) — requires D1's invite format.
3. **kpm**: D5 (cache formalization) — independent of D3, can proceed in parallel after D1.
4. Deprecation warnings one release, removal the next.

**UTA adapter impact: none blocking.** `AgentKmsSecretClient` speaks the server API directly and is unaffected. UTAv2 sandbox scripts (`kpm-run-sandbox.sh`, `winrm-exec.py` wrappers) get simpler once `KPM_CONFIG=` juggling disappears, but P1 validation does not wait for this work.

## Invite code format (draft — finalize during D1 implementation)

```
kpmi1_<base64url(cbor{v:1, url, ca_fp, token, exp})>
```

Prefix + version for forward compatibility; CBOR (or bare JSON) payload; short enough to paste in chat. Exact envelope decided at implementation time — the contract is the field set, not the encoding.

## Open questions

- **Named multi-remote support** — deferred. Does anyone besides the author need >1 hosted remote per machine? If yes, `kpm remote add/use` later; design must not preclude it (identity dir is already keyed by server).
- **Dev → prod migration** — is there a story for promoting an `init --dev` store's secrets to a prod server (`kpm import` may already cover it)?
- **Windows cache key custody** — DPAPI vs. Credential Manager for the local cache encryption key on Windows (macOS/Linux use keychain/keyring).
- **Invite expiry default** — 24h proposed; confirm against real onboarding latency (e.g. inviting a contractor across time zones).
- **Existing-user migration** — one-shot `kpm migrate` that collapses current multi-config setups into the new single-config layout, or documented manual steps?
