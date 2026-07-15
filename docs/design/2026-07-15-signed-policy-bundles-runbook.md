# Signed Policy Bundles: Runbook

**Date:** 2026-07-15
**Owner:** Bert Smith
**Status:** Operational — signing (Task 2), fail-closed verify/load (Task 3) merged.
**Related:**

- [../superpowers/plans/2026-07-15-signed-policy-bundles.md](../superpowers/plans/2026-07-15-signed-policy-bundles.md) — design plan (locked choices, task breakdown)
- [../key-rotation-runbook.md](../key-rotation-runbook.md) — cryptographic key rotation for AgentKMS-managed keys (a different key class: master LLM/encryption/audit keys, not the policy-signing key covered here)

---

## What this is

Production AgentKMS refuses to activate a policy document unless it arrives as a **signed bundle** — a JSON envelope wrapping the exact policy YAML bytes plus an Ed25519 signature over them (`internal/policy/bundle.go`, `sign.go`, `trust.go`). This closes the gap where a compromised or misconfigured GitOps/CD pipeline could push an unauthorized policy change straight to a running server. Unsigned YAML only loads when an operator explicitly opts out for local development (`AGENTKMS_POLICY_ALLOW_UNSIGNED=1`).

An example signed bundle for the canonical `docs/examples/policy-catalog-visibility.yaml` policy lives at `docs/examples/policy-catalog-visibility.bundle.json`. It was produced with a throwaway demo key (`key_id: example-demo-key`) that is not trusted by any real deployment — it exists only to show the envelope shape. Do not add its key to a production trust-keys file.

## 1. Generate a signing key

There is no `agentkms policy keygen` subcommand. Generate a raw Ed25519 seed and hex-encode it — this is the format `agentkms policy sign --key` expects (`cmd/agentkms/policy_sign.go`, `loadEd25519PrivateKey`, which accepts either a 32-byte seed or a 64-byte private key, hex-encoded on one line):

```go
// gen_policy_key.go — run once per key, offline, then delete.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	seed := priv.Seed() // 32 bytes — the format policy_sign.go expects
	if err := os.WriteFile("policy-signing-key.hex", []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		panic(err)
	}
	fmt.Println("public key (register in trust-keys.json):", hex.EncodeToString(pub))
}
```

```
go run gen_policy_key.go
```

**Never commit the private key file.** Store `policy-signing-key.hex` in a secrets manager (kpm, OpenBao, etc.) as soon as it's generated, and delete the local copy. This matches the warning already printed by `agentkms policy sign --help`.

The printed public key (64 hex chars / 32 bytes) is not secret — it goes into the trust-keys JSON file that every verifying server loads via `--policy-trust-keys` / `AGENTKMS_POLICY_TRUST_KEYS`.

## 2. Sign in CI

```
agentkms policy sign \
  --key policy-signing-key.hex \
  --key-id ci-2026-07 \
  --in docs/examples/policy-catalog-visibility.yaml \
  --out docs/examples/policy-catalog-visibility.bundle.json
```

The signature covers the exact bytes of `--in` — no YAML re-serialization happens before signing, so CI must sign the same bytes that get deployed (don't reformat or re-lint the YAML between signing and deploy).

A typical CI job pulls the private key seed from the secrets manager into an ephemeral file for the duration of the `policy sign` step only, then signs and publishes the resulting `.bundle.json` as a deploy artifact — the seed file itself never leaves the CI job's ephemeral filesystem.

## 3. Deploy / verify

The server is pointed at the bundle and a trust-keys file:

```
agentkms-server \
  --policy docs/examples/policy-catalog-visibility.bundle.json \
  --policy-trust-keys trust-keys.json \
  --policy-require-signature true   # default true when --env=production
```

`trust-keys.json` maps `key_id → hex-encoded Ed25519 public key` (`internal/policy/trust.go`, `LoadTrustStoreFromJSON`):

```json
{"ci-2026-07": "a1b2c3...64 hex chars..."}
```

Load is fail-closed end to end (`internal/policy/loader.go`): a bundle with an unknown `key_id`, invalid signature, or tampered YAML never falls through to the last-good policy or to unsigned YAML — `LoadPolicyFromPath` / `VaultPolicyLoader` return an error and the caller keeps whatever policy was already running.

## 4. Rotate a key_id

Rotation is **config-only** — no code change:

1. Generate a new key (§1) with a new `key_id`, e.g. `ci-2026-10`.
2. Add the new `key_id → pubkey` entry to `trust-keys.json` **alongside** the old one, and redeploy the trust-keys file/ConfigMap. Both keys now verify.
3. Switch CI to sign new bundles with the new key (`--key-id ci-2026-10`).
4. Once every server has redeployed with a bundle signed by the new key, remove the retired `key_id` entry from `trust-keys.json` and redeploy again. Bundles still signed under the retired `key_id` stop verifying the moment its entry is gone.

There is no revocation list beyond "present or absent from `trust-keys.json`" — removing an entry is the revocation.

## Out of scope here

- A `kpm policy verify --bundle <file>` preview command in kpm (a separate product/repo) that would let operators locally check a bundle against a pinned trust key before deploying it. Not implemented in this repo; mentioned only as a plausible future consumer of the same `Bundle` JSON shape.
- Signing anything other than policy bundles (e.g. plugin binaries) — a separate, unrelated initiative.
