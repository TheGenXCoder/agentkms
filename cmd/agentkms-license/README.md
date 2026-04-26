# agentkms-license

Catalyst9 internal CLI for issuing, verifying, and inspecting AgentKMS Pro license files.

**This binary is NOT distributed in public release artifacts.** The source is public (transparency is a feature — customers can audit the verification logic), but the compiled binary is excluded from GitHub Release assets per OQ-LT-5. Customers receive only the signed `.lic` file; the signing private key and this tool are held exclusively by Catalyst9.

---

## What it does

`agentkms-license` issues Ed25519-signed license files in the two-line format consumed by the Pro rotation orchestrator plugin. The plugin verifies each license at load time against an embedded public key. Because the signing key is asymmetric, the source code is fully public without weakening the system — only Catalyst9 can produce valid signatures.

---

## Subcommands

### `keygen` — Generate a signing keypair

```sh
agentkms-license keygen \
  --private-key /tmp/license-v1-private.pem \
  --public-key  ./license-v1-public.pem \
  --key-version 1
```

Outputs:
- `--private-key`: PKCS#8 PEM, mode `0600`
- `--public-key`: SPKI PEM, mode `0644`
- SHA-256 fingerprint (16-byte prefix, colon-separated lowercase hex) printed to stdout

**After keygen:** import the private key into KPM immediately, then delete the local file:
```sh
kpm set catalyst9/license-signing-key/v1 < /tmp/license-v1-private.pem
rm /tmp/license-v1-private.pem
```

Retain `license-v1-public.pem` — its bytes are embedded in `internal/license/verify.go` before the Pro plugin binary ships.

Use `--force` to overwrite an existing key file (dangerous — invalidates all licenses signed by the old key).

---

### `issue` — Sign and produce a license file

```sh
agentkms-license issue \
  --private-key /path/to/private.pem \
  --customer    "Acme Corp" \
  --email       "admin@acme.example" \
  --expires     "2027-05-01T00:00:00Z" \
  --feature     rotation_orchestrator \
  --out         acme-corp-2026-04-26.lic
```

Repeat `--feature` for multiple features. `--expires` is RFC 3339 UTC (must end in `Z`).

Optional overrides: `--license-id <uuid>` (auto-generated UUID v4 if omitted), `--issued-at <rfc3339>` (current UTC time if omitted), `--force` (overwrite existing output file).

The manifest JSON is printed to stderr for confirmation. The license summary is printed to stdout.

---

### `verify` — Validate a license file

```sh
agentkms-license verify \
  --license    acme-corp-2026-04-26.lic \
  --public-key ./license-v1-public.pem
```

Exit codes:
- `0`: License is valid and not expired
- `1`: Invalid (bad format or bad signature)
- `2`: Signature valid but license is expired

Optional `--at <rfc3339>`: override "now" for expiry check (useful for testing near-expiry licenses).

**Always run verify before delivering a license to a customer. Do not deliver an unverified license.**

---

### `inspect` — Print manifest without verification

```sh
agentkms-license inspect --license acme-corp-2026-04-26.lic
```

Pretty-prints the manifest JSON to stdout. Always emits a verification warning to stderr. Does not require the public key. Useful for support and debugging.

Add `--raw` to print the raw base64url-encoded lines instead of decoded JSON:
```sh
agentkms-license inspect --license acme-corp-2026-04-26.lic --raw
```

---

## KPM pipe pattern (standard issuance invocation)

The private key must never exist in plaintext on disk during issuance. The canonical invocation reads the key from KPM via stdin:

```sh
kpm get catalyst9/license-signing-key/v1 | \
  agentkms-license issue \
    --private-key - \
    --license-id "$(python3 -c 'import uuid; print(uuid.uuid4())')" \
    --customer "CUSTOMER_NAME" \
    --email "CUSTOMER_EMAIL" \
    --expires "EXPIRES_AT_RFC3339" \
    --feature rotation_orchestrator \
    --out CUSTOMER_SLUG-YYYY-MM-DD.lic
```

When `--private-key -` is specified, the tool reads the full PEM block from stdin before any other processing. The private key exists only in process memory for the duration of the `issue` command, then is freed on exit. It is never written to disk by this invocation. Shell history does not contain the key value (it comes from stdin, not a flag value).

---

## File modes and public/private distinction

| File | Mode | Notes |
|------|------|-------|
| Private key PEM | `0600` | Owner-read only. Import to KPM immediately; delete local copy. |
| Public key PEM | `0644` | World-readable. Embed in Pro plugin binary. |
| License file (`.lic`) | `0644` | World-readable. Deliver to customer. Contains only the manifest and signature — no secrets. |

---

## WARNING: internal tool only

Do not include the `agentkms-license` binary in public release artifacts or GitHub Release assets. The source is OSS; the binary is not distributed. The `.gitignore` in this directory excludes the compiled binary. The CI release pipeline must be configured to omit `agentkms-license` from GitHub Release uploads.
