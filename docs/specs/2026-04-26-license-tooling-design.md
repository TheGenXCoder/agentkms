# AgentKMS Pro License Issuance Tooling — Design Document

**Date:** 2026-04-26
**Status:** Design pass — awaiting coordinator review before implementation
**Related:**
- `docs/specs/2026-04-26-T5-orchestrator-design.md` — §2 defines the license file format and verification model that this tooling must produce
- `internal/license/verify.go` — future home of the embedded public key and verification logic (inside the Pro plugin binary)

---

## 1. Overview

T5's Pro rotation orchestrator validates a license file at plugin load time using an embedded Ed25519 public key (T5 §2.2). That file must be produced by Catalyst9-internal tooling — `cmd/agentkms-license/` — before any Pro plugin binary ships. This document designs that tooling: CLI surface, exact file format, key operational handling, and the runbook for issuing licenses.

The tool is never distributed to customers. Customers receive only the signed license file; the signing private key and this CLI are held exclusively by Catalyst9 (Bert).

---

## 2. CLI Surface

### 2.1 Binary and Subcommand Structure

`agentkms-license` is a standalone Go binary at `cmd/agentkms-license/main.go`. It is not a subcommand of `agentkms` or `kpm`. It has four subcommands:

```
agentkms-license keygen   Generate an Ed25519 keypair
agentkms-license issue    Sign and produce a license file
agentkms-license verify   Validate a license file against a public key
agentkms-license inspect  Print manifest JSON from a license file (no verification)
```

Global flags (available to all subcommands):

```
--json    Output machine-readable JSON instead of human-readable text
```

---

### 2.2 `keygen` — Generate Signing Keypair

**Purpose:** Generate the Ed25519 keypair whose public half gets embedded in the Pro plugin binary and whose private half gets stored in KPM.

**Flags:**

```
--private-key   string   Path for the PEM-encoded private key output (required)
--public-key    string   Path for the PEM-encoded public key output (required)
--key-version   int      Integer label for this key epoch; used only in the console
                         output fingerprint label (default: 1)
--force                  Overwrite existing output files (default: false; refuses
                         to overwrite without this flag)
```

**Behavior:**

1. If either output path already exists and `--force` is not set, exit 1 with:
   ```
   error: output file already exists: <path>
   Use --force to overwrite. Overwriting a key in use will invalidate all licenses signed with it.
   ```
2. Generate an Ed25519 keypair using `crypto/ed25519.GenerateKey(crypto/rand.Reader)`.
3. Write private key to `--private-key` path as a PEM block with type `ED25519 PRIVATE KEY`, mode `0600`.
4. Write public key to `--public-key` path as a PEM block with type `ED25519 PUBLIC KEY`, mode `0644`.
5. Print to stdout:
   ```
   Key version:    1
   Private key:    /path/to/private.pem  (mode 0600)
   Public key:     /path/to/public.pem   (mode 0644)
   Fingerprint:    SHA256:<base64(sha256(public_key_bytes))>

   NEXT STEPS:
   1. Store the private key in KPM:
      kpm set catalyst9/license-signing-key/v1 < /path/to/private.pem
   2. Delete the local private key file:
      rm /path/to/private.pem
   3. Embed the public key bytes in internal/license/verify.go before the Pro plugin release.
   ```

**Exit codes:** 0 = success, 1 = error (message printed to stderr).

**Stdin/stdout:** No stdin. Stdout is the summary above. Stderr is errors.

---

### 2.3 `issue` — Sign a License

**Purpose:** Produce a signed license file in the two-line format consumed by the Pro plugin (T5 §2.1).

**Flags:**

```
--customer      string   Customer display name (required)
--email         string   Customer email address (required)
--expires       string   Expiration in RFC 3339 UTC, e.g. "2026-08-01T00:00:00Z" (required)
--features      string   Comma-separated list of feature strings, e.g.
                         "rotation_orchestrator" (required; may be repeated)
--private-key   string   Path to PEM private key, OR "-" to read from stdin (required)
--out           string   Output license file path (required; must not exist unless
                         --force is set)
--license-id    string   Override UUID v4 for the license_id field (default: auto-generated)
--issued-at     string   Override issued_at in RFC 3339 UTC (default: current UTC time)
--force                  Overwrite existing output file
```

**Behavior:**

1. If `--private-key` is `-`, read the PEM block from stdin. Otherwise read from the specified path.
2. Auto-generate `license_id` as UUID v4 if not provided.
3. Set `issued_at` to `time.Now().UTC()` formatted as RFC 3339 if not provided.
4. Parse `--expires` as RFC 3339. If the resulting time is before `issued_at`, exit 1:
   ```
   error: --expires must be after --issued-at (got expires=<value>, issued_at=<value>)
   ```
5. Build and serialize the manifest JSON (§3.1 below).
6. Sign the manifest bytes with the Ed25519 private key.
7. Write the two-line license file (§3.2 below) to `--out`.
8. Print to stdout:
   ```
   License issued successfully.
   File:        /path/to/license.lic
   License ID:  <uuid>
   Customer:    <name> <email>
   Issued:      <issued_at>
   Expires:     <expires_at>
   Features:    rotation_orchestrator
   ```

**Exit codes:** 0 = success, 1 = error.

**Stdin behavior:** If `--private-key -` is used, the entire PEM block is read from stdin before any other processing. The tool must not prompt; it reads until EOF.

**Typical invocation (reading private key from KPM — see §4):**

```sh
kpm get catalyst9/license-signing-key/v1 | \
  agentkms-license issue \
    --private-key - \
    --customer "Acme Corp" \
    --email "admin@acme.example" \
    --expires "2027-05-01T00:00:00Z" \
    --features "rotation_orchestrator" \
    --out acme-corp.lic
```

---

### 2.4 `verify` — Validate a License File

**Purpose:** Confirm a license file parses correctly, the signature is valid against a known public key, and the license is not expired. Used before delivering a license to a customer and as a smoke test in CI.

**Flags:**

```
--license       string   Path to the license file to verify (required)
--public-key    string   Path to the PEM public key to verify against (required)
--at            string   Override "now" for expiry check in RFC 3339 UTC (optional;
                         useful for testing near-expiry licenses)
```

**Behavior:**

1. Read and parse the two-line format. If malformed, exit 1:
   ```
   error: invalid license format: expected exactly 2 non-empty lines, got <N>
   ```
2. base64url-decode both lines.
3. Verify the Ed25519 signature of the manifest bytes using the public key. On failure, exit 1:
   ```
   error: signature verification failed
   ```
4. Unmarshal the manifest JSON. On failure, exit 1:
   ```
   error: manifest JSON is not valid: <detail>
   ```
5. Check `schema_version == 1`. On mismatch, exit 1:
   ```
   error: unsupported schema_version: <value> (expected 1)
   ```
6. Check `expires_at > now` (or `--at` if provided). If expired, exit 2:
   ```
   error: license expired at <expires_at> (now: <now>)
   ```
   Exit code 2 (distinct from 1) lets scripts distinguish "invalid" from "expired."
7. On success, print:
   ```
   OK  license_id=<uuid>  customer=<name>  expires=<date>  features=[...]
   ```

**Exit codes:** 0 = valid and not expired, 1 = invalid (bad format or bad signature), 2 = signature valid but expired.

---

### 2.5 `inspect` — Print Manifest Without Verification

**Purpose:** View the manifest fields of any license file without needing the public key. Useful for support and for debugging malformed licenses.

**Flags:**

```
--license   string   Path to the license file (required)
--raw                Print the raw base64url-encoded lines instead of decoded JSON
```

**Behavior:**

1. Read the two-line format. If malformed, exit 1.
2. base64url-decode line 1 (the manifest).
3. Print the manifest as pretty-printed JSON to stdout.
4. If `--raw`, print the two raw base64url lines instead, labeled:
   ```
   manifest:  <base64url>
   signature: <base64url>
   ```
5. **Never prints the signature bytes as anything other than base64url.** This is not a security boundary (the file contains the signature in plaintext), but it makes accidental misuse less likely.

**Note:** No verification is performed. The output explicitly includes a warning line:

```
WARNING: signature not verified — use 'agentkms-license verify' to confirm authenticity
```

**Exit codes:** 0 = parsed successfully, 1 = parse error.

---

## 3. File Format — Exact Specification

This section is normative for both the issuing tooling and the orchestrator plugin's `internal/license/verify.go`. Any discrepancy between this document and a future implementation is a bug in the implementation.

### 3.1 Manifest JSON

The manifest is a JSON object serialized with the following constraints:

- **Field order** (canonical): `license_id`, `customer`, `email`, `issued_at`, `expires_at`, `features`, `schema_version`
- **Encoding:** UTF-8, no BOM
- **Whitespace:** No indentation, no trailing spaces, no trailing newline within the JSON
- **Timestamp format:** RFC 3339 UTC, always ending in `Z`, e.g. `"2026-05-01T00:00:00Z"`
- **`features` array:** JSON array of strings; at least one element required; strings are lowercase ASCII with underscores, e.g. `"rotation_orchestrator"`
- **`schema_version`:** integer `1` (not a string)

Canonical example:

```json
{"license_id":"550e8400-e29b-41d4-a716-446655440000","customer":"Acme Corp","email":"admin@acme.example","issued_at":"2026-05-01T00:00:00Z","expires_at":"2027-05-01T00:00:00Z","features":["rotation_orchestrator"],"schema_version":1}
```

The implementation must serialize the struct with `encoding/json` using field tags in the declared order, then verify the output contains no whitespace other than inside string values. A round-trip parse after serialization is a mandatory self-check before signing.

### 3.2 Two-Line Format

The license file consists of exactly two lines, each terminated by a Unix LF (`\n`, byte `0x0A`). No CRLF. No trailing newline after the second line.

```
<base64url(manifest_bytes)>\n<base64url(signature_bytes)>\n
```

Wait — to be precise: the file is exactly:

```
LINE1 LF LINE2 LF
```

Where:
- `LINE1` = base64url encoding of the UTF-8 manifest JSON bytes, **no padding** (RFC 4648 §5, pad chars omitted)
- `LINE2` = base64url encoding of the 64-byte Ed25519 signature, **no padding**

Both lines use the same alphabet and the same no-padding rule, for consistency. The orchestrator's parser reads until the first `\n` to get `LINE1`, then reads the remainder (stripped of any trailing `\n`) to get `LINE2`.

**Signature input:** The bytes signed are the raw UTF-8 bytes of the manifest JSON (i.e., the bytes that were base64url-encoded to produce `LINE1`). The signature is over manifest bytes, not over the base64url-encoded string.

**Size cap:** A typical license file is under 400 bytes. Enforce a hard maximum of 4 KB in the parser to prevent memory exhaustion from a malformed or malicious file. Exit 1 if the file exceeds 4 KB before decoding.

**Cross-reference:** T5 §2.1 specifies the same two-line format. This section is the authoritative byte-level elaboration of that specification.

---

## 4. Key Storage and Operational Handling

### 4.1 Storage Rule

**The Ed25519 private key must never exist in plaintext on disk outside of the issuance operation.** The threat is straightforward: if the key leaks, any holder can forge licenses for any customer indefinitely. Because the public key is embedded in the binary, key rotation requires a new binary release — meaning a leaked key has a blast radius proportional to how many customers have already received binaries.

**Storage location:** KPM secrets registry, under the key name:

```
catalyst9/license-signing-key/v1
```

The value stored is the full PEM block produced by `agentkms-license keygen`. KPM encrypts at rest; the plaintext is only visible to an authenticated `kpm get` call.

### 4.2 Issuance Invocation Pattern

The private key is never written to a file for issuance. The canonical invocation:

```sh
kpm get catalyst9/license-signing-key/v1 | \
  agentkms-license issue \
    --private-key - \
    --customer "CUSTOMER_NAME" \
    --email "CUSTOMER_EMAIL" \
    --expires "EXPIRES_AT_RFC3339" \
    --features "rotation_orchestrator" \
    --out CUSTOMER.lic
```

The private key exists in memory for the duration of the `agentkms-license issue` process and is freed when the process exits. It is never written to disk by this invocation. Shell history for this command should not contain the key value (it does not; the key comes from stdin, not a flag).

After `keygen`, the local PEM files should be deleted:

```sh
agentkms-license keygen --private-key /tmp/license-v1-private.pem --public-key ./license-v1-public.pem
kpm set catalyst9/license-signing-key/v1 < /tmp/license-v1-private.pem
rm /tmp/license-v1-private.pem
# license-v1-public.pem is retained — embed its bytes in internal/license/verify.go
```

### 4.3 Key Rotation

Increment the version suffix in the KPM key name: `catalyst9/license-signing-key/v2`. Re-embed the new public key in the Pro plugin binary. All licenses signed by `v1` will fail verification on any binary built with the `v2` public key embedded. This is acceptable because key rotation is a deliberate, pre-announced event that accompanies a major version bump of the Pro plugin.

Customers with active licenses receive reissued licenses (signed by `v2`) as part of the version upgrade. The `license_id` is preserved on reissue (same UUID, new signature). The `issued_at` is updated to the reissue date.

### 4.4 Backup

The private key in KPM is protected by KPM's encryption-at-rest. A separate encrypted backup should be created on a hardware token (YubiKey) following the hardware-key recovery pattern established in the v0.4 enrollment story. This is a v0.4 item; for v0.3 the KPM entry is the sole copy. The backup procedure should be documented before the first Pro binary ships to customers.

---

## 5. Customer Issuance Runbook

### 5.1 General Runbook

**Step 1 — Collect customer information**

Required inputs:
- Full name or company name (for `customer` field)
- Contact email (for `email` field)
- Term length (e.g., 90 days, 1 year)
- Feature set (currently always `["rotation_orchestrator"]`)

Compute `expires_at = issued_at + term_length`, rounded to midnight UTC on the last day.

**Step 2 — Generate the license ID**

```sh
python3 -c "import uuid; print(uuid.uuid4())"
# or: uuidgen | tr '[:upper:]' '[:lower:]'
```

Record this UUID in the license ledger (Step 7) before issuing.

**Step 3 — Issue the license**

```sh
kpm get catalyst9/license-signing-key/v1 | \
  agentkms-license issue \
    --private-key - \
    --license-id "<UUID from Step 2>" \
    --customer "<name>" \
    --email "<email>" \
    --expires "<expires_at>" \
    --features "rotation_orchestrator" \
    --out "<customer-slug>-<YYYY-MM-DD>.lic"
```

**Step 4 — Verify before delivery**

```sh
agentkms-license verify \
  --license "<customer-slug>-<YYYY-MM-DD>.lic" \
  --public-key ./license-v1-public.pem
```

Exit code must be 0. If not, diagnose and re-issue. Do not deliver an unverified license.

**Step 5 — Deliver to customer**

Recommended channels (in order of preference):
1. 1Password secure share link (recipient-email-gated, expires after first open)
2. Encrypted email (GPG-encrypted to customer's key if they have one)
3. HTTPS-only direct download link behind a short-lived token

Do not send via unencrypted email, Slack, or GitHub issue comments.

**Step 6 — Record in the license ledger**

Append a row to the license ledger (see §5.3 below) with:
- `license_id`
- `customer`
- `email`
- `issued_at`
- `expires_at`
- `features`
- `delivered_at` (timestamp)
- `delivery_channel`
- `key_version` (e.g., `v1`)

**Step 7 — Remind for renewal**

Set a calendar reminder at `expires_at - 14 days` to contact the customer about renewal. Renewal generates a new license file with the same `license_id`, updated `issued_at` and `expires_at`, and a fresh signature.

---

### 5.2 Self-Issued Demo License (Bert / Catalyst9 Internal)

For the initial Pro demo, Bert issues a license to himself:

```sh
kpm get catalyst9/license-signing-key/v1 | \
  agentkms-license issue \
    --private-key - \
    --customer "Catalyst9 Internal — demo" \
    --email "devopsbert@gmail.com" \
    --expires "2026-08-01T00:00:00Z" \
    --features "rotation_orchestrator" \
    --out catalyst9-internal-demo.lic
```

- **Customer:** `Catalyst9 Internal — demo`
- **Expiration:** ~3 months from issuance (aligns with OQ-T5-2's quarterly-license recommendation in T5 §6; short enough to exercise renewal before a paying customer does)
- **Features:** `["rotation_orchestrator"]`
- **Placement:** `$XDG_CONFIG_HOME/agentkms/license.lic` (default path read by the orchestrator plugin per T5 §2.3)

Verify before use:
```sh
agentkms-license verify \
  --license catalyst9-internal-demo.lic \
  --public-key ./license-v1-public.pem
```

---

### 5.3 License Ledger

For v0.3, the ledger is a private GitHub repository: `catalyst9ai/license-ledger` (or equivalent private repo). Each issued license is recorded as a JSON file at `licenses/<license_id>.json` with the fields listed in Step 6 of §5.1. The repository is private, access-controlled, and the single source of truth for active licenses.

This approach is operationally sufficient for a single-digit customer count. A database-backed ledger is a post-v0.3 concern and can be introduced without changes to the license format or the issuance CLI.

---

## 6. Repo Placement

**Recommendation: include in the OSS `agentkms` repo at `cmd/agentkms-license/`.**

The security model is asymmetric key cryptography: the source code for the issuance tooling can be fully public without weakening the system, because the private signing key is never in the repo. Anyone can read the signing code; only Catalyst9 can produce valid signatures.

This mirrors HashiCorp's approach with Vault Enterprise: the license format and verification logic are documented and partially visible in the open-source server; only the signing key is proprietary. The transparency is a feature — customers can audit exactly what is being validated without trusting a black box.

Practical advantages of staying in the OSS repo:
- The existing Go module, CI pipeline, and release infrastructure apply without modification.
- The `cmd/` layout is already established; `cmd/agentkms-license/` is consistent with `cmd/agentkms/` and `cmd/kpm/`.
- The verification code (`internal/license/verify.go`) lives in the same module as the Pro plugin, making cross-package imports straightforward.
- Customers curious about how verification works can read the code — this builds trust, not risk.

The only counter-argument (internal tooling mixed with public surface) is outweighed by the operational overhead of maintaining a separate repo for a small CLI that changes infrequently.

The coordinator should confirm this placement before implementation.

---

## 7. Open Questions for Coordinator

**OQ-LT-1: License ledger backend**

`catalyst9ai/license-ledger` (private GitHub repo with one JSON file per license) is operationally sufficient for early customers. The alternative is KPM tags or a simple SQLite database. The ledger does not need to be queryable programmatically in v0.3; a human-readable directory of JSON files is fine. Confirm the GH private repo approach, or specify a preference.

**OQ-LT-2: Auto-delivery via registry API**

Should `agentkms-license issue` optionally push the license to the customer's KPM instance via the registry API at issuance time? This would require knowing the customer's KPM endpoint and an API token, which is more operational complexity than warranted for early customers. Recommendation: no auto-delivery in v0.3; the runbook's manual delivery step is sufficient.

**OQ-LT-3: HSM-backed signing key**

Storing the private key in KPM (software encryption at rest) is the v0.3 security posture. A higher-security alternative is to store the private signing key on a hardware security module (YubiKey PIV or similar), never extracting it in software, and performing signing operations on the device. This is the same hardware-key recovery cert pattern planned for v0.4 enrollment. It eliminates the class of attacks where someone gains read access to the KPM store and extracts the key. Recommendation: defer HSM signing to v0.4; document the upgrade path (the `keygen` and `issue` commands' interfaces do not change — only the key source changes).

**OQ-LT-4: `--features` flag multiplicity**

The design specifies `--features` as both a comma-separated string and repeatable. These two modes should be collapsed to one. Recommendation: accept `--features` as a flag that may be specified multiple times (idiomatic Go CLI style), e.g. `--features rotation_orchestrator --features another_feature`. Comma-separation as a fallback is optional. Confirm before implementation to avoid a flag parsing ambiguity.

**OQ-LT-5: Binary inclusion in release artifacts**

If `cmd/agentkms-license/` is in the OSS repo, the CI release pipeline will build it alongside `agentkms` and `kpm`. The binary should either be excluded from public release artifacts (using a build tag or a separate CI step that omits it from the GitHub Release assets) or included with a prominent note that it is issuer-only tooling. Recommendation: exclude from public release artifacts; the source remains public but the binary is not distributed via GitHub Releases. Coordinator should confirm.
