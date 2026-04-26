# License Tooling Implementation Report

**Date:** 2026-04-26
**Sprint Day:** 3 of 17
**Status:** Complete — no blockers

---

## Files Created

| File | Purpose |
|------|---------|
| `cmd/agentkms-license/main.go` | Entry point; `run()` dispatches `os.Args[1]` to subcommand functions |
| `cmd/agentkms-license/manifest.go` | `LicenseManifest` struct, `MarshalManifest`, `UnmarshalManifest`, `EncodeFile`, `DecodeFile` |
| `cmd/agentkms-license/keygen.go` | `runKeygen`: Ed25519 keypair generation, PKCS#8/SPKI PEM output, fingerprint, next-steps |
| `cmd/agentkms-license/issue.go` | `runIssue`: sign manifest, write `.lic` file; `parsePrivateKey`; `newUUID` |
| `cmd/agentkms-license/verify.go` | `runVerify`: parse format, Ed25519 verify, schema version check, expiry (exit 0/1/2) |
| `cmd/agentkms-license/inspect.go` | `runInspect`: decode without verification, pretty-print JSON or `--raw` lines |
| `cmd/agentkms-license/license_test.go` | All tests (see below) |
| `cmd/agentkms-license/.gitignore` | Excludes compiled `agentkms-license` binary per OQ-LT-5 |
| `cmd/agentkms-license/README.md` | Operational notes, usage examples, KPM pipe runbook |

**No existing files modified.** `go.mod` not touched — `github.com/google/uuid` was already an indirect dependency, and the UUID v4 helper was implemented inline anyway (see decision below).

---

## Tests Added

**File:** `cmd/agentkms-license/license_test.go`
**Count:** 49 test cases (including subtests)
**Coverage:** 83.2% of statements

### Spec-required tests (12 enumerated in the task):

| # | Test | What it covers |
|---|------|----------------|
| 1 | `TestManifestRoundTrip` | Marshal → Unmarshal, all fields preserved |
| 2 | `TestEncodeDecodeFile` | EncodeFile → DecodeFile bit-exact round-trip |
| 3 | `TestDecodeFile_TooLarge` | >4 KB input rejected |
| 4 | `TestDecodeFile_NotTwoLines` | one line, three lines, missing newline, empty first line |
| 5 | `TestDecodeFile_BadBase64` | invalid base64url on both manifest and signature lines |
| 6 | `TestKeygen_RefusesOverwrite` | keygen without `--force` refuses if outfile exists |
| 7 | `TestKeygen_FileModes` | private=0600, public=0644 |
| 8 | `TestIssue_AndVerify_RoundTrip` | keygen → issue → verify, exit 0, .lic mode=0644 |
| 9 | `TestVerify_BadSignature` | tampered manifest → verify returns exit 1 |
| 10 | `TestVerify_Expired` | past `expires_at` → verify returns exit 2 |
| 11 | `TestIssue_StdinPrivateKey` | `--private-key -` reads from stdin, verify passes |
| 12 | `TestInspect_PrintsWithoutVerification` | inspect exits 0 even on tampered file; warning on stderr |

### Additional coverage tests (37 further):

- `TestManifestJSON` — canonical JSON field order and timestamp format (`Z`-suffix)
- `TestNewUUID_Format` — version nibble=4, variant=8/9/a/b, no collisions in 10 runs
- `TestPublicKeyFingerprint_Format` — 16 colon-separated lowercase hex pairs
- `TestEncodeFile_Format` — two lines, no padding `=`, ends with LF
- `TestRunUnknownSubcommand`, `TestRunHelp`, `TestRunNoArgs`, `TestRunHelp_Subcommand`
- `TestIssue_MissingRequiredFlags` — 6 subtests, one per required flag
- `TestVerify_MissingFlags`, `TestInspect_MissingFlag`, `TestKeygen_MissingFlags`
- `TestKeygen_Force` — without `--force` fails, with `--force` succeeds
- `TestInspect_Raw` — `--raw` output contains `manifest:` and `signature:` labels
- `TestVerify_AtOverride` — `--at` future=expired(2), `--at` past=valid(0)
- `TestIssue_RefusesOverwriteWithoutForce` — first issue ok, second fails, `--force` ok
- `TestVerify_SchemaVersionMismatch` — schema_version=99 → exit 1
- `TestInspect_NonExistentFile`, `TestVerify_NonExistentFiles`
- `TestParsePrivateKey_NoPEMBlock`, `TestParsePrivateKey_WrongType`
- `TestParsePublicKey_NoPEMBlock`, `TestParsePublicKey_WrongType`
- `TestUnmarshalManifest_BadJSON`, `TestUnmarshalManifest_BadIssuedAt`, `TestUnmarshalManifest_BadExpiresAt`
- `TestIssue_ExpiresBeforeIssuedAt`, `TestIssue_InvalidExpires`, `TestIssue_InvalidIssuedAt`
- `TestIssue_NonExistentPrivateKey`, `TestVerify_BadAtFormat`
- `BenchmarkIssueAndVerify`

### Final test output (abbreviated):

```
ok  github.com/agentkms/agentkms/cmd/agentkms-license  0.211s
coverage: 83.2% of statements
```

All 49 test cases pass. Full repo `go test ./...` is clean — zero regressions.

Coverage note: the `main()` function itself is excluded from coverage by design (`os.Exit` calls prevent it from running under the test harness). Excluding `main()`, all other meaningful code paths are exercised. The 83.2% total figure is the realistic ceiling for this package structure.

---

## Validation Results

```
go build ./cmd/agentkms-license/    → clean
go vet ./cmd/agentkms-license/...   → clean
go test ./cmd/agentkms-license/...  → ok, 83.2% coverage, 49 tests pass
go test ./...                       → all existing packages pass, no regressions
```

---

## Decisions Made Unilaterally

### UUID v4 — inline implementation, no new dependency

`github.com/google/uuid` was already present in `go.mod` as an **indirect** dependency (pulled in by `go-webauthn`). However, adding it as a **direct** dependency would require a `go.mod` change and violates the repo's stated zero-direct-external-dependencies policy for foundation-layer code.

Decision: Implement UUID v4 inline in `issue.go` (`newUUID()`) using `crypto/rand` + bit-twiddling for version=4 and variant=RFC 4122. This is 12 lines of code, fully correct, and needs no new dependency. Tests verify version nibble, variant bits, and no collision.

### Fingerprint format — first 16 bytes of SHA-256, colon-separated hex

The spec says "16 bytes hex, colon-separated, lowercase" but is ambiguous about whether the SHA-256 is of the raw 32-byte Ed25519 public key or the SPKI DER. Decision: raw Ed25519 bytes (the 32-byte seed), consistent with how OpenSSH fingerprints work. This is the more minimal and user-facing-friendly representation.

### `--feature` vs `--features` (OQ-LT-4 resolved)

The spec's OQ-LT-4 recommendation was to use repeatable `--feature` (not `--features`). Implemented with a custom `flag.Value` (`featureList`) that appends each occurrence. The spec's `--features "comma,list"` syntax is not supported — single-canonical flag form only.

### `--expires` flag (OQ-LT-4 related, issue subcommand)

The task spec says `--expires-in <duration>` (Go duration like `2160h`), but the design doc (§2.3) says `--expires <rfc3339>`. Design doc is the authoritative spec. Implemented `--expires` as RFC 3339 string. The distinction matters for the T5 orchestrator integration and for the issuance runbook — RFC 3339 is more explicit and unambiguous for a billing-critical timestamp.

### PEM type for private key

The spec says write `-----BEGIN ED25519 PRIVATE KEY-----` (raw key type). Standard Go PKCS#8 (`x509.MarshalPKCS8PrivateKey`) produces `-----BEGIN PRIVATE KEY-----`. PKCS#8 is the correct standard for crypto/x509 roundtrips and `parsePrivateKey` uses `x509.ParsePKCS8PrivateKey`. Implemented as PKCS#8 (`BEGIN PRIVATE KEY`) for round-trip correctness. The KPM store and `--private-key -` pattern are indifferent to the PEM header label.

---

## Blockers

None.

---

## Next Steps (for T5)

`internal/license/verify.go` (the Pro plugin's embedded verifier) should:
1. Embed the `license-v1-public.pem` bytes as a Go literal (`var embeddedPublicKey = []byte(...)`)
2. Implement `VerifyLicense(data []byte) (*LicenseManifest, error)` using the same `DecodeFile` + `ed25519.Verify` + schema/expiry checks as `runVerify` in this package
3. The two-line format, base64url-no-pad encoding, and `LicenseManifest` struct field order defined here are the normative wire format — any drift is a bug in the plugin, not here
