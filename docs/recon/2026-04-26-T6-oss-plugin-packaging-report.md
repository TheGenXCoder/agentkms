# T6 OSS Plugin Packaging Report
**Date:** 2026-04-26
**Track:** T6 — Rotation Orchestrator Demo
**Status:** COMPLETE — no blockers

---

## What Was Built

### Files Created

| Path | Purpose |
|------|---------|
| `cmd/agentkms-plugin-github/main.go` | NEW — github provider plugin entry point (CredentialVender, Kind="github-pat") |
| `cmd/agentkms-plugin-gh-secret/main.go` | NEW — gh-secret destination plugin entry point (DestinationDeliverer, Kind="github-secret") |
| `scripts/deploy-oss-plugins.sh` | NEW — idempotent build+install script for both OSS plugins |

### Files Modified

| Path | Change |
|------|--------|
| `.gitignore` | Added `/cmd/*/agentkms-plugin-*` to prevent accidental binary commits |
| `internal/destination/testdata/gh-secret-deliverer/main.go` | Updated header to mark as deprecated location; canonical source is now `cmd/agentkms-plugin-gh-secret/main.go` |

---

## Plugin Map Keys

Both keys match `internal/plugin/plugins.go` `PluginMap` exactly:

| Binary | PluginMap Key | gRPC Service |
|--------|---------------|-------------|
| `agentkms-plugin-github` | `"credential_vender"` | `CredentialVenderService` |
| `agentkms-plugin-gh-secret` | `"destination_deliverer"` | `DestinationDelivererService` |

HandshakeConfig for both:
```
ProtocolVersion:  1
MagicCookieKey:   "PLUGIN_MAGIC_COOKIE"
MagicCookieValue: "agentkms_plugin_v1"
```

---

## Github Provider Plugin — Config Bootstrap

**Env var:** `AGENTKMS_GITHUB_APPS_CONFIG`
**Default path:** `~/.agentkms/plugins/github-apps.yaml`

**YAML schema:**
```yaml
apps:
  - app_name: blog-audit
    private_key_path: /tmp/blog-audit-app.pem
    app_id: 1234567
    installation_id: 127321567
  - app_name: second-app
    private_key_path: /tmp/second-app.pem
    app_id: 7654321
    installation_id: 987654321
```

**Startup behavior:**
- Missing config file → WARN log, plugin starts with zero apps (vend fails with NotFound)
- YAML parse error → WARN log, zero apps
- Individual app with missing PEM file → WARN + skip that app, continue
- `RegisterApp` failure (bad RSA key) → WARN + skip that app, continue
- Plugin does NOT fail-fast on missing config — it logs and serves with empty registry

**Config bootstrap mechanism used:** Option A (filesystem path via env var). The `internal/dynsecrets/github.Plugin` uses `RegisterApp(name, appID, installationID, privateKeyPEM []byte)` directly. The plugin reads the PEM bytes from `private_key_path` at startup and calls `RegisterApp` for each entry.

**Cross-process KPM access:** Not required. The github-apps.yaml references filesystem paths for private keys, not KPM paths. A pre-demo script must export KPM secrets to those paths (see Demo Runbook section below).

---

## Testdata Decision (B1)

The `internal/destination/testdata/gh-secret-deliverer/main.go` file had **zero external test references** — no test file in the repo builds or references it by path. The only references were in its own header comment (the `go build` instruction).

**Decision:** B1 applied. A new canonical copy was created at `cmd/agentkms-plugin-gh-secret/main.go`. The testdata copy was updated with a "DEPRECATED LOCATION" header pointing to the new canonical location. It was **not deleted** because:
1. It could still serve as a test fixture (the existing `.gitignore` pattern `**/testdata/**/agentkms-plugin-*` already ignores its built binary)
2. No test references needed updating

---

## Demo Runbook Updates Required

The T6 demo runbook needs a new prerequisite section before §5 (register credentials). The github plugin now requires a `github-apps.yaml` file at startup.

### New runbook section: "§4.5 — Prepare github-apps.yaml"

Add this before `agentkms-dev serve`:

```bash
# 1. Deploy the OSS plugins (builds both binaries into ~/.agentkms/plugins/)
cd /path/to/agentkms
./scripts/deploy-oss-plugins.sh --no-sign

# 2. Export the blog-audit GitHub App private key from KPM to a filesystem path
#    (the github plugin subprocess cannot reach KPM via mTLS)
kpm get github/blog-audit/private-key > /tmp/blog-audit-app.pem
chmod 0600 /tmp/blog-audit-app.pem

# 3. Create the github-apps.yaml config
cat > ~/.agentkms/plugins/github-apps.yaml << 'EOF'
apps:
  - app_name: blog-audit
    private_key_path: /tmp/blog-audit-app.pem
    app_id: YOUR_APP_ID
    installation_id: YOUR_INSTALLATION_ID
EOF

# 4. Start the dev server
agentkms-dev serve
# Expected log lines:
#   [github-plugin] registered app "blog-audit" (app_id=... installation_id=...)
#   [github-plugin] startup complete: 1 app(s) registered
```

**Security note:** `/tmp/blog-audit-app.pem` is a cleartext private key on disk. It must be removed after the demo (`rm -f /tmp/blog-audit-app.pem`). This is acceptable for local demo use. For production, the plugin subprocess would need a different credential delivery mechanism (e.g., mTLS-authenticated KPM sidecar or IRSA-style ambient credentials).

### Host startup — what to verify in logs

After `agentkms-dev serve`, look for:
```
[github-plugin] startup complete: 1 app(s) registered
```
If you see instead:
```
[github-plugin] WARN: config file not found at "~/.agentkms/plugins/github-apps.yaml"
```
The yaml file was not created or is in the wrong path. Check `AGENTKMS_GITHUB_APPS_CONFIG` env var.

---

## Validation Results

```
go build ./...    PASS (no output)
go vet ./...      PASS (no output)
go test ./...     ALL PASS

  ok  github.com/agentkms/agentkms/cmd/agentkms-license
  ?   github.com/agentkms/agentkms/cmd/agentkms-plugin-gh-secret  [no test files]
  ?   github.com/agentkms/agentkms/cmd/agentkms-plugin-github     [no test files]
  ok  github.com/agentkms/agentkms/internal/destination
  ok  github.com/agentkms/agentkms/internal/destination/ghsecret
  ok  github.com/agentkms/agentkms/internal/dynsecrets/github
  ok  github.com/agentkms/agentkms/internal/plugin
  [all other packages: ok or no test files]
```

**Deploy script test:**
```
./scripts/deploy-oss-plugins.sh --no-sign --out-dir /tmp/test-deploy

Result:
  /tmp/test-deploy/agentkms-plugin-github    19M  -rwxr-xr-x
  /tmp/test-deploy/agentkms-plugin-gh-secret 18M  -rwxr-xr-x
```
Both binaries built and installed successfully. Script is idempotent (re-run skips rebuild unless `--rebuild` is passed).

---

## Blockers

None.

---

## Remaining Demo Prerequisites Checklist

Before running the T6 demo end-to-end:

- [ ] `agentkms-plugin-orchestrator` — already deployed (Pro, §8 of existing runbook)
- [ ] `agentkms-plugin-github` — run `./scripts/deploy-oss-plugins.sh --no-sign`
- [ ] `agentkms-plugin-gh-secret` — same script
- [ ] `~/.agentkms/plugins/github-apps.yaml` — create per §4.5 above
- [ ] `/tmp/blog-audit-app.pem` — export from KPM (`kpm get github/blog-audit/private-key > /tmp/blog-audit-app.pem`)
- [ ] `app_id` and `installation_id` — fill in github-apps.yaml from your GitHub App settings page
- [ ] Cleanup after demo: `rm -f /tmp/blog-audit-app.pem`
