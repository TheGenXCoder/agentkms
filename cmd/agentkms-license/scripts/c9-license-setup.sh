#!/usr/bin/env bash
#
# c9-license-setup.sh — Catalyst9 internal license provisioning runbook.
#
# Idempotent setup for the Pro license signing keypair and a demo license:
#   1. Build the agentkms-license binary
#   2. Generate Ed25519 signing keypair (if not already in KPM)
#   3. Import private key to KPM (catalyst9/license-signing-key/v<N>)
#   4. Save public key to ~/.config/agentkms/license.pub.pem
#   5. Securely delete the local private PEM
#   6. Issue a demo license at ~/.config/agentkms/license.lic (if not present)
#   7. Verify the issued license round-trips
#
# Re-running is safe: step 2 is skipped if the key already exists in KPM,
# and step 6 is skipped if the license file already exists.
#
# Customer-issuance use:
#   AGENTKMS_LICENSE_CUSTOMER="Acme Corp" \
#   AGENTKMS_LICENSE_EMAIL=admin@acme.example \
#   AGENTKMS_LICENSE_EXPIRES_DAYS=365 \
#   AGENTKMS_LICENSE_OUTPUT=./acme-corp.lic \
#   ./c9-license-setup.sh --issue-only

set -euo pipefail

# ─── Config (env-overridable) ───────────────────────────────────────────────
KEY_VERSION="${KEY_VERSION:-1}"
KEY_NAME="catalyst9/license-signing-key/v${KEY_VERSION}"

CUSTOMER="${AGENTKMS_LICENSE_CUSTOMER:-Catalyst9 Internal — demo}"
EMAIL="${AGENTKMS_LICENSE_EMAIL:-devopsbert@gmail.com}"
EXPIRES_DAYS="${AGENTKMS_LICENSE_EXPIRES_DAYS:-90}"
FEATURES="${AGENTKMS_LICENSE_FEATURES:-rotation_orchestrator}"
LICENSE_OUTPUT="${AGENTKMS_LICENSE_OUTPUT:-$HOME/.config/agentkms/license.lic}"
PUBKEY_FILE="${AGENTKMS_LICENSE_PUBKEY:-$HOME/.config/agentkms/license.pub.pem}"

TMP_PRIV="${TMPDIR:-/tmp}/c9-license.priv.pem"
TMP_PUB="${TMPDIR:-/tmp}/c9-license.pub.pem"
BIN="${TMPDIR:-/tmp}/agentkms-license"

# Repo root resolves from the script's location: scripts/ -> cmd/agentkms-license/ -> repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTKMS_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# ─── Output helpers ─────────────────────────────────────────────────────────
say()  { printf "==> %s\n" "$*"; }
warn() { printf "    WARNING: %s\n" "$*" >&2; }
die()  { printf "    ERROR: %s\n" "$*" >&2; exit 1; }
ok()   { printf "    %s\n" "$*"; }

# ─── Argument parsing ───────────────────────────────────────────────────────
ISSUE_ONLY=0
KEYGEN_ONLY=0
FORCE_REISSUE=0
for arg in "$@"; do
    case "$arg" in
        --issue-only)     ISSUE_ONLY=1 ;;
        --keygen-only)    KEYGEN_ONLY=1 ;;
        --force-reissue)  FORCE_REISSUE=1 ;;
        --help|-h)
            sed -n '2,22p' "$0"
            exit 0
            ;;
        *) die "unknown flag: $arg" ;;
    esac
done

# ─── Preflight ──────────────────────────────────────────────────────────────
say "Preflight checks"
command -v go >/dev/null  || die "go not found in PATH"
command -v kpm >/dev/null || die "kpm not found in PATH"
[[ -d "$AGENTKMS_DIR/cmd/agentkms-license" ]] \
    || die "agentkms repo not found at $AGENTKMS_DIR (script must run from cmd/agentkms-license/scripts/)"
ok "go: $(go version | awk '{print $3}')"
ok "kpm: $(command -v kpm)"
ok "agentkms repo: $AGENTKMS_DIR"

# ─── Step 1: Build the binary ───────────────────────────────────────────────
say "Building agentkms-license"
( cd "$AGENTKMS_DIR" && go build -o "$BIN" ./cmd/agentkms-license/ )
ok "binary: $BIN"

# ─── Step 2-5: Keygen + import + secure delete ──────────────────────────────
if [[ $ISSUE_ONLY -eq 0 ]]; then
    if kpm describe "$KEY_NAME" >/dev/null 2>&1; then
        say "Signing key already in KPM as $KEY_NAME — skipping keygen"
        if [[ ! -f "$PUBKEY_FILE" ]]; then
            warn "$PUBKEY_FILE not found — orchestrator binary embedding will need this."
            warn "Either keep your previously-saved public key file at that path, or regenerate the keypair:"
            warn "  kpm remove $KEY_NAME --purge && rerun this script"
        else
            ok "public key on disk: $PUBKEY_FILE"
        fi
    else
        say "Generating Ed25519 signing keypair (version $KEY_VERSION)"
        "$BIN" keygen \
            --private-key "$TMP_PRIV" \
            --public-key  "$TMP_PUB" \
            --key-version "$KEY_VERSION"

        say "Importing private key to KPM as $KEY_NAME"
        kpm add "$KEY_NAME" \
            --from-file "$TMP_PRIV" \
            --type "private-key" \
            --description "Catalyst9 Pro license signing key (Ed25519, version $KEY_VERSION)" \
            --tags "pro=license-signing,key-version=$KEY_VERSION" \
            --force

        say "Persisting public key to $PUBKEY_FILE"
        mkdir -p "$(dirname "$PUBKEY_FILE")"
        cp "$TMP_PUB" "$PUBKEY_FILE"
        chmod 0644 "$PUBKEY_FILE"
        ok "public key: $PUBKEY_FILE"

        say "Securely deleting local private PEM"
        if rm -P "$TMP_PRIV" 2>/dev/null; then
            ok "removed (rm -P, BSD/macOS overwrite-then-unlink)"
        elif command -v shred >/dev/null; then
            shred -u "$TMP_PRIV"
            ok "removed (shred -u)"
        else
            rm -f "$TMP_PRIV"
            warn "no secure-delete available; used plain rm. Private key existed in plaintext on this filesystem."
        fi
        rm -f "$TMP_PUB"
    fi
fi

# ─── Step 6-7: Issue + verify demo license ──────────────────────────────────
if [[ $KEYGEN_ONLY -eq 0 ]]; then
    if [[ -f "$LICENSE_OUTPUT" ]] && [[ $FORCE_REISSUE -eq 0 ]]; then
        say "License already exists at $LICENSE_OUTPUT — skipping issuance"
        ok "to re-issue: $0 --force-reissue"
    else
        # Compute expiry (RFC 3339 UTC) — try GNU date first, fall back to BSD/macOS
        if EXPIRES=$(date -u -d "+${EXPIRES_DAYS} days" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null); then
            :
        elif EXPIRES=$(date -u -v+"${EXPIRES_DAYS}"d +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null); then
            :
        else
            die "could not compute expiry date — neither GNU nor BSD date worked"
        fi

        say "Issuing license"
        ok "customer: $CUSTOMER"
        ok "email:    $EMAIL"
        ok "expires:  $EXPIRES (in ${EXPIRES_DAYS} days)"
        ok "features: $FEATURES"
        ok "output:   $LICENSE_OUTPUT"

        mkdir -p "$(dirname "$LICENSE_OUTPUT")"

        # Build --feature args from the comma-separated FEATURES var
        feature_args=()
        IFS=',' read -ra FEATURE_ARR <<< "$FEATURES"
        for f in "${FEATURE_ARR[@]}"; do
            feature_args+=(--feature "$(echo "$f" | xargs)")
        done

        kpm get "$KEY_NAME" | "$BIN" issue \
            --private-key - \
            --customer "$CUSTOMER" \
            --email    "$EMAIL" \
            --expires  "$EXPIRES" \
            "${feature_args[@]}" \
            --out      "$LICENSE_OUTPUT"

        say "Verifying issued license"
        "$BIN" verify \
            --public-key "$PUBKEY_FILE" \
            --license    "$LICENSE_OUTPUT"
    fi
fi

# ─── Summary ────────────────────────────────────────────────────────────────
echo
say "Done"
ok "KPM private key:  $KEY_NAME"
ok "Public key (PEM): $PUBKEY_FILE"
[[ $KEYGEN_ONLY -eq 0 ]] && ok "License file:     $LICENSE_OUTPUT"
echo
ok "Next: when T5 dispatches, point it at $PUBKEY_FILE for the embedded public-key bytes."
