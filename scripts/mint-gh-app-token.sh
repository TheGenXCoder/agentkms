#!/usr/bin/env bash
#
# mint-gh-app-token.sh — Mint a GitHub App installation token via JWT.
#
# Reads App credentials from KPM:
#   github/blog-audit-app/private-key   (the PEM, plaintext via kpm get)
#   github/blog-audit-app/app-id        (numeric App ID)
#   github/blog-audit-app/installation-id (numeric Installation ID)
#
# Writes the installation token (1-hour TTL) to:
#   /tmp/install-token.txt
#
# And optionally re-registers a binding's destination params with the fresh
# token via `--rebind <binding-name>`.
#
# Usage:
#   ./mint-gh-app-token.sh                    # mint only
#   ./mint-gh-app-token.sh --rebind blog-audit-rotator
#                                             # mint + re-register binding
#                                             # with the fresh writer_token
#
# Override the App in KPM with env vars:
#   APP_KPM_PRIV=catalyst9/some-other-app/private-key \
#   APP_KPM_ID=catalyst9/some-other-app/app-id \
#   APP_KPM_INSTALL=catalyst9/some-other-app/installation-id \
#     ./mint-gh-app-token.sh

set -euo pipefail

# ─── Config (env-overridable) ───────────────────────────────────────────────
APP_KPM_PRIV="${APP_KPM_PRIV:-github/blog-audit-app/private-key}"
APP_KPM_ID="${APP_KPM_ID:-github/blog-audit-app/app-id}"
APP_KPM_INSTALL="${APP_KPM_INSTALL:-github/blog-audit-app/installation-id}"
TOKEN_OUT="${TOKEN_OUT:-/tmp/install-token.txt}"
PEM_PATH="${PEM_PATH:-/tmp/blog-audit-app.pem}"
KPM_BIN="${KPM_BIN:-kpm}"

# ─── Output helpers ─────────────────────────────────────────────────────────
say()  { printf "==> %s\n" "$*"; }
ok()   { printf "    %s\n" "$*"; }
die()  { printf "    ERROR: %s\n" "$*" >&2; exit 1; }

# ─── Argument parsing ───────────────────────────────────────────────────────
REBIND_TARGET=""
for arg in "$@"; do
    case "$arg" in
        --rebind=*) REBIND_TARGET="${arg#*=}" ;;
        --rebind)   shift; REBIND_TARGET="${1:-}" ;;
        --help|-h)
            sed -n '2,28p' "$0"
            exit 0
            ;;
    esac
done

# ─── Preflight ──────────────────────────────────────────────────────────────
say "Preflight"
command -v "$KPM_BIN" >/dev/null || die "kpm not found: $KPM_BIN (override via KPM_BIN)"
command -v python3 >/dev/null || die "python3 required for JWT signing"
python3 -c "import jwt" 2>/dev/null || die "python3 'jwt' module missing — pip install pyjwt cryptography"
ok "kpm: $(command -v "$KPM_BIN")"
ok "python3: $(command -v python3)"

# ─── Pull App credentials from KPM ──────────────────────────────────────────
say "Reading App credentials from KPM"
APP_ID="$("$KPM_BIN" get "$APP_KPM_ID")"
INSTALL_ID="$("$KPM_BIN" get "$APP_KPM_INSTALL")"
"$KPM_BIN" get "$APP_KPM_PRIV" > "$PEM_PATH"
chmod 0600 "$PEM_PATH"

ok "App ID:          $APP_ID"
ok "Installation ID: $INSTALL_ID"
ok "Private key →    $PEM_PATH"

# ─── Mint installation token ────────────────────────────────────────────────
say "Minting installation token"
python3 <<PY > "$TOKEN_OUT"
import jwt, time, urllib.request, json, sys
with open("$PEM_PATH","rb") as f:
    pem = f.read()
now = int(time.time())
jwt_token = jwt.encode({"iat": now-30, "exp": now+540, "iss": "$APP_ID"}, pem, algorithm="RS256")
req = urllib.request.Request(
    f"https://api.github.com/app/installations/$INSTALL_ID/access_tokens",
    method="POST",
    headers={
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
try:
    with urllib.request.urlopen(req) as resp:
        body = json.load(resp)
    sys.stdout.write(body["token"])
    sys.stderr.write(f"  expires:    {body['expires_at']}\n")
    sys.stderr.write(f"  permissions: {json.dumps(body.get('permissions',{}))}\n")
except urllib.error.HTTPError as e:
    sys.stderr.write(f"HTTP {e.code}: {e.read().decode()}\n")
    sys.exit(1)
PY
chmod 0600 "$TOKEN_OUT"
ok "token →         $TOKEN_OUT (head: $(head -c 12 "$TOKEN_OUT")...)"

# ─── Optional: rebind a binding's destination writer_token ─────────────────
if [[ -n "$REBIND_TARGET" ]]; then
    say "Re-registering binding \"$REBIND_TARGET\" with fresh writer_token"

    # Pull the existing binding's full config so we can preserve everything
    # except the destination params.
    EXISTING="$("$KPM_BIN" cred inspect "$REBIND_TARGET" --json 2>/dev/null || true)"
    if [[ -z "$EXISTING" ]]; then
        die "binding \"$REBIND_TARGET\" not found — register it first"
    fi

    # Extract fields we need to round-trip
    PROVIDER=$(printf '%s' "$EXISTING" | python3 -c "import json,sys; print(json.load(sys.stdin)['provider_kind'])")
    PROVIDER_PARAMS=$(printf '%s' "$EXISTING" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin).get('provider_params',{})))")
    SCOPE=$(printf '%s' "$EXISTING" | python3 -c "import json,sys; print(json.load(sys.stdin).get('scope',{}).get('kind','generic'))")
    TTL=$(printf '%s' "$EXISTING" | python3 -c "import json,sys; print(json.load(sys.stdin).get('rotation_policy',{}).get('ttl_hint_seconds',3600))")
    MANUAL=$(printf '%s' "$EXISTING" | python3 -c "import json,sys; print(str(json.load(sys.stdin).get('rotation_policy',{}).get('manual_only',True)).lower())")

    # Rebuild the destinations list with the fresh writer_token in each
    DEST_ARGS=$(printf '%s' "$EXISTING" | TOKEN="$(cat "$TOKEN_OUT")" python3 - <<'PYEOF'
import json, sys, os, shlex
b = json.load(sys.stdin)
token = os.environ["TOKEN"]
out = []
for d in b.get("destinations", []):
    params = dict(d.get("params") or {})
    params["writer_token"] = token
    triple = f"{d['kind']}:{d['target_id']}:{json.dumps(params)}"
    out.append(f'--destination {shlex.quote(triple)}')
print(" ".join(out))
PYEOF
    )

    "$KPM_BIN" cred remove "$REBIND_TARGET" --purge >/dev/null 2>&1 || true

    eval "$KPM_BIN cred register \"$REBIND_TARGET\" \
        --provider \"$PROVIDER\" \
        --provider-params \"$PROVIDER_PARAMS\" \
        --scope \"$SCOPE\" \
        --ttl \"$TTL\" \
        --manual-only=$MANUAL \
        $DEST_ARGS" >/dev/null

    ok "binding \"$REBIND_TARGET\" re-registered with fresh writer_token"
fi

echo
say "Done"
ok "Installation token at: $TOKEN_OUT (1-hour TTL)"
[[ -n "$REBIND_TARGET" ]] && ok "Binding refreshed:     $REBIND_TARGET"
