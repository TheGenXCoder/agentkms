#!/usr/bin/env bash
#
# deploy-oss-plugins.sh — Build and install the OSS AgentKMS plugin binaries.
#
# Idempotent deployment for:
#   - agentkms-plugin-github    (CredentialVender for Kind="github-pat")
#   - agentkms-plugin-gh-secret (DestinationDeliverer for Kind="github-secret")
#
# Steps for each plugin:
#   1. Preflight: go, plugin directory.
#   2. Build: go build ./cmd/agentkms-plugin-<name>/
#   3. Sign:  produce a detached Ed25519 .sig sidecar (unless --no-sign).
#   4. Install: copy binary + .sig to plugin directory, chmod 0755.
#
# Re-running is safe: the build step is skipped if the binary is already present
# and --rebuild is not passed. The sign + copy steps always run when the binary
# is (re-)built.
#
# NOTE — Plugin signing:
#   The OSS host verifies plugin binaries with an Ed25519 sidecar. The private
#   key required to produce that sidecar is a Catalyst9 internal key (not in
#   this repository). Use --no-sign for local development; the agentkms-dev
#   host is configured without a verifier (NewHost, not NewHostWithVerifier)
#   so unsigned binaries are permitted with a log warning.
#
# Usage:
#   ./scripts/deploy-oss-plugins.sh [--out-dir <path>] [--no-sign] [--rebuild] [--help]
#
# Environment variables:
#   AGENTKMS_PLUGIN_DIR   Override plugin install directory (same variable the host uses)
#
# Flags:
#   --out-dir <path>   Override plugin install directory (beats AGENTKMS_PLUGIN_DIR)
#   --no-sign          Skip signing; install binary only, no .sig sidecar
#   --rebuild          Force rebuild even if binary already exists at build output path
#   --help / -h        Show this help

set -euo pipefail

# ─── Config (env-overridable) ────────────────────────────────────────────────

# Repo root: scripts/ -> repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Plugin directory precedence:
#   1. --out-dir flag (parsed below)
#   2. AGENTKMS_PLUGIN_DIR env
#   3. ~/.agentkms/plugins/  (matches cmd/cli/main.go defaultPluginDir())
DEFAULT_PLUGIN_DIR="${HOME}/.agentkms/plugins"
PLUGIN_DIR="${AGENTKMS_PLUGIN_DIR:-${DEFAULT_PLUGIN_DIR}}"

# ─── Output helpers ──────────────────────────────────────────────────────────

say()  { printf "==> %s\n" "$*"; }
warn() { printf "    WARNING: %s\n" "$*" >&2; }
die()  { printf "    ERROR: %s\n" "$*" >&2; exit 1; }
ok()   { printf "    %s\n" "$*"; }
skip() { printf "    (skip) %s\n" "$*"; }

# ─── Argument parsing ────────────────────────────────────────────────────────

NO_SIGN=0
REBUILD=0
for arg in "$@"; do
    case "$arg" in
        --no-sign)         NO_SIGN=1 ;;
        --rebuild)         REBUILD=1 ;;
        --out-dir)         ;;  # value handled as a pair below
        --help|-h)
            sed -n '3,47p' "$0"
            exit 0
            ;;
        *) : ;;
    esac
done

# Re-parse for --out-dir <value> (positional pairing)
i=1
while [[ $i -le $# ]]; do
    arg="${!i}"
    if [[ "$arg" == "--out-dir" ]]; then
        i=$(( i + 1 ))
        if [[ $i -gt $# ]]; then
            die "--out-dir requires a path argument"
        fi
        PLUGIN_DIR="${!i}"
    fi
    i=$(( i + 1 ))
done

# Unknown flags — surface early to avoid silent misuse
for arg in "$@"; do
    case "$arg" in
        --no-sign|--rebuild|--help|-h|--out-dir) ;;
        -*)
            warn "unknown flag: $arg"
            ;;
    esac
done

# ─── Preflight ───────────────────────────────────────────────────────────────

say "Preflight checks"

command -v go >/dev/null || die "go not found in PATH"
ok "go: $(go version | awk '{print $3}')"
ok "repo root: ${REPO_ROOT}"

[[ -d "${REPO_ROOT}/cmd/agentkms-plugin-github" ]] \
    || die "cmd/agentkms-plugin-github not found — run from the agentkms repo root"
[[ -d "${REPO_ROOT}/cmd/agentkms-plugin-gh-secret" ]] \
    || die "cmd/agentkms-plugin-gh-secret not found — run from the agentkms repo root"

# Signing check
if [[ $NO_SIGN -eq 0 ]]; then
    if ! command -v kpm >/dev/null; then
        warn "kpm not found — cannot retrieve signing key."
        warn "For local dev, use --no-sign."
        die "Cannot sign without kpm. Use --no-sign for the demo."
    fi
    if ! kpm describe "catalyst9/plugin-signing-key/v1" >/dev/null 2>&1; then
        warn "Plugin signing key not found in KPM (catalyst9/plugin-signing-key/v1)."
        warn "The plugin signing key is a Catalyst9 internal key, not distributed to customers."
        warn "Re-running with --no-sign automatically."
        NO_SIGN=1
    else
        ok "plugin signing key: found in KPM (catalyst9/plugin-signing-key/v1)"
    fi
fi

if [[ $NO_SIGN -eq 1 ]]; then
    warn "--no-sign: binaries will be installed without .sig sidecars."
    warn "The agentkms-dev host (NewHost, no verifier) accepts unsigned plugins with a warning."
    warn "Production hosts configured with NewHostWithVerifier will REJECT these binaries."
fi

# ─── Plugin directory ─────────────────────────────────────────────────────────

say "Ensuring plugin directory exists"
if [[ -d "${PLUGIN_DIR}" ]]; then
    ok "plugin dir: ${PLUGIN_DIR} (exists)"
else
    mkdir -p "${PLUGIN_DIR}"
    chmod 0750 "${PLUGIN_DIR}"
    ok "plugin dir: ${PLUGIN_DIR} (created)"
fi

# ─── Inline Ed25519 signer (reused across plugins) ───────────────────────────

SIGN_TOOL_SRC=""
if [[ $NO_SIGN -eq 0 ]]; then
    SIGN_TOOL_SRC="${TMPDIR:-/tmp}/c9-plugin-sign.go"
    cat > "${SIGN_TOOL_SRC}" << 'GOSIGN'
// c9-plugin-sign.go — one-shot Ed25519 signer for agentkms plugin binaries.
// Usage: go run c9-plugin-sign.go <binary-path> <sig-output-path>
// Reads 64-byte raw Ed25519 private key from stdin (no PEM wrapping).
// Writes 64-byte raw signature to sig-output-path.
package main

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: c9-plugin-sign <binary> <sig-output>")
		os.Exit(1)
	}
	binaryPath := os.Args[1]
	sigPath := os.Args[2]

	privKeyBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read private key: %v\n", err)
		os.Exit(1)
	}
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "invalid private key: expected %d bytes, got %d\n",
			ed25519.PrivateKeySize, len(privKeyBytes))
		os.Exit(1)
	}

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read binary: %v\n", err)
		os.Exit(1)
	}

	sig := ed25519.Sign(ed25519.PrivateKey(privKeyBytes), data)

	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write sig: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "signed %s -> %s (%d bytes)\n", binaryPath, sigPath, len(sig))
}
GOSIGN
fi

# ─── build_and_install <cmd-name> <binary-name> ───────────────────────────────
#
# Builds ./cmd/<cmd-name>/ and installs the binary to PLUGIN_DIR.
# Signs if NO_SIGN=0.

build_and_install() {
    local cmd_name="$1"
    local binary_name="$2"
    local build_out="${TMPDIR:-/tmp}/${binary_name}"
    local cmd_pkg="./cmd/${cmd_name}/"

    say "Building ${binary_name}"

    if [[ $REBUILD -eq 0 ]] && [[ -f "${build_out}" ]]; then
        skip "binary already built at ${build_out} (use --rebuild to force)"
    else
        (
            cd "${REPO_ROOT}"
            go build -o "${build_out}" "${cmd_pkg}"
        )
        ok "binary: ${build_out}"
        ok "size:   $(du -sh "${build_out}" | cut -f1)"
    fi

    # Sign (optional)
    local sig_file="${build_out}.sig"
    local dest_binary="${PLUGIN_DIR}/${binary_name}"
    local dest_sig="${dest_binary}.sig"

    if [[ $NO_SIGN -eq 0 ]]; then
        say "Signing ${binary_name} with Ed25519 plugin signing key"
        kpm get "catalyst9/plugin-signing-key/v1" \
            | go run "${SIGN_TOOL_SRC}" "${build_out}" "${sig_file}"
        ok "signature: ${sig_file} ($(wc -c < "${sig_file}" | tr -d ' ') bytes)"
    else
        rm -f "${sig_file}"
    fi

    # Install binary
    say "Installing ${binary_name} to plugin directory"
    cp "${build_out}" "${dest_binary}"
    chmod 0755 "${dest_binary}"
    ok "binary installed: ${dest_binary}"
    ok "permissions: $(ls -la "${dest_binary}" | awk '{print $1, $3, $4}')"

    # Install or remove sig
    if [[ $NO_SIGN -eq 0 ]] && [[ -f "${sig_file}" ]]; then
        cp "${sig_file}" "${dest_sig}"
        chmod 0644 "${dest_sig}"
        ok "signature installed: ${dest_sig}"
    else
        if [[ -f "${dest_sig}" ]]; then
            rm -f "${dest_sig}"
            ok "stale signature removed: ${dest_sig}"
        fi
    fi
}

# ─── Build and install each plugin ───────────────────────────────────────────

build_and_install "agentkms-plugin-github"    "agentkms-plugin-github"
build_and_install "agentkms-plugin-gh-secret" "agentkms-plugin-gh-secret"

# Cleanup temp signer
if [[ -n "${SIGN_TOOL_SRC}" ]] && [[ -f "${SIGN_TOOL_SRC}" ]]; then
    rm -f "${SIGN_TOOL_SRC}"
fi

# ─── Remote deployment hint ───────────────────────────────────────────────────

if [[ -n "${REMOTE_HOST:-}" ]]; then
    REMOTE_DIR="${REMOTE_PLUGIN_DIR:-/home/bert/.agentkms/plugins}"
    say "Remote deployment (REMOTE_HOST=${REMOTE_HOST})"
    ok "Sync command:"
    ok "  rsync -avz \\"
    ok "    '${PLUGIN_DIR}/agentkms-plugin-github' \\"
    ok "    '${PLUGIN_DIR}/agentkms-plugin-gh-secret' \\"
    if [[ $NO_SIGN -eq 0 ]]; then
        ok "    '${PLUGIN_DIR}/agentkms-plugin-github.sig' \\"
        ok "    '${PLUGIN_DIR}/agentkms-plugin-gh-secret.sig' \\"
    fi
    ok "    '${REMOTE_HOST}:${REMOTE_DIR}/'"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────

echo
say "Done — OSS plugins installed"
ok "plugin dir:      ${PLUGIN_DIR}"
ok "github vender:   ${PLUGIN_DIR}/agentkms-plugin-github"
ok "gh-secret dest:  ${PLUGIN_DIR}/agentkms-plugin-gh-secret"
if [[ $NO_SIGN -eq 0 ]]; then
    ok "signatures:      installed (.sig sidecars)"
else
    warn "no .sig sidecars — host must be configured without a verifier (--no-sign mode)"
fi
echo
ok "Prerequisites for T6 demo:"
ok "  1. Create ~/.agentkms/plugins/github-apps.yaml (see deploy runbook)"
ok "  2. Export KPM private keys to filesystem paths listed in github-apps.yaml"
ok "  3. Run: agentkms-dev serve"
ok "  4. Check logs for '[github-plugin] registered app' and '[gh-secret-plugin] loaded'"
ok "  5. Continue with runbook-T6-demo.md §5 (register credentials)"
