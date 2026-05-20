#!/usr/bin/env bash
# deploy/scripts/setup-pki-role.sh
#
# Idempotent setup of the Vault/OpenBao PKI engine and agentkms-device role.
#
# Usage:
#   export VAULT_ADDR=https://openbao.openbao.svc.cluster.local:8200
#   export VAULT_TOKEN=<operator-or-root-token>
#   ./deploy/scripts/setup-pki-role.sh
#
# Optional overrides:
#   PKI_MOUNT      — Vault PKI mount path (default: pki)
#   KV_MOUNT       — Vault KV v2 mount for bootstrap tokens (default: kv)
#   TRUST_DOMAIN   — SPIFFE trust domain (default: catalyst9.local)
#   POLICY_NAME    — Vault policy name for agentkms (default: agentkms)
#   ROLE_TTL       — Max cert TTL for agentkms-device role (default: 8760h = 365d)
#
# Prerequisites:
#   - curl and jq must be present on PATH.
#   - VAULT_ADDR and VAULT_TOKEN must be set.
#   - The operator token must have permission to:
#       sys/mounts/*          (enable PKI/KV engines)
#       pki/config/*          (set CA cert and URLs)
#       pki/roles/*           (create roles)
#       sys/policy/*          (read and write policies)
#       kv/config/*           (configure KV v2)
#
# Security note: this script does not print the VAULT_TOKEN value anywhere.
# It sets the TTL/max_ttl to 365 days (8760h) per the Phase 1b spec.
#
# Idempotency:
#   - PKI/KV mounts are only enabled if they do not already exist.
#   - CA root is only generated if /v1/pki/cert/ca returns a 404 / empty cert.
#   - The agentkms-device role is created/updated unconditionally (PUT is safe).
#   - The Vault policy is read, the two required paths are merged in, and the
#     result is written back so pre-existing rules are preserved.

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

VAULT_ADDR="${VAULT_ADDR:?VAULT_ADDR must be set (e.g. https://openbao.openbao.svc.cluster.local:8200)}"
VAULT_TOKEN="${VAULT_TOKEN:?VAULT_TOKEN must be set}"

PKI_MOUNT="${PKI_MOUNT:-pki}"
KV_MOUNT="${KV_MOUNT:-kv}"
TRUST_DOMAIN="${TRUST_DOMAIN:-catalyst9.local}"
POLICY_NAME="${POLICY_NAME:-agentkms}"
ROLE_TTL="${ROLE_TTL:-8760h}"

ROLE_NAME="agentkms-device"

# Suppress curl progress but keep error output.
CURL="curl --silent --show-error --fail-with-body"

vault_request() {
  local method="$1"; local path="$2"; shift 2
  $CURL -X "$method" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    "${VAULT_ADDR}/v1/${path}" "$@"
}

log() { echo "[setup-pki-role] $*" >&2; }
ok()  { echo "[setup-pki-role] OK: $*" >&2; }

# ── Step 1: Enable PKI secrets engine (idempotent) ───────────────────────────

log "Checking PKI mount at ${PKI_MOUNT}/ ..."
if vault_request GET "sys/mounts/${PKI_MOUNT}" > /dev/null 2>&1; then
  ok "PKI mount '${PKI_MOUNT}' already exists."
else
  log "Enabling PKI mount at ${PKI_MOUNT}/ ..."
  vault_request POST "sys/mounts/${PKI_MOUNT}" -d "{
    \"type\": \"pki\",
    \"config\": {
      \"max_lease_ttl\": \"${ROLE_TTL}\"
    }
  }" > /dev/null
  ok "PKI mount '${PKI_MOUNT}' enabled."
fi

# ── Step 2: Configure PKI URLs ───────────────────────────────────────────────

log "Configuring PKI cluster/issuer URLs ..."
vault_request POST "${PKI_MOUNT}/config/urls" -d "{
  \"issuing_certificates\":    \"${VAULT_ADDR}/v1/${PKI_MOUNT}/ca\",
  \"crl_distribution_points\": \"${VAULT_ADDR}/v1/${PKI_MOUNT}/crl\"
}" > /dev/null
ok "PKI URLs configured."

# ── Step 3: Generate root CA if not already present ──────────────────────────

log "Checking for existing root CA ..."
CA_CERT="$($CURL --silent "${VAULT_ADDR}/v1/${PKI_MOUNT}/cert/ca" \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  | jq -r '.data.certificate // ""' 2>/dev/null || true)"

if [ -z "${CA_CERT}" ]; then
  log "No root CA found — generating internal root CA ..."
  vault_request POST "${PKI_MOUNT}/root/generate/internal" -d "{
    \"common_name\":  \"AgentKMS Root CA\",
    \"key_type\":     \"ec\",
    \"key_bits\":     256,
    \"ttl\":          \"${ROLE_TTL}\",
    \"ou\":           \"AgentKMS PKI\",
    \"organization\": \"AgentKMS\"
  }" > /dev/null
  ok "Root CA generated."
else
  ok "Root CA already present — skipping generation."
fi

# ── Step 4: Create / update the agentkms-device role ─────────────────────────

log "Creating/updating PKI role '${ROLE_NAME}' ..."
vault_request POST "${PKI_MOUNT}/roles/${ROLE_NAME}" -d "{
  \"allowed_uri_sans\":       [\"spiffe://*\"],
  \"allow_subdomains\":       true,
  \"allow_any_name\":         true,
  \"enforce_hostnames\":      false,
  \"client_flag\":            true,
  \"server_flag\":            false,
  \"key_usage\":              [\"DigitalSignature\"],
  \"ext_key_usage\":          [\"ClientAuth\"],
  \"ttl\":                    \"${ROLE_TTL}\",
  \"max_ttl\":                \"${ROLE_TTL}\",
  \"no_store\":               false,
  \"require_cn\":             false,
  \"use_csr_sans\":           true,
  \"use_csr_common_name\":    true
}" > /dev/null
ok "Role '${ROLE_NAME}' configured."

# ── Step 5: Enable KV v2 for bootstrap tokens (idempotent) ───────────────────

log "Checking KV mount at ${KV_MOUNT}/ ..."
if vault_request GET "sys/mounts/${KV_MOUNT}" > /dev/null 2>&1; then
  ok "KV mount '${KV_MOUNT}' already exists."
else
  log "Enabling KV v2 mount at ${KV_MOUNT}/ ..."
  vault_request POST "sys/mounts/${KV_MOUNT}" -d "{
    \"type\": \"kv\",
    \"options\": { \"version\": \"2\" }
  }" > /dev/null
  ok "KV mount '${KV_MOUNT}' (v2) enabled."
fi

# ── Step 6: Extend the agentkms Vault policy ─────────────────────────────────
#
# We read the existing policy, append the two new paths if they are not already
# present, and write it back.  This is idempotent.

log "Updating Vault policy '${POLICY_NAME}' ..."

EXISTING_POLICY="$($CURL --silent \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/sys/policy/${POLICY_NAME}" \
  | jq -r '.data.rules // ""' 2>/dev/null || true)"

PKI_SIGN_PATH="${PKI_MOUNT}/sign/${ROLE_NAME}"
PKI_REVOKE_PATH="${PKI_MOUNT}/revoke"

NEW_RULES=""
if ! echo "${EXISTING_POLICY}" | grep -q "\"${PKI_SIGN_PATH}\""; then
  NEW_RULES="${NEW_RULES}
path \"${PKI_SIGN_PATH}\" {
  capabilities = [\"create\", \"update\"]
}
"
fi
if ! echo "${EXISTING_POLICY}" | grep -q "\"${PKI_REVOKE_PATH}\""; then
  NEW_RULES="${NEW_RULES}
path \"${PKI_REVOKE_PATH}\" {
  capabilities = [\"create\", \"update\"]
}
"
fi

KV_BOOTSTRAP_PATH="${KV_MOUNT}/data/bootstrap-tokens/*"
if ! echo "${EXISTING_POLICY}" | grep -q "bootstrap-tokens"; then
  NEW_RULES="${NEW_RULES}
path \"${KV_BOOTSTRAP_PATH}\" {
  capabilities = [\"create\", \"read\", \"update\"]
}
"
fi

COMBINED_RULES="${EXISTING_POLICY}${NEW_RULES}"

if [ -n "${NEW_RULES}" ]; then
  # Escape for JSON transport.
  ESCAPED_RULES="$(echo "${COMBINED_RULES}" | jq -Rs .)"
  vault_request PUT "sys/policy/${POLICY_NAME}" \
    -d "{\"policy\": ${ESCAPED_RULES}}" > /dev/null
  ok "Policy '${POLICY_NAME}' updated with PKI sign/revoke + KV bootstrap paths."
else
  ok "Policy '${POLICY_NAME}' already contains all required paths — no changes."
fi

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "================================================================"
echo "  AgentKMS PKI setup complete."
echo ""
echo "  PKI mount:            ${PKI_MOUNT}/"
echo "  Device role:          ${PKI_MOUNT}/roles/${ROLE_NAME}"
echo "  Sign endpoint:        ${VAULT_ADDR}/v1/${PKI_MOUNT}/sign/${ROLE_NAME}"
echo "  Trust domain:         ${TRUST_DOMAIN}"
echo "  KV mount (tokens):    ${KV_MOUNT}/"
echo "  Vault policy updated: ${POLICY_NAME}"
echo "================================================================"
