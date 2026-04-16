#!/usr/bin/env bash
# AgentKMS Quality Gate — thin wrapper around the quality-gate implementation.
#
# This file exists so the project's AGENTS.md and CI can reference
# `bash scripts/quality_check.sh` without knowing the implementation path.
#
# Resolution order:
#   1. Vendored implementation at scripts/quality_check_impl.sh (always present,
#      used by CI and any fresh checkout).
#   2. Global quality-gate skill at ~/.pi/agent/skills/quality-gate/scripts/
#      quality_check.sh (used by local dev if the user has it installed; keeps
#      the skill-based workflow working).
#
# The wrapper sets AgentKMS-specific defaults before delegating.

set -euo pipefail

# AgentKMS-specific defaults (overrideable via environment)
export COVERAGE_MIN="${COVERAGE_MIN:-80}"
export SECURITY_COVERAGE_MIN="${SECURITY_COVERAGE_MIN:-85}"
export SECURITY_PACKAGES="${SECURITY_PACKAGES:-internal/auth*,internal/policy*,internal/audit*}"

# Packages whose coverage is gated by hardware availability (CGo/PKCS#11/Secure Enclave).
# These contain code that physically cannot execute in unit tests without a YubiKey or
# Apple Secure Enclave hardware token.  They are excluded from the coverage threshold.
export EXCLUDE_PACKAGES="${EXCLUDE_PACKAGES:-pkg/keystore}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDORED_SCRIPT="${SCRIPT_DIR}/quality_check_impl.sh"
GLOBAL_SCRIPT="${HOME}/.pi/agent/skills/quality-gate/scripts/quality_check.sh"

if [ -f "$VENDORED_SCRIPT" ]; then
  exec bash "$VENDORED_SCRIPT" "$@"
elif [ -f "$GLOBAL_SCRIPT" ]; then
  exec bash "$GLOBAL_SCRIPT" "$@"
else
  echo "ERROR: Neither vendored ($VENDORED_SCRIPT) nor global ($GLOBAL_SCRIPT) quality gate found." >&2
  exit 1
fi
