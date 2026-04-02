#!/usr/bin/env bash
# AgentKMS Quality Gate — thin wrapper around the global quality-gate skill.
#
# This file exists so the project's AGENTS.md and CI can reference
# `bash scripts/quality_check.sh` without knowing the global install path.
#
# The global script handles all the actual work. This wrapper sets
# AgentKMS-specific defaults before delegating.

set -euo pipefail

# AgentKMS-specific defaults (overrideable via environment)
export COVERAGE_MIN="${COVERAGE_MIN:-80}"
export SECURITY_COVERAGE_MIN="${SECURITY_COVERAGE_MIN:-85}"
export SECURITY_PACKAGES="${SECURITY_PACKAGES:-internal/auth*,internal/policy*,internal/audit*}"

# Delegate to global skill script
GLOBAL_SCRIPT="$HOME/.pi/agent/skills/quality-gate/scripts/quality_check.sh"

if [ -f "$GLOBAL_SCRIPT" ]; then
  exec bash "$GLOBAL_SCRIPT" "$@"
else
  echo "ERROR: Global quality gate not found at $GLOBAL_SCRIPT" >&2
  echo "Install: mkdir -p ~/.pi/agent/skills/quality-gate/scripts" >&2
  echo "Then copy a quality_check.sh there, or install the quality-gate skill." >&2
  exit 1
fi
