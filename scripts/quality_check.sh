#!/usr/bin/env bash
# scripts/quality_check.sh — AgentKMS Code Quality Gate
#
# Run from the ROOT OF THE WORKTREE you want to check.
# Example:
#   cd ~/projects/agentkms-auth && bash ../agentkms/scripts/quality_check.sh
#   cd ~/projects/agentkms        && bash scripts/quality_check.sh
#
# Checks:
#   1. go vet — zero issues
#   2. Coverage >= threshold per package (85% for auth/policy/audit, 80% others)
#   3. Every directory under internal/ and pkg/ with exported functions has ≥1 test file
#   4. Every t.Skip/t.Skipf has a preceding "// TODO(#NNN):" comment
#
# Exit 0 = all checks pass.  Exit 1 = one or more failures.

set -uo pipefail

FAIL=0
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
fail() { printf "  \033[31m✗\033[0m %s\n" "$*"; FAIL=1; }

echo "AgentKMS Quality Gate — $(basename "$(pwd)")"
echo "──────────────────────────────────────────────────────────────"

# ── 1. go vet ─────────────────────────────────────────────────────────────────
echo ""
echo "1. go vet"
if go vet ./... 2>&1; then
  ok "vet clean"
else
  fail "vet reported issues (see above)"
fi

# ── 2. Coverage thresholds ────────────────────────────────────────────────────
echo ""
echo "2. Coverage (min 85% for auth/policy/audit, 80% for others)"

# Reads "ok  github.com/.../internal/auth  1.2s  coverage: 93.4% of statements"
while IFS= read -r line; do
  # Only process lines that look like: "ok  github.com/...  time  coverage: X%"
  # $2 must start with "github.com" — skip malformed coverage summary lines.
  rawpkg=$(echo "$line" | awk '{print $2}')
  echo "$rawpkg" | grep -q '^github.com' || continue

  pkg=$(echo "$rawpkg" | sed 's|github.com/agentkms/agentkms/||')
  pct=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+%' | tr -d '%')
  [ -z "$pct" ] && continue

  # cmd/* packages have no tests by design — skip coverage check.
  echo "$pkg" | grep -q '^cmd/' && continue
  # If the package directory contains integration test files (//go:build integration),
  # the true coverage requires a live external service.  Exempt such packages from
  # the non-integration coverage threshold.
  pkgdir="$(echo "$rawpkg" | sed 's|github.com/agentkms/agentkms/||')"
  if grep -rql '//go:build integration' "$pkgdir/" 2>/dev/null; then
    ok "$(printf '%-42s' "$pkg") ${pct}% (integration-only package — exempt from threshold)"
    continue
  fi

  # Determine threshold
  min=80
  case "$pkg" in
    internal/auth*|internal/policy*|internal/audit*) min=85 ;;
  esac

  if awk "BEGIN{exit ($pct >= $min)?0:1}"; then
    ok "$(printf '%-42s' "$pkg") ${pct}% (min ${min}%)"
  else
    fail "$(printf '%-42s' "$pkg") ${pct}% < ${min}% — add tests"
  fi
done < <(go test -count=1 -cover ./... 2>/dev/null | grep "coverage:")

# ── 3. Exported functions have test files ─────────────────────────────────────
echo ""
echo "3. Exported functions → test files"

any_untested=0
for dir in $(find internal pkg -mindepth 1 -maxdepth 2 -type d 2>/dev/null | sort); do
  n_exp=$(grep -rl "^func [A-Z]" "$dir/" --include="*.go" 2>/dev/null | \
          grep -v "_test.go" | wc -l | tr -d ' ')
  n_tests=$(find "$dir/" -maxdepth 1 -name "*_test.go" 2>/dev/null | wc -l | tr -d ' ')
  if [ "$n_exp" -gt 0 ] && [ "$n_tests" -eq 0 ]; then
    fail "$dir — $n_exp file(s) with exported funcs, 0 test files"
    any_untested=1
  elif [ "$n_exp" -gt 0 ]; then
    ok "$(printf '%-38s' "$dir") $n_tests test file(s)"
  fi
done
[ "$any_untested" -eq 0 ] && ok "all packages with exported funcs have test files"

# ── 4. t.Skip audit ──────────────────────────────────────────────────────────
echo ""
echo "4. t.Skip / t.Skipf — every skip needs // TODO(#NNN): on the preceding line"

any_bad=0
while IFS=: read -r file lineno _rest; do
  prev=$(awk -v n="$((lineno-1))" 'NR==n{print;exit}' "$file" 2>/dev/null)
  if echo "$prev" | grep -q "TODO(#"; then
    ok "$file:$lineno — linked issue present"
  else
    fail "$file:$lineno — missing // TODO(#NNN): skip until YYYY-MM-DD — reason"
    any_bad=1
  fi
done < <(grep -rn 't\.Skipf\?\b' . --include="*.go" 2>/dev/null | grep -v "^Binary")

if [ "$any_bad" -eq 0 ] && \
   ! grep -rq 't\.Skipf\?\b' . --include="*.go" 2>/dev/null; then
  ok "no t.Skip calls found"
fi

# ── Result ────────────────────────────────────────────────────────────────────
echo ""
echo "──────────────────────────────────────────────────────────────"
if [ "$FAIL" -eq 0 ]; then
  printf "\033[32mQuality gate: PASS\033[0m\n"
else
  printf "\033[31mQuality gate: FAIL — address all ✗ items above\033[0m\n"
  exit 1
fi
