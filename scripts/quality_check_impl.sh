#!/usr/bin/env bash
# quality_check.sh — Code Quality Gate
#
# Generic quality gate for Go and TypeScript projects.
# Parameterized via environment variables (see defaults below).
#
# Usage:
#   bash quality_check.sh                          # from project root
#   COVERAGE_MIN=90 bash quality_check.sh          # custom general threshold
#   SECURITY_COVERAGE_MIN=95 bash quality_check.sh # custom security threshold
#
# Environment variables:
#   COVERAGE_MIN            General package coverage threshold (default: 80)
#   SECURITY_COVERAGE_MIN   Security package coverage threshold (default: 85)
#   SECURITY_PACKAGES       Glob for security packages (default: internal/auth*,internal/policy*,internal/audit*)
#   INTEGRATION_BUILD_TAG   Build tag for integration-only tests (default: integration)
#   VET_CMD                 Static analysis command (default: auto-detected)
#
# Exit 0 = all checks pass.  Exit 1 = one or more failures.

set -uo pipefail

# ── Defaults (overridable via environment) ────────────────────────────────────
COVERAGE_MIN="${COVERAGE_MIN:-80}"
SECURITY_COVERAGE_MIN="${SECURITY_COVERAGE_MIN:-85}"
SECURITY_PACKAGES="${SECURITY_PACKAGES:-internal/auth*,internal/policy*,internal/audit*}"
INTEGRATION_BUILD_TAG="${INTEGRATION_BUILD_TAG:-integration}"
VET_CMD="${VET_CMD:-}"

# ── Helpers ───────────────────────────────────────────────────────────────────
FAIL=0
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
fail() { printf "  \033[31m✗\033[0m %s\n" "$*"; FAIL=1; }

# Detect project type
detect_project() {
  if [ -f "go.mod" ]; then
    echo "go"
  elif [ -f "package.json" ]; then
    echo "ts"
  elif [ -f "Cargo.toml" ]; then
    echo "rust"
  elif [ -f "pyproject.toml" ] || [ -f "setup.py" ]; then
    echo "python"
  else
    echo "unknown"
  fi
}

PROJECT_NAME="$(basename "$(pwd)")"
PROJECT_TYPE="$(detect_project)"

echo "Quality Gate — ${PROJECT_NAME} (${PROJECT_TYPE})"
echo "──────────────────────────────────────────────────────────────"

# ── 1. Static Analysis ───────────────────────────────────────────────────────
echo ""
echo "1. Static analysis"

if [ -n "$VET_CMD" ]; then
  if eval "$VET_CMD" 2>&1; then
    ok "static analysis clean"
  else
    fail "static analysis reported issues"
  fi
else
  case "$PROJECT_TYPE" in
    go)
      if command -v go >/dev/null 2>&1; then
        if go vet ./... 2>&1; then
          ok "go vet clean"
        else
          fail "go vet reported issues"
        fi
      else
        ok "go not found — skipping vet"
      fi
      ;;
    ts)
      if [ -f "node_modules/.bin/tsc" ]; then
        if npx tsc --noEmit 2>&1; then
          ok "tsc clean"
        else
          fail "tsc reported issues"
        fi
      elif command -v eslint >/dev/null 2>&1; then
        if eslint . --ext .ts,.tsx 2>&1; then
          ok "eslint clean"
        else
          fail "eslint reported issues"
        fi
      else
        ok "no type checker or linter found — skipping"
      fi
      ;;
    *)
      ok "no static analysis tool configured — set VET_CMD"
      ;;
  esac
fi

# ── 2. Coverage ──────────────────────────────────────────────────────────────
echo ""
echo "2. Coverage (general ≥ ${COVERAGE_MIN}%, security ≥ ${SECURITY_COVERAGE_MIN}%)"

run_coverage=0
case "$PROJECT_TYPE" in
  go)
    command -v go >/dev/null 2>&1 && run_coverage=1
    ;;
  ts)
    [ -f "node_modules/.bin/jest" ] && run_coverage=1
    ;;
esac

if [ "$run_coverage" -eq 0 ]; then
  ok "no coverage tool found — skipping"
else
  case "$PROJECT_TYPE" in
    go)
      # Read module path for prefix stripping
      module_path="$(head -1 go.mod | awk '{print $2}')"
      # shellcheck disable=SC2086
      while IFS= read -r line; do
        # Only process lines where $2 is a full package path
        rawpkg=$(echo "$line" | awk '{print $2}')
        echo "$rawpkg" | grep -q "^${module_path}" || continue

        # Strip module prefix
        pkg="${rawpkg#"${module_path}"/}"
        pct=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+%' | tr -d '%')
        [ -z "$pct" ] && continue

        # Skip cmd/ packages (entry points, no tests by design)
        echo "$pkg" | grep -q '^cmd/' && continue

        # Skip integration-only packages
        pkgdir="$pkg"
        if grep -rql "//go:build ${INTEGRATION_BUILD_TAG}" "$pkgdir/" 2>/dev/null; then
          ok "$(printf '%-42s' "$pkg") ${pct}% (integration-only — exempt)"
          continue
        fi

        # Determine threshold
        min="$COVERAGE_MIN"
        # shellcheck disable=SC2254
        case "$pkg" in
          $SECURITY_PACKAGES) min="$SECURITY_COVERAGE_MIN" ;;
        esac

        if awk "BEGIN{exit ($pct >= $min)?0:1}"; then
          ok "$(printf '%-42s' "$pkg") ${pct}% (min ${min}%)"
        else
          fail "$(printf '%-42s' "$pkg") ${pct}% < ${min}% — add tests"
        fi
      done < <(go test -count=1 -cover ./... 2>/dev/null | grep "coverage:")
      ;;
    ts)
      if npx jest --coverage --silent 2>/dev/null; then
        # Parse jest coverage summary
        if [ -f "coverage/coverage-summary.json" ]; then
          # Extract per-file coverage — simplified check
          ok "jest coverage complete (check coverage/ directory for details)"
        else
          ok "jest coverage ran"
        fi
      else
        fail "jest coverage reported failures"
      fi
      ;;
  esac
fi

# ── 3. Exported Functions → Test Files ───────────────────────────────────────
echo ""
echo "3. Exported functions → test files"

any_untested=0
case "$PROJECT_TYPE" in
  go)
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
    ;;
  ts)
    for dir in $(find src lib internal pkg -mindepth 1 -maxdepth 2 -type d 2>/dev/null | sort); do
      n_exp=$(grep -rl "export " "$dir/" --include="*.ts" --include="*.tsx" 2>/dev/null | \
              grep -v ".test." | grep -v ".spec." | wc -l | tr -d ' ')
      n_tests=$(find "$dir/" -maxdepth 1 \( -name "*.test.ts" -o -name "*.test.tsx" -o -name "*.spec.ts" -o -name "*.spec.tsx" \) 2>/dev/null | wc -l | tr -d ' ')
      if [ "$n_exp" -gt 0 ] && [ "$n_tests" -eq 0 ]; then
        fail "$dir — $n_exp file(s) with exports, 0 test files"
        any_untested=1
      elif [ "$n_exp" -gt 0 ]; then
        ok "$(printf '%-38s' "$dir") $n_tests test file(s)"
      fi
    done
    ;;
  *)
    ok "export check only supported for Go and TypeScript"
    ;;
esac

[ "$any_untested" -eq 0 ] && ok "all packages with exports have test files"

# ── 4. t.Skip Audit (Go only) ───────────────────────────────────────────────
echo ""
echo "4. Test skip audit"

any_bad=0
case "$PROJECT_TYPE" in
  go)
    echo "  Checking t.Skip / t.Skipf — every skip needs // TODO(#NNN): on the preceding line"
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
    ;;
  ts)
    echo "  Checking .skip() — every skip needs a // TODO(#NNN): comment"
    while IFS=: read -r file lineno _rest; do
      prev=$(awk -v n="$((lineno-1))" 'NR==n{print;exit}' "$file" 2>/dev/null)
      if echo "$prev" | grep -q "TODO(#"; then
        ok "$file:$lineno — linked issue present"
      else
        fail "$file:$lineno — missing // TODO(#NNN): reason"
        any_bad=1
      fi
    done < <(grep -rn '\.skip(' . --include="*.ts" --include="*.tsx" 2>/dev/null | grep -v "node_modules")

    if [ "$any_bad" -eq 0 ] && \
       ! grep -rq '\.skip(' . --include="*.ts" --include="*.tsx" 2>/dev/null | grep -v "node_modules"; then
      ok "no .skip() calls found"
    fi
    ;;
  *)
    ok "skip audit only supported for Go and TypeScript"
    ;;
esac

# ── Result ────────────────────────────────────────────────────────────────────
echo ""
echo "──────────────────────────────────────────────────────────────"
if [ "$FAIL" -eq 0 ]; then
  printf "\033[32mQuality gate: PASS\033[0m\n"
else
  printf "\033[31mQuality gate: FAIL — address all ✗ items above\033[0m\n"
  exit 1
fi
