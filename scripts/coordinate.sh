#!/usr/bin/env bash
# =============================================================================
# AgentKMS Development Coordinator
#
# Manages git worktrees, tmux layout, and Pi agent sessions based on the
# dependency graph defined in docs/backlog.md.
#
# Usage:
#   ./scripts/coordinate.sh setup     — Create worktrees + tmux + launch Pi
#   ./scripts/coordinate.sh status    — Show progress across all streams
#   ./scripts/coordinate.sh open      — Unlock newly available streams
#   ./scripts/coordinate.sh teardown  — Kill tmux + remove all worktrees
#
# The dependency graph is hardcoded here (not parsed from backlog).
# Item status IS read from backlog.md files in each worktree.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PARENT_DIR="$(dirname "$REPO_ROOT")"
PROJECT="$(basename "$REPO_ROOT")"
BACKLOG="$REPO_ROOT/docs/backlog.md"
COORD_CONFIG="$REPO_ROOT/.pi/coord.json"
TMUX_SESSION="$PROJECT"

# Terminal colours (degrading gracefully if not supported)
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# =============================================================================
# Stream Definitions
#
# Variable naming: hyphens in stream names are replaced with underscores
# for variable names. e.g. "pi-pkg" → STREAM_GATE_pi_pkg
#
# STREAM_NAMES     space-separated list of all stream names
# STREAM_BRANCH_*  git branch for each stream
# STREAM_GATE_*    space-separated IDs that must be [x] before stream opens
# STREAM_IDS_*     space-separated backlog IDs owned by this stream
# STREAM_FOCUS_*   initial context message sent to Pi in this stream
# =============================================================================

STREAM_NAMES="main auth backend policy api pi-pkg local-dev"

# ── main ─────────────────────────────────────────────────────────────────────
STREAM_BRANCH_main="main"
STREAM_GATE_main=""
STREAM_IDS_main="F-01 F-02 F-03 F-04 F-05 F-06 F-07 F-08"
STREAM_FOCUS_main="You are on the FOUNDATION stream (main branch). \
Work through F-01 to F-08 in order — these are sequential dependencies that unlock all other streams. \
Key deliverables: Go module init, Backend interface, Auditor interface, AuditEvent struct, \
dev (in-memory) backend, file audit sink, MultiAuditor, and adversarial tests for the Backend contract. \
Run: /coord status to see when downstream streams unlock."

# ── auth ─────────────────────────────────────────────────────────────────────
STREAM_BRANCH_auth="feature/auth-layer"
STREAM_GATE_auth="F-01 F-02 F-03 F-04 F-05 F-06 F-07 F-08"
STREAM_IDS_auth="A-01 A-02 A-03 A-04 A-05 A-06 A-07 A-08 A-09 A-10 A-11 A-12 A-13"
STREAM_FOCUS_auth="You are on the AUTH stream (feature/auth-layer). \
There is EXISTING UNCOMMITTED WORK in this worktree from a previous session. \
Before anything else: run 'go test -race ./...' to see the current state. \
There are 3 known build failures to fix: \
(1) auth.InjectTokenForTest missing from export_test.go — referenced in api/auth_test.go; \
(2) mustClientCert helper missing — referenced throughout middleware_test.go; \
(3) TestServerTLSConfig_EndToEndMTLS failing — no-cert client is not being rejected. \
Fix all failures, get the full test suite green with 'go test -race ./...', then run \
/coord review and follow the independent review workflow from AGENTS.md before committing. \
Run: /coord next to see your next task."

# ── backend ──────────────────────────────────────────────────────────────────
STREAM_BRANCH_backend="feature/backend-abstraction"
STREAM_GATE_backend="F-01 F-02 F-03 F-04 F-05 F-06 F-07 F-08"
STREAM_IDS_backend="B-01 B-02 B-03 B-04 B-05 B-06 B-07"
STREAM_FOCUS_backend="You are on the BACKEND stream (feature/backend-abstraction). \
There is EXISTING UNCOMMITTED WORK in this worktree: internal/backend/openbao.go and its \
integration test are present. Run 'go test -race ./...' — existing tests pass. \
Review openbao.go: verify it correctly implements the Backend interface contract and that \
no key material is exposed in any return value or error. Then run /coord review and follow \
the independent review workflow from AGENTS.md before committing. \
Run: /coord next to see your next task."

# ── policy ───────────────────────────────────────────────────────────────────
STREAM_BRANCH_policy="feature/policy-engine"
STREAM_GATE_policy="F-01 F-02 F-03 F-04 F-05 F-06 F-07 F-08"
STREAM_IDS_policy="P-01 P-02 P-03 P-04 P-05 P-06 P-07 P-08"
STREAM_FOCUS_policy="You are on the POLICY stream (feature/policy-engine). \
There is EXISTING UNCOMMITTED WORK in this worktree: engine.go, rules.go, loader.go, \
and test YAML fixtures are all present. Run 'go test -race ./...' — all tests currently pass. \
Review the implementation: verify deny-by-default is enforced (empty policy must deny all), \
check that rule scoping is tight (team, key prefix, operation type), and that invalid YAML \
returns an error rather than silently allowing all. Then run /coord review and follow \
the independent review workflow from AGENTS.md before committing. \
Run: /coord next to see your next task."

# ── api ───────────────────────────────────────────────────────────────────────
STREAM_BRANCH_api="feature/api-handlers"
STREAM_GATE_api="F-01 F-02 F-03 F-04 F-05 F-06 F-07 F-08"
STREAM_IDS_api="C-01 C-02 C-03 C-04 C-05 C-06 C-07"
STREAM_FOCUS_api="You are on the API HANDLERS stream (feature/api-handlers). \
There is EXISTING UNCOMMITTED WORK in this worktree: sign.go, encrypt.go, decrypt.go, keys.go, \
server.go, middleware.go, validation.go, errors.go, context.go are all present. \
Run 'go test -race ./...' — all tests currently pass. \
Review the implementation: verify C-06 (no key material in any response, log, or error), \
check that every handler validates input before calling policy or backend, and confirm \
audit events are written for all outcomes including denials. Then run /coord review and \
follow the independent review workflow from AGENTS.md before committing. \
Run: /coord next to see your next task."

# ── pi-pkg ────────────────────────────────────────────────────────────────────
STREAM_BRANCH_pi_pkg="feature/pi-package"
STREAM_GATE_pi_pkg="F-01 F-02 F-03 F-04 F-05 F-06 F-07 F-08"
STREAM_IDS_pi_pkg="PI-01 PI-02 PI-03 PI-04 PI-05 PI-06 PI-07 PI-08 PI-09 PI-10 PI-11 PI-12 PI-13 PI-14 PI-15 PI-16"
STREAM_FOCUS_pi_pkg="You are on the PI PACKAGE stream (feature/pi-package). \
There is EXISTING UNCOMMITTED WORK in this worktree: all 5 TypeScript files are present \
(index.ts, client.ts, identity.ts, provider.ts, tools.ts) plus package.json and SKILL.md. \
Review the implementation against docs/architecture.md section 6: verify that zero crypto \
logic is in the TypeScript layer, that LLM keys only live in the in-memory runtimeKeys map \
(never written to disk), that session_shutdown revokes the server-side token, and that the \
tool_call hook blocks reads to credential paths. Then run /coord review and follow \
the independent review workflow from AGENTS.md before committing. \
Run: /coord next to see your next task."

# ── local-dev ─────────────────────────────────────────────────────────────────
STREAM_BRANCH_local_dev="feature/local-dev"
STREAM_GATE_local_dev="F-01 F-02 F-03 F-04 F-05 F-06 F-07 F-08"
STREAM_IDS_local_dev="D-01 D-02 D-03 D-04 D-05"
STREAM_FOCUS_local_dev="You are on the LOCAL DEV stream (feature/local-dev). \
There is EXISTING UNCOMMITTED WORK in this worktree integrating auth, policy, and API layers. \
The build is currently broken: run 'go test -race ./...' to see failures. \
Known issues: missing 'audit' import in api/middleware.go, handleDecrypt undefined on Server, \
unused imports in api/decrypt.go. Fix all build failures first, then get the full test \
suite green. This stream integrates the most moving parts — verify that the dev server \
enforces the same mTLS + token lifecycle as production with zero shortcuts. \
Then run /coord review and follow the independent review workflow from AGENTS.md before committing. \
Run: /coord next to see your next task."

# =============================================================================
# Helpers
# =============================================================================

# Sanitise stream name to a valid shell variable name component
# "pi-pkg" → "pi_pkg", "local-dev" → "local_dev"
sanitize_name() { echo "${1//-/_}"; }

# Get a stream property via indirect variable lookup
stream_prop() {
  local prop="$1" name="$2"
  local varname="STREAM_${prop}_$(sanitize_name "$name")"
  # Use eval for bash 3.2 compatibility (no nameref)
  eval "printf '%s' \"\${${varname}:-}\""
}

# Compute worktree path for a stream
stream_path() {
  local name="$1"
  if [ "$name" = "main" ]; then echo "$REPO_ROOT"
  else echo "$PARENT_DIR/${PROJECT}-${name}"; fi
}

# Read the status of a single backlog item ID from a given backlog file
# Echoes: done | in-progress | blocked | todo | missing
item_status() {
  local id="$1" backlog="${2:-$BACKLOG}"
  [ -f "$backlog" ] || { echo "missing"; return; }
  local line
  line=$(grep -E "^\| *${id} *\|" "$backlog" 2>/dev/null || true)
  [ -z "$line" ] && { echo "missing"; return; }
  if   echo "$line" | grep -q "\[x\]"; then echo "done"
  elif echo "$line" | grep -q "\[~\]"; then echo "in-progress"
  elif echo "$line" | grep -q "\[!\]"; then echo "blocked"
  else echo "todo"; fi
}

# Returns 0 (true) if all gate IDs are [x] done; 1 (false) otherwise
gate_clear() {
  local gate="$1"
  [ -z "$gate" ] && return 0
  for id in $gate; do
    [ "$(item_status "$id")" = "done" ] || return 1
  done
  return 0
}

# Check if a tmux window exists in the session
tmux_window_exists() {
  tmux list-windows -t "$TMUX_SESSION" -F '#{window_name}' 2>/dev/null \
    | grep -qx "$1"
}

# =============================================================================
# Status Display
# =============================================================================

show_status() {
  echo ""
  printf "${BOLD}  AgentKMS — Stream Status${NC}\n"
  echo "  ──────────────────────────────────────────────────────────────────"
  printf "  %-14s %-7s %-24s %s\n" "Stream" "Gate" "Progress" "Items"
  echo "  ──────────────────────────────────────────────────────────────────"

  for name in $STREAM_NAMES; do
    local gate ids path backlog
    gate=$(stream_prop "GATE" "$name")
    ids=$(stream_prop "IDS" "$name")
    path=$(stream_path "$name")
    backlog="$path/docs/backlog.md"

    local gate_icon
    if gate_clear "$gate"; then gate_icon="${GREEN}open  ${NC}"
    else                        gate_icon="${YELLOW}locked${NC}"; fi

    local done=0 inprog=0 todo=0 blocked=0 total=0
    for id in $ids; do
      total=$((total + 1))
      case "$(item_status "$id" "$backlog")" in
        done)        done=$((done + 1)) ;;
        in-progress) inprog=$((inprog + 1)) ;;
        blocked)     blocked=$((blocked + 1)) ;;
        *)           todo=$((todo + 1)) ;;
      esac
    done

    local pct=0
    [ "$total" -gt 0 ] && pct=$(( (done * 100) / total ))

    # Build progress bar (10 chars)
    local bar="" filled empty
    filled=$(( pct / 10 )); empty=$(( 10 - filled ))
    for _ in $(seq 1 $filled 2>/dev/null || true); do bar="${bar}█"; done
    for _ in $(seq 1 $empty  2>/dev/null || true); do bar="${bar}░"; done
    # Fallback if seq didn't work (macOS seq needs start end)
    while [ "${#bar}" -lt "$filled" ]; do bar="${bar}█"; done
    while [ "${#bar}" -lt 10 ]; do bar="${bar}░"; done

    local extra=""
    [ "$inprog"  -gt 0 ] && extra="${extra} ~${inprog}"
    [ "$blocked" -gt 0 ] && extra="${extra} !${blocked}"
    [ "$todo"    -gt 0 ] && extra="${extra} □${todo}"

    local colour="${NC}"
    [ "$pct" -ge 100 ] && colour="${GREEN}"
    [ "$inprog"  -gt 0 ] && colour="${CYAN}"

    printf "  ${colour}%-14s${NC} ${gate_icon} ${colour}%s${NC} %3d%%  ✓%d/%d%s\n" \
      "$name" "$bar" "$pct" "$done" "$total" "$extra"
  done

  echo "  ──────────────────────────────────────────────────────────────────"
  echo ""
}

# =============================================================================
# Worktree Management
# =============================================================================

ensure_git_repo() {
  if [ ! -d "$REPO_ROOT/.git" ]; then
    echo -e "${CYAN}  Initialising git repo...${NC}"
    git -C "$REPO_ROOT" init -q
    git -C "$REPO_ROOT" add -A
    git -C "$REPO_ROOT" commit -q -m "chore: initial commit" --allow-empty
  fi
}

setup_worktrees() {
  echo -e "${BOLD}Setting up worktrees...${NC}"
  ensure_git_repo

  for name in $STREAM_NAMES; do
    [ "$name" = "main" ] && continue

    local gate path branch
    gate=$(stream_prop "GATE" "$name")
    path=$(stream_path "$name")
    branch=$(stream_prop "BRANCH" "$name")

    if ! gate_clear "$gate"; then
      echo -e "  ${YELLOW}⏸  $name — gate locked${NC}"
      continue
    fi

    if [ -d "$path" ]; then
      echo -e "  ${GREEN}✓  $name — already exists${NC}"
      continue
    fi

    # Create branch if it doesn't exist
    if ! git -C "$REPO_ROOT" show-ref --verify --quiet "refs/heads/$branch" 2>/dev/null; then
      git -C "$REPO_ROOT" branch "$branch" -q
    fi

    git -C "$REPO_ROOT" worktree add "$path" "$branch" -q
    echo -e "  ${GREEN}✓  $name — created ($branch → $path)${NC}"
  done
}

teardown_worktrees() {
  echo -e "${BOLD}Removing worktrees...${NC}"
  for name in $STREAM_NAMES; do
    [ "$name" = "main" ] && continue
    local path
    path=$(stream_path "$name")
    if [ -d "$path" ]; then
      git -C "$REPO_ROOT" worktree remove "$path" --force 2>/dev/null \
        || rm -rf "$path"
      echo -e "  ${GREEN}✓  $name removed${NC}"
    fi
  done
  git -C "$REPO_ROOT" worktree prune 2>/dev/null || true
}

# =============================================================================
# Coord Config (read by Pi coordinator extension)
# =============================================================================

write_coord_config() {
  mkdir -p "$(dirname "$COORD_CONFIG")"

  # Build JSON array of stream objects
  local streams_json="" first=true
  for name in $STREAM_NAMES; do
    local path branch ids_raw focus
    path=$(stream_path "$name")
    branch=$(stream_prop "BRANCH" "$name")
    ids_raw=$(stream_prop "IDS" "$name")
    focus=$(stream_prop "FOCUS" "$name")

    # Convert space-separated IDs to JSON array
    local ids_json="" first_id=true
    for id in $ids_raw; do
      if $first_id; then ids_json="\"$id\""; first_id=false
      else ids_json="${ids_json},\"$id\""; fi
    done

    # Escape focus string for JSON (replace backslash, double-quote, newline)
    focus=$(echo "$focus" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' | tr -d '\n')
    focus="${focus%\\n}"

    local entry="{\"name\":\"$name\",\"branch\":\"$branch\",\"path\":\"$path\",\"ids\":[$ids_json],\"focus\":\"$focus\"}"
    if $first; then streams_json="$entry"; first=false
    else streams_json="${streams_json},$entry"; fi
  done

  printf '{"project":"%s","repoRoot":"%s","streams":[%s]}\n' \
    "$PROJECT" "$REPO_ROOT" "$streams_json" > "$COORD_CONFIG"

  echo -e "  ${GREEN}✓  Wrote .pi/coord.json${NC}"
}

# =============================================================================
# tmux Management
# =============================================================================

setup_tmux() {
  echo -e "${BOLD}Setting up tmux session '$TMUX_SESSION'...${NC}"

  # Kill any existing session cleanly
  tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true

  # Status window — auto-refreshes every 10s using this script itself
  tmux new-session -d -s "$TMUX_SESSION" -n "status" -c "$REPO_ROOT"
  tmux send-keys -t "$TMUX_SESSION:status" \
    "watch -n 10 '\"$SCRIPT_DIR/coordinate.sh\" status 2>&1'" C-m

  local opened=0
  for name in $STREAM_NAMES; do
    local gate path focus
    gate=$(stream_prop "GATE" "$name")
    path=$(stream_path "$name")
    focus=$(stream_prop "FOCUS" "$name")

    gate_clear "$gate" || continue
    [ -d "$path" ] || continue

    tmux new-window -t "$TMUX_SESSION" -n "$name" -c "$path"

    # Launch Pi with stream-specific context baked in as the first message.
    # The coordinator extension (loaded from .pi/extensions/coordinator.ts)
    # also injects context via session_start — this is belt-and-suspenders.
    tmux send-keys -t "$TMUX_SESSION:$name" \
      "pi \"$focus\"" C-m

    opened=$((opened + 1))
  done

  # Focus main stream window (or first available)
  tmux select-window -t "$TMUX_SESSION:main" 2>/dev/null \
    || tmux select-window -t "$TMUX_SESSION:status"

  echo -e "${GREEN}✓  Session '$TMUX_SESSION' ready — $opened stream(s) open${NC}"
  if [ -n "${TMUX:-}" ]; then
    echo -e "   You're inside tmux. Switch with: ${CYAN}tmux switch-client -t $TMUX_SESSION${NC}"
    echo -e "   Return here with:               ${CYAN}tmux switch-client -l${NC}"
  else
    echo -e "   Attach with: ${CYAN}tmux attach -t $TMUX_SESSION${NC}"
  fi
  echo ""
  # Print window list
  echo -e "   Windows:"
  tmux list-windows -t "$TMUX_SESSION" -F '     #{window_index}: #{window_name}' 2>/dev/null || true
  echo ""
}

# Open any newly unlocked streams into the existing tmux session
open_new_streams() {
  if ! tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    echo -e "${YELLOW}No active session. Run 'setup' first.${NC}"
    exit 1
  fi

  echo -e "${BOLD}Checking for newly unlocked streams...${NC}"
  local opened=0

  for name in $STREAM_NAMES; do
    [ "$name" = "main" ] && continue

    local gate path focus
    gate=$(stream_prop "GATE" "$name")
    path=$(stream_path "$name")
    focus=$(stream_prop "FOCUS" "$name")

    gate_clear "$gate" || continue
    tmux_window_exists "$name" && continue  # Already open
    [ -d "$path" ] || continue

    tmux new-window -t "$TMUX_SESSION" -n "$name" -c "$path"
    tmux send-keys -t "$TMUX_SESSION:$name" \
      "pi \"Gate cleared! $focus\"" C-m

    echo -e "  ${GREEN}✓  Opened stream: $name${NC}"
    opened=$((opened + 1))
  done

  if [ "$opened" -eq 0 ]; then
    echo -e "  ${YELLOW}No new streams to open. Check 'status' to see what gates remain.${NC}"
  fi
}

# =============================================================================
# Dependency checks
# =============================================================================

check_deps() {
  local missing=()
  command -v git  >/dev/null 2>&1 || missing+=("git")
  command -v tmux >/dev/null 2>&1 || missing+=("tmux")
  command -v pi   >/dev/null 2>&1 || missing+=("pi  →  npm install -g @mariozechner/pi-coding-agent")

  if [ "${#missing[@]}" -gt 0 ]; then
    echo -e "${RED}Missing dependencies:${NC}"
    for dep in "${missing[@]}"; do echo "  • $dep"; done
    exit 1
  fi
}

# =============================================================================
# Entry point
# =============================================================================

usage() {
  echo ""
  echo -e "  ${BOLD}AgentKMS Coordinator${NC}"
  echo ""
  echo "  Usage: $0 <command>"
  echo ""
  echo "  Commands:"
  echo "    setup     Create worktrees for unlocked streams, write .pi/coord.json,"
  echo "              and launch a tmux session with Pi in each window"
  echo "    status    Print progress table across all streams"
  echo "    open      Add newly unlocked streams to the running tmux session"
  echo "    teardown  Kill tmux session and remove all worktrees"
  echo ""
  echo "  Streams:  $STREAM_NAMES"
  echo ""
  echo "  Gate logic:"
  echo "    main     → always open (no gate)"
  echo "    all others → gate: F-01 through F-08 (foundation must be [x])"
  echo "    api      → also needs A-04 and B-01 for full integration (stubs OK earlier)"
  echo ""
}

main() {
  case "${1:-}" in
    setup)
      check_deps
      setup_worktrees
      write_coord_config
      setup_tmux
      ;;
    status)
      show_status
      ;;
    open)
      check_deps
      setup_worktrees
      write_coord_config
      open_new_streams
      ;;
    teardown)
      tmux kill-session -t "$TMUX_SESSION" 2>/dev/null \
        && echo -e "${GREEN}✓  tmux session killed${NC}" || true
      teardown_worktrees
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
