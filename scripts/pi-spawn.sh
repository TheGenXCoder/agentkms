#!/usr/bin/env bash
# scripts/pi-spawn.sh — Spawn Pi subprocesses with model tiering + token tracking
#
# Usage:
#   scripts/pi-spawn.sh <tier> <prompt-or-file>
#   scripts/pi-spawn.sh <tier> -f <file>     # read prompt from file
#
# Tiers:
#   worker  — Local Ollama (qwen3-coder-next:latest). Implementation/coding tasks.
#   qa      — Claude Sonnet. Quality checks, testing, code review.
#   review  — Claude Opus. Adversarial security review.
#
# Model selection follows time-of-day rules:
#   11am-3pm PDT → Antigravity-scoped Claude (rate limit avoidance)
#   Outside       → Anthropic-direct Claude
#   worker tier   → Always local Ollama (no provider switch)
#
# Token tracking:
#   Every spawn logs tokens in/out to $TOKEN_LOG (default: .pi/token-usage.jsonl)
#   Format: {"ts":"...","tier":"...","model":"...","provider":"...","tokens_in":N,...}

set -euo pipefail

TOKEN_LOG="${TOKEN_LOG:-.pi/token-usage.jsonl}"
mkdir -p "$(dirname "$TOKEN_LOG")"

TIER="${1:?Usage: pi-spawn.sh <worker|qa|review> <prompt>}"
shift

# Handle -f <file> or inline prompt
if [ "${1:-}" = "-f" ]; then
  shift
  PROMPT_FILE="${1:?Missing file after -f}"
  PROMPT=$(cat "$PROMPT_FILE")
else
  PROMPT="$*"
fi

# ── Model selection ──────────────────────────────────────────────────────────

select_model() {
  local tier="$1"
  local hour
  hour=$(TZ=America/Los_Angeles date +%H)

  case "$tier" in
    worker)
      echo "ollama/devstral:24b"
      ;;
    qa)
      if [ "$hour" -ge 11 ] && [ "$hour" -lt 15 ]; then
        echo "google-antigravity/claude-sonnet-4-6"
      else
        echo "anthropic/claude-sonnet-4-6"
      fi
      ;;
    review)
      if [ "$hour" -ge 11 ] && [ "$hour" -lt 15 ]; then
        echo "google-antigravity/claude-opus-4-6-thinking"
      else
        echo "anthropic/claude-opus-4-6"
      fi
      ;;
    *)
      echo >&2 "ERROR: Unknown tier: $tier (use worker|qa|review)"
      exit 1
      ;;
  esac
}

MODEL=$(select_model "$TIER")
PROVIDER=$(echo "$MODEL" | cut -d/ -f1)
MODEL_ID=$(echo "$MODEL" | cut -d/ -f2)

echo "┌─ pi-spawn: tier=$TIER model=$MODEL" >&2
echo "│  prompt: ${PROMPT:0:80}..." >&2

# ── Temp session dir for token capture ───────────────────────────────────────

SESSION_DIR=$(mktemp -d /tmp/pi-spawn-XXXXXX)
trap 'rm -rf "$SESSION_DIR"' EXIT

# ── Run Pi in print mode (one-shot) ─────────────────────────────────────────

START_MS=$(python3 -c "import time; print(int(time.time()*1000))")

RESPONSE=$(echo "$PROMPT" | pi --print \
  --model "$MODEL" \
  --session-dir "$SESSION_DIR" \
  --no-prompt-templates \
  2>/dev/null) || true

END_MS=$(python3 -c "import time; print(int(time.time()*1000))")
ELAPSED_MS=$((END_MS - START_MS))

# ── Extract token usage from session file ────────────────────────────────────

SESSION_FILE=$(find "$SESSION_DIR" -name "*.jsonl" -type f 2>/dev/null | head -1)

if [ -n "$SESSION_FILE" ]; then
  USAGE=$(SESSION_FILE="$SESSION_FILE" TIER="$TIER" MODEL_ID="$MODEL_ID" PROVIDER="$PROVIDER" ELAPSED_MS="$ELAPSED_MS" \
    python3 << 'PYEOF'
import json, os, datetime

tokens_in = tokens_out = cache_read = cache_write = 0
cost_total = 0.0
model_used = ""
provider_used = ""
sfpath = os.environ.get('SESSION_FILE', '')

if sfpath:
    with open(sfpath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except:
                continue
            msg = entry.get('message', {})
            usage = msg.get('usage', entry.get('usage', {}))
            if usage:
                tokens_in += usage.get('input', 0)
                tokens_out += usage.get('output', 0)
                cache_read += usage.get('cacheRead', 0)
                cache_write += usage.get('cacheWrite', 0)
                c = usage.get('cost', {})
                if isinstance(c, dict):
                    cost_total += c.get('total', 0)
                elif isinstance(c, (int, float)):
                    cost_total += c
            if msg.get('model'):
                model_used = msg['model']
            if msg.get('provider'):
                provider_used = msg['provider']

result = {
    'ts': datetime.datetime.utcnow().isoformat() + 'Z',
    'tier': os.environ.get('TIER', ''),
    'model': model_used or os.environ.get('MODEL_ID', ''),
    'provider': provider_used or os.environ.get('PROVIDER', ''),
    'tokens_in': tokens_in,
    'tokens_out': tokens_out,
    'cache_read': cache_read,
    'cache_write': cache_write,
    'cost': round(cost_total, 6),
    'elapsed_ms': int(os.environ.get('ELAPSED_MS', 0)),
}
print(json.dumps(result))
PYEOF
  ) || USAGE=""

  if [ -n "$USAGE" ]; then
    echo "$USAGE" >> "$TOKEN_LOG"
    # Summary to stderr
    echo "$USAGE" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'└─ tokens: in={d[\"tokens_in\"]:,} out={d[\"tokens_out\"]:,} cache={d[\"cache_read\"]:,} cost=\${d[\"cost\"]:.4f} elapsed={d[\"elapsed_ms\"]/1000:.1f}s')
" >&2 2>/dev/null || echo "└─ tokens: (parse error)" >&2
  else
    echo "└─ tokens: (no usage data in session)" >&2
  fi
else
  echo "└─ tokens: (no session file found)" >&2
fi

# ── Output ───────────────────────────────────────────────────────────────────

echo "$RESPONSE"
