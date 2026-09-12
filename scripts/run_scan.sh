#!/usr/bin/env bash
#
# Run one red team scan end to end: start the target, generate and execute the
# adversarial probes, tear the target down, print the scorecard.
#
# Usage:
#   ./scripts/run_scan.sh                      # full scan, unhardened
#   ./scripts/run_scan.sh --hardened           # full scan, hardened
#   ./scripts/run_scan.sh --smoke              # cheap pipeline check
#   ./scripts/run_scan.sh --output output/x.json
#
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CONFIG=""
OUTPUT=""
SMOKE=false
HARDENED="${AGENT_HARDENED:-false}"
PORT="${AGENT_PORT:-8000}"
HEALTH_TIMEOUT=30

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hardened)   HARDENED=true; shift ;;
    --unhardened) HARDENED=false; shift ;;
    --smoke)      SMOKE=true; shift ;;
    --config)     CONFIG="$2"; shift 2 ;;
    --output)     OUTPUT="$2"; shift 2 ;;
    -h|--help)    sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Defaults are resolved AFTER parsing so flag order never matters. --smoke
# selects the cheap config but must not override an explicit --output;
# compare_modes.sh passes both, and silently writing each pass to the same
# file would make the comparison compare a run against itself.
if [[ -z "$CONFIG" ]]; then
  if [[ "$SMOKE" == "true" ]]; then
    CONFIG="redteam/promptfooconfig.smoke.yaml"
  else
    CONFIG="redteam/promptfooconfig.yaml"
  fi
fi
if [[ -z "$OUTPUT" ]]; then
  if [[ "$SMOKE" == "true" ]]; then
    OUTPUT="output/smoke.json"
  else
    OUTPUT="output/results.json"
  fi
fi

# --------------------------------------------------------------------------
# 1. Preflight
# --------------------------------------------------------------------------
PROVIDER="${AGENT_MODEL_PROVIDER:-anthropic}"

if [[ "$PROVIDER" == "anthropic" && -z "${ANTHROPIC_API_KEY:-}" ]]; then
  cat >&2 <<'MSG'
ERROR: ANTHROPIC_API_KEY is not set.

A red team scan needs a model key for three separate jobs:
  1. the TARGET agent's own responses,
  2. promptfoo's attacker model, which writes the adversarial probes,
  3. the grader that judges each response.

Set it and re-run:

    export ANTHROPIC_API_KEY=sk-ant-...
    ./scripts/run_scan.sh

To exercise the harness without a key or any spend, run the target with the
deterministic mock backend instead. Probe generation still needs network
access to promptfoo's generation service:

    AGENT_MODEL_PROVIDER=mock ./scripts/run_scan.sh --smoke
MSG
  exit 1
fi

if [[ "$PROVIDER" == "openai" && -z "${OPENAI_API_KEY:-}" ]]; then
  echo "ERROR: AGENT_MODEL_PROVIDER=openai but OPENAI_API_KEY is not set." >&2
  exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "ERROR: config not found: $CONFIG" >&2
  exit 1
fi

PROMPTFOO="npx --no-install promptfoo"
if [[ -x "node_modules/.bin/promptfoo" ]]; then
  PROMPTFOO="node_modules/.bin/promptfoo"
elif ! command -v promptfoo >/dev/null 2>&1; then
  echo "ERROR: promptfoo is not installed. Run: make install" >&2
  exit 1
fi

mkdir -p output logs

# --------------------------------------------------------------------------
# 2. Start the target, and make sure it dies with us
# --------------------------------------------------------------------------
TARGET_PID=""
cleanup() {
  if [[ -n "$TARGET_PID" ]] && kill -0 "$TARGET_PID" 2>/dev/null; then
    echo "  stopping target agent (pid $TARGET_PID)"
    kill "$TARGET_PID" 2>/dev/null || true
    wait "$TARGET_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "=============================================================================="
echo "  Northwind red team scan"
echo "    config    : $CONFIG"
echo "    mode      : $([[ "$HARDENED" == "true" ]] && echo HARDENED || echo UNHARDENED)"
echo "    backend   : $PROVIDER"
echo "    output    : $OUTPUT"
echo "=============================================================================="

echo "  starting target agent on 127.0.0.1:$PORT ..."
AGENT_HARDENED="$HARDENED" \
AGENT_MODEL_PROVIDER="$PROVIDER" \
AGENT_PORT="$PORT" \
  python3 -m target_agent.app > "logs/target-$( [[ "$HARDENED" == "true" ]] && echo hardened || echo unhardened ).log" 2>&1 &
TARGET_PID=$!

deadline=$((SECONDS + HEALTH_TIMEOUT))
until curl -sf --noproxy '*' "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; do
  if ! kill -0 "$TARGET_PID" 2>/dev/null; then
    echo "ERROR: the target agent exited during startup. Last lines of its log:" >&2
    tail -20 logs/target-*.log >&2
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    echo "ERROR: target agent did not become healthy within ${HEALTH_TIMEOUT}s." >&2
    exit 1
  fi
  sleep 0.5
done

ACTUAL_MODE=$(curl -s --noproxy '*' "http://127.0.0.1:$PORT/healthz" \
  | python3 -c "import sys,json; print('HARDENED' if json.load(sys.stdin)['config']['hardened'] else 'UNHARDENED')")
echo "  target healthy (pid $TARGET_PID, reporting $ACTUAL_MODE)"

# --------------------------------------------------------------------------
# 3. Scan
# --------------------------------------------------------------------------
echo "  generating adversarial probes and running the scan ..."
echo

# --no-cache is not optional here. promptfoo keys its cache on provider id and
# prompt, neither of which changes between hardened and unhardened runs — so a
# cached run would replay the unhardened answers into the hardened scan and
# quietly report a perfect improvement that never happened.
set +e
$PROMPTFOO redteam run \
  --config "$CONFIG" \
  --output "$OUTPUT" \
  --no-cache
SCAN_STATUS=$?
set -e

if [[ ! -f "$OUTPUT" ]]; then
  echo >&2
  echo "ERROR: the scan did not produce $OUTPUT (promptfoo exited $SCAN_STATUS)." >&2
  echo "If probe generation failed, check network access to promptfoo's" >&2
  echo "generation service and that your model API key is valid." >&2
  exit 1
fi

# --------------------------------------------------------------------------
# 4. Scorecard
# --------------------------------------------------------------------------
python3 scripts/summarize.py "$OUTPUT" ${SCAN_GATE:+--fail-on-severity "$SCAN_GATE"}
