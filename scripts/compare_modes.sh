#!/usr/bin/env bash
#
# The demo money shot.
#
# Runs the identical scan twice — once against the unhardened agent, once
# against the hardened one — and prints the attack success rate per plugin
# side by side. Same probes, same grader, same assertions; the only variable
# is AGENT_HARDENED.
#
# Usage:
#   ./scripts/compare_modes.sh            # full plugin/strategy set
#   ./scripts/compare_modes.sh --smoke    # cheap version, for a dry run
#
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCAN_ARGS=()
[[ "${1:-}" == "--smoke" ]] && SCAN_ARGS+=(--smoke)

UNHARDENED_OUT="output/unhardened.json"
HARDENED_OUT="output/hardened.json"

mkdir -p output logs

echo
echo "##############################################################################"
echo "#  PASS 1 of 2 — UNHARDENED baseline"
echo "##############################################################################"
./scripts/run_scan.sh --unhardened --output "$UNHARDENED_OUT" "${SCAN_ARGS[@]}"

echo
echo "##############################################################################"
echo "#  PASS 2 of 2 — HARDENED"
echo "##############################################################################"
./scripts/run_scan.sh --hardened --output "$HARDENED_OUT" "${SCAN_ARGS[@]}"

echo
echo "##############################################################################"
echo "#  RESULT"
echo "##############################################################################"
python3 scripts/summarize.py --compare "$UNHARDENED_OUT" "$HARDENED_OUT"

cat <<'NOTE'
  Read this table as: how often did the attack work?

  Every probe, grader and assertion was identical across both passes. The only
  thing that changed is the four controls AGENT_HARDENED turns on — a stricter
  system prompt, authorization on issue_refund, read_internal_note switched off
  for customer sessions, and an output scrubber.

  Rows that barely move are the interesting ones: those are attacks the
  hardening does not actually address, and they are where the next round of
  work belongs.

NOTE
