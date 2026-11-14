#!/usr/bin/env bash
# Guided demo, no API calls. Press Enter to move to the next step.
#   bash scripts/demo.sh
cd "$(dirname "$0")/.."
PY=tau2-bench/.venv/bin/python
NONE=${NONE:-results/20261110_105024_attacks_mas_none_claude-haiku-5-5}
BE=${BE:-results/20261110_135548_attacks_mas_BE_claude-haiku-5-5}
TRIAL_NONE=${TRIAL_NONE:-0}
TRIAL_BE=${TRIAL_BE:-1}

step() { echo; echo "────────────────────────────────────────────────────────────────────────"; echo "  $1"; echo "────────────────────────────────────────────────────────────────────────"; [[ -t 0 ]] && read -r -p "  [Enter] " _; }

step "1/5  Automated tests of detectors, gateway (B), handoff check (E), assessor"
$PY scripts/selftest.py 2>&1 | grep -cE "^PASS" | sed 's/^/  checks passed: /'
$PY scripts/selftest.py 2>&1 | tail -1

step "2/5  Results of all runs: attack success per defense, utility on normal tasks"
$PY scripts/summarize.py 2>/dev/null

step "3/5  One attack, raw conversation: T3-01 on the two-agent system, no defense"
$PY scripts/show_run.py T3-01 --trial "$TRIAL_NONE" --run "$NONE" --width 260 2>/dev/null

step "4/5  The same conversation assessed per interaction: Y_P, Y_R -> Z   (then with B + E)"
$PY scripts/assess_interactions.py --show T3-01 --trial "$TRIAL_NONE" --run "$NONE" 2>/dev/null
$PY scripts/assess_interactions.py --show T3-01 --trial "$TRIAL_BE" --run "$BE" 2>/dev/null

step "5/5  All conversations: reference Z vs assessor, and prompt-only / response-only / joint"
$PY scripts/assess_interactions.py 2>/dev/null

step "+    The same assessment as one page: results/report.html"
if [[ -n "${NOOPEN:-}" ]]; then $PY scripts/make_report.py 2>/dev/null; else $PY scripts/make_report.py --open 2>/dev/null; fi
echo
