#!/usr/bin/env bash
# Pilot 2: more trials on every configuration, for the interaction-level assessment (O3) and the defense
# comparison. Runs one step after another; a finished step is skipped when the script is restarted.
#
#   bash scripts/run_all.sh            # everything (several hours: leave it running)
#   bash scripts/run_all.sh t3         # only the steps whose name contains "t3"
#   TRIALS=3 bash scripts/run_all.sh   # change trials for attack steps
set -u
cd "$(dirname "$0")/.."
PY=tau2-bench/.venv/bin/python
TRIALS=${TRIALS:-3}
ONLY=${1:-}
EXTRA=${MOCK:+--mock}                  # MOCK=1 bash scripts/run_all.sh : dry run of the whole plan, no API
LOG=results/run_all.log
DONE=results/.done${MOCK:+_mock}
mkdir -p "$DONE"

step() {   # step <name> <run_baseline args...>
  local name=$1; shift
  [[ -n "$ONLY" && "$name" != *"$ONLY"* ]] && return
  if [[ -f $DONE/$name ]]; then echo "skip $name (done)"; return; fi
  echo "=== $(date '+%F %T') $name: $*" | tee -a "$LOG"
  if $PY scripts/run_baseline.py "$@" $EXTRA 2>&1 | tee -a "$LOG" | grep -E "^\s+(T[0-9]|[0-9])|Saved to|No valid run|API call failed"; then
    grep -q "No valid run" <(tail -n 40 "$LOG") || touch "$DONE/$name"
  fi
}

# 1. Handoff attacks (T3) on the two-agent system, every defense
step t3_mas_none  --set attacks --split t3 --agent mas --defense none --trials "$TRIALS"
step t3_mas_E     --set attacks --split t3 --agent mas --defense E    --trials "$TRIALS"
step t3_mas_B     --set attacks --split t3 --agent mas --defense B    --trials "$TRIALS"
step t3_mas_BE    --set attacks --split t3 --agent mas --defense BE   --trials "$TRIALS"

# 2. Direct and indirect attacks (T1, T2) on the two-agent system: does the handoff make them easier?
step v1_mas_none  --set attacks --split v1 --agent mas --defense none --trials 2
step v2_mas_none  --set attacks --split v2 --agent mas --defense none --trials 2
step v1_mas_BE    --set attacks --split v1 --agent mas --defense BE   --trials 2
step v2_mas_BE    --set attacks --split v2 --agent mas --defense BE   --trials 2

# 3. Same attacks on the single agent (more trials than pilot 1)
step v1_single_none --set attacks --split v1 --defense none --trials 2
step v2_single_none --set attacks --split v2 --defense none --trials 2
step v1_single_B    --set attacks --split v1 --defense B    --trials 2
step v2_single_B    --set attacks --split v2 --defense B    --trials 2

# 4. Normal customers: utility and over-refusal (OR) of each configuration
step benign_single_none --set benign --limit 20 --defense none
step benign_single_B    --set benign --limit 20 --defense B
step benign_mas_none    --set benign --limit 20 --agent mas --defense none
step benign_mas_BE      --set benign --limit 20 --agent mas --defense BE

echo "=== $(date '+%F %T') finished" | tee -a "$LOG"
[[ -n "${MOCK:-}" ]] && exit 0
$PY scripts/summarize.py
$PY scripts/assess_interactions.py --out results/interactions.jsonl
