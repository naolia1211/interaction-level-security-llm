#!/usr/bin/env bash
# One-time setup of the testbed on macOS/Linux. Run from the testbed folder: bash scripts/setup.sh
set -euo pipefail
cd "$(dirname "$0")/.."

TAU2_COMMIT=96a3ef92329baf908ffe9dfe188cea34e8701d2a   # pinned: same commit as the survey in the report

command -v uv >/dev/null || { echo "Installing uv..."; curl -LsSf https://astral.sh/uv/install.sh | sh; export PATH="$HOME/.local/bin:$PATH"; }

if [ ! -d tau2-bench ]; then
  git clone https://github.com/sierra-research/tau2-bench.git
fi
git -C tau2-bench fetch -q origin
git -C tau2-bench checkout -q "$TAU2_COMMIT"

# Python 3.12: the core package imports audio code that needs the stdlib 'audioop' (removed in 3.13).
(cd tau2-bench && uv sync --frozen --python 3.12)
# The core install also misses 'websockets' at this commit (imported by tau2.voice at startup).
uv pip install -q -p tau2-bench/.venv/bin/python websockets

[ -f .env ] || cp .env.example .env
echo
echo "Setup done. Next:"
echo "  1) put your key in .env"
echo "  2) tau2-bench/.venv/bin/python scripts/selftest.py"
echo "  3) tau2-bench/.venv/bin/python scripts/run_baseline.py --set attacks --limit 2"
