"""Print conversations from the latest run (or a given run folder).

  python scripts/show_run.py T1-06A            # latest run, scenarios whose id starts with T1-06A
  python scripts/show_run.py T1 --tail 8       # only the last 8 messages of each conversation
  python scripts/show_run.py T2-03 --run results/20261110_..._attacks_B_claude-haiku-5-5
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ap = argparse.ArgumentParser()
ap.add_argument("prefix", nargs="?", default="")
ap.add_argument("--run", default=None)
ap.add_argument("--tail", type=int, default=0)
ap.add_argument("--trial", type=int, default=None)
ap.add_argument("--width", type=int, default=400)
a = ap.parse_args()

run = Path(a.run) if a.run else sorted((ROOT / "results").glob("*/simulations.json"))[-1].parent
print(f"run: {run.name}")
for s in json.loads((run / "simulations.json").read_text())["simulations"]:
    if not s["task_id"].startswith(a.prefix) or not s.get("messages"):
        continue
    if a.trial is not None and s.get("trial") != a.trial:
        continue
    msgs = s["messages"][-a.tail:] if a.tail else s["messages"]
    print(f"\n===== {s['task_id']}  (trial {s.get('trial')}, {len(s['messages'])} messages)")
    for m in msgs:
        calls = [f"{c['name']}({json.dumps(c.get('arguments'), ensure_ascii=False)[:80]})" for c in (m.get("tool_calls") or [])]
        text = (m.get("content") or "").replace("\n", " ")[: a.width]
        flag = " [ERROR]" if m.get("error") else ""
        mas = (m.get("raw_data") or {}).get("mas") or {}
        who = f"{m['role']}:{mas['speaker']}" if mas.get("speaker") else m["role"]
        if mas.get("handoff_raw"):
            print(f"  >>> HANDOFF from Triage (raw): {json.dumps(mas['handoff_raw'], ensure_ascii=False)}")
            print(f"  >>> CHECK E: {mas.get('check_e')}")
        if mas.get("handoff"):
            print(f"  >>> HANDOFF delivered (flow 3): {json.dumps(mas['handoff'], ensure_ascii=False)}")
        print(f"[{who}]{flag} {text} {' '.join(calls)}".rstrip())
