"""Merge attack runs into ASR tables, one table per defense configuration (valid runs only).

  python scripts/summarize.py                      # every attacks run in results/
  python scripts/summarize.py results/A results/B  # selected runs
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
GOALS = json.loads((ROOT / "thesis_sec" / "data" / "attack_goals.json").read_text())


def relayed(handoffs, pattern):
    import re
    fields = ("intent", "order_id", "reason", "summary")
    return any(re.search(pattern, " ".join(str(h.get(k, "")) for k in fields), re.I) for h in handoffs)
dirs = [Path(p) for p in sys.argv[1:]] or sorted(p for p in (ROOT / "results").glob("*_attacks_*") if "mock" not in p.name)

by_def = defaultdict(list)
for d in dirs:
    f = d / "evaluation.json"
    if not f.exists():
        continue
    data = json.loads(f.read_text())
    cfg = data["summary"]["config"]
    defense = f'agent={cfg.get("agent", "single")}, defense={cfg.get("defense", "none")}'
    for r in data["runs"]:
        if r.get("status", "ok") == "ok" and r.get("turns", 0) > 0 and "success" in r:
            by_def[defense].append(r)

for defense, rows in sorted(by_def.items()):
    per_task, per_threat = defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0])
    reads, denials, relays = defaultdict(int), defaultdict(int), defaultdict(int)
    for r in rows:
        mon = r.get("monitors", {})
        per_task[r["task_id"]][0] += r["success"]
        per_task[r["task_id"]][1] += 1
        threat = r.get("threat") or r["task_id"].split("-")[0]
        per_threat[threat][0] += r["success"]
        per_threat[threat][1] += 1
        reads[r["task_id"]] += bool(mon.get("cross_user_read"))
        denials[r["task_id"]] += len(mon.get("gateway_denials", []))
        pattern = GOALS.get(r["task_id"], {}).get("relay_pattern")
        if pattern:   # recomputed from stored handoffs, so older runs use the current definition too
            relays[r["task_id"]] += relayed(mon.get("handoffs", []), pattern)

    print(f"\n=== {defense}  ({len(rows)} valid conversations)")
    print(f"{'scenario':<38} {'ASR':>9}   cross-user reads   gateway denials   handoff relay")
    for t in sorted(per_task):
        s, n = per_task[t]
        relay = f"{relays[t]}/{n}" if t.startswith("T3") else "-"
        print(f"{t:<38} {s}/{n:<3} {s / n:>4.0%}   {reads[t]}/{n:<15} {denials[t]:<17} {relay}")
    for k in sorted(per_threat):
        s, n = per_threat[k]
        print(f"{k:<38} {s}/{n:<3} {s / n:>4.0%}")
    s_all = sum(v[0] for v in per_threat.values())
    n_all = sum(v[1] for v in per_threat.values())
    r_all = sum(reads.values())
    print(f"{'ALL':<38} {s_all}/{n_all:<3} {s_all / max(n_all, 1):>4.0%}   {r_all}/{n_all}")
