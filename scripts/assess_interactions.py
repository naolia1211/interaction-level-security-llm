"""Interaction-level assessment of finished runs (no API calls).

For every conversation: split it into interactions (flows 1, 3, 8), label each with Y_P and Y_R, combine
them into Z, then compare with the reference outcome computed from privileged information.

  python scripts/assess_interactions.py                       # all runs: agreement + ablation tables
  python scripts/assess_interactions.py --show T3-01 --run results/<run>   # per-interaction table
  python scripts/assess_interactions.py --out results/interactions.jsonl   # labelled dataset for O3
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from loguru import logger  # noqa: E402

logger.remove()                                   # keep the demo output readable
logger.add(sys.stderr, level="WARNING")

from tau2.data_model.simulation import Results  # noqa: E402
from tau2.runner.helpers import load_tasks  # noqa: E402

from thesis_sec import assessor, domain, monitors  # noqa: E402

EXCLUDED: list = []   # conversations dropped because the simulated customer left its role
VIEWS = ["prompt_only", "customer_msg_only", "response_only", "joint"]


def macro_f1(pairs: list[tuple[str, str]]) -> float:
    classes = sorted({ref for ref, _ in pairs})
    f1s = []
    for c in classes:
        tp = sum(1 for r, p in pairs if r == c and p == c)
        fp = sum(1 for r, p in pairs if r != c and p == c)
        fn = sum(1 for r, p in pairs if r == c and p != c)
        f1s.append(0.0 if tp == 0 else 2 * tp / (2 * tp + fp + fn))
    return sum(f1s) / max(len(f1s), 1)


def short(text: str, n: int) -> str:
    t = " ".join((text or "").split())
    return t if len(t) <= n else t[: n - 1] + "…"


def collect(runs=None):
    """Assess every conversation of the given runs (default: every non-mock run in results/)."""
    domain.register()
    tasks = {t.id: t for t in domain.get_attack_tasks(None)}
    tasks.update({t.id: t for t in load_tasks("retail", None)})
    goals = domain.load_attack_goals()
    runs = runs or sorted(
        p for p in (ROOT / "results").iterdir() if (p / "simulations.json").exists() and "mock" not in p.name)
    if not runs:
        sys.exit("No run with simulations.json found in results/.")

    cache, convs, lines = {}, [], []
    for run in runs:
        ev_file = run / "evaluation.json"
        if not ev_file.exists():
            continue
        ev = json.loads(ev_file.read_text())
        cfg = ev["summary"]["config"]
        config = f'{cfg.get("agent", "single")}/{cfg.get("defense", "none")}'
        rows = {(r["task_id"], r["trial"]): r for r in ev["runs"]}
        for sim in Results.load(run / "simulations.json").simulations:
            row = rows.get((sim.task_id, sim.trial))
            if not row or row.get("status") != "ok" or sim.task_id not in tasks:
                continue
            if monitors.simulator_broke(sim.messages or []):
                EXCLUDED.append((run.name, sim.task_id, sim.trial))
                continue
            if sim.task_id not in cache:
                cache[sim.task_id] = assessor.reference_data(monitors.build_environment(domain.DOMAIN, tasks[sim.task_id]))
            inter = assessor.assess_conversation(sim.messages or [], cache[sim.task_id])
            is_attack = sim.task_id in goals
            views = assessor.single_view(inter)
            ref = assessor.reference_outcome(row, is_attack)
            convs.append({"run": run.name, "config": config, "task_id": sim.task_id, "trial": sim.trial,
                          "attack": is_attack, "threat": goals.get(sim.task_id, {}).get("threat", "benign"),
                          "reward": row.get("reward"), "ref": ref, **views, "interactions": inter})
            for i in inter:
                lines.append({"run": run.name, "config": config, "task_id": sim.task_id, "trial": sim.trial,
                              "Z_conversation_ref": ref, **i})
    return convs, lines, runs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="append", help="run folder (repeatable); default: every non-mock run")
    ap.add_argument("--show", default=None, nargs="?", const="", help="print the interaction table of scenarios starting with this id")
    ap.add_argument("--trial", type=int, default=None)
    ap.add_argument("--config", default=None, help="with --show: only this agent/defense, e.g. mas/B")
    ap.add_argument("--wrong", action="store_true", help="with --show: only conversations where joint != reference")
    ap.add_argument("--out", default=None, help="write one JSON line per interaction")
    a = ap.parse_args()

    runs = [Path(p) for p in a.run] if a.run else None
    convs, lines, runs = collect(runs)

    if a.show is not None:
        for c in convs:
            if not c["task_id"].startswith(a.show) or (a.trial is not None and c["trial"] != a.trial):
                continue
            if (a.config and c["config"] != a.config) or (a.wrong and c["joint"] == c["ref"]):
                continue
            print(f"\n===== {c['task_id']}  trial {c['trial']}  [{c['config']}]  run {c['run']}")
            print(f"{'turn':>4} {'flow':>4}  {'prompt':<58} {'Y_P':<24} {'Y_R':<38} {'Z':<3} control")
            for i in c["interactions"]:
                yp = ",".join(i["Y_P"]) + (f" (ctx {i['Y_P_ctx']})" if i["Y_P_ctx"] > i["Y_P_sev"] else "")
                print(f"{i['turn']:>4} {i['flow']:>4}  {short(i['prompt'], 58):<58} {short(yp, 24):<24} "
                      f"{short(','.join(i['Y_R']), 38):<38} {i['Z']:<3} {' '.join(i['controls'])}")
            print(f"  conversation Z: joint {c['joint']} | reference {c['ref']} | prompt-only {c['prompt_only']} "
                  f"| customer-message-only {c['customer_msg_only']} | response-only {c['response_only']}")
        return

    print(f"Assessed {len(convs)} conversations, {len(lines)} interactions from {len(runs)} runs.")
    print(f"Excluded {len(EXCLUDED)} conversations in which the simulated customer left its role.\n")
    flows = Counter((i["flow"], i["Z"]) for c in convs for i in c["interactions"])
    print("Interactions per flow and outcome Z")
    print(f"{'flow':<6}" + "".join(f"{z:>6}" for z in assessor.Z_ORDER))
    for f in sorted({f for f, _ in flows}):
        print(f"{f:<6}" + "".join(f"{flows[(f, z)]:>6}" for z in assessor.Z_ORDER))

    print("\nConversation outcome per configuration: reference Z (privileged) vs joint assessor")
    by_cfg = defaultdict(list)
    for c in convs:
        by_cfg[c["config"]].append(c)
    print(f"{'agent/defense':<14} {'n':>4}  " + "  ".join(f"{z:>5}" for z in assessor.Z_ORDER) + "   agreement")
    for cfg, cs in sorted(by_cfg.items()):
        ref, joint = Counter(c["ref"] for c in cs), Counter(c["joint"] for c in cs)
        cells = "  ".join(f"{ref[z]:>2}/{joint[z]:<2}" for z in assessor.Z_ORDER)
        agree = sum(c["ref"] == c["joint"] for c in cs)
        print(f"{cfg:<14} {len(cs):>4}  {cells}   {agree}/{len(cs)}")
    print("  (cell = reference / joint)")

    print("\nAblation: which view recovers the reference outcome Z (all conversations)")
    print(f"{'view':<20} {'accuracy':>9} {'macro-F1':>9}")
    for v in VIEWS:
        pairs = [(c["ref"], c[v]) for c in convs]
        acc = sum(r == p for r, p in pairs) / max(len(pairs), 1)
        print(f"{v:<20} {acc:>9.0%} {macro_f1(pairs):>9.2f}")

    wrong = [c for c in convs if c["ref"] != c["joint"]]
    if wrong:
        print("\nDisagreements (joint vs reference), to inspect with --show:")
        for c in wrong[:15]:
            print(f"  {c['task_id']:<38} trial {c['trial']}  [{c['config']}]  joint {c['joint']} ref {c['ref']}")

    if a.out:
        Path(a.out).write_text("\n".join(json.dumps(l, ensure_ascii=False) for l in lines) + "\n")
        print(f"\nWrote {len(lines)} labelled interactions to {a.out}")


if __name__ == "__main__":
    main()
