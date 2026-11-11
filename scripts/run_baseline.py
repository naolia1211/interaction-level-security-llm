"""Phase 1 baseline: run the undefended single agent on attack tasks (ASR) and benign retail tasks
(utility, natural policy violations).

Examples
  python scripts/run_baseline.py --set attacks
  python scripts/run_baseline.py --set benign --limit 10
  python scripts/run_baseline.py --set attacks --mock      # dry run, no API calls
"""
import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from tau2.data_model.simulation import TextRunConfig  # noqa: E402
from tau2.runner import run_tasks  # noqa: E402
from tau2.runner.helpers import load_tasks  # noqa: E402

from tau2.data_model.message import AssistantMessage  # noqa: E402

from thesis_sec import domain, monitors  # noqa: E402


def _configure_nl_judge(model: str, args: dict) -> None:
    """tau2 grades some tasks (natural-language assertions) with an LLM judge hard-wired to OpenAI gpt-4.1.
    Point it at our own provider instead, and accept JSON wrapped in ``` fences (Claude often adds them)."""
    import re as _re

    import tau2.evaluator.evaluator_nl_assertions as nl

    nl.DEFAULT_LLM_NL_ASSERTIONS = model
    nl.DEFAULT_LLM_NL_ASSERTIONS_ARGS = args
    original = nl.generate

    def generate_unfenced(*a, **kw):
        msg = original(*a, **kw)
        if msg.content:
            m = _re.search(r"\{.*\}", msg.content, _re.S)
            msg.content = m.group(0) if m else msg.content
        return msg

    nl.generate = generate_unfenced


def _install_retry_notice() -> None:
    """Print one visible line whenever the gateway rate-limits or times out a call (LiteLLM retries silently)."""
    import litellm
    from litellm.integrations.custom_logger import CustomLogger

    class _Notice(CustomLogger):
        def log_failure_event(self, kwargs, response_obj, start_time, end_time):
            err = kwargs.get("exception") or kwargs.get("original_exception")
            name = type(err).__name__ if err else "error"
            print(f"  [{datetime.now():%H:%M:%S}] API call failed ({name}); LiteLLM will wait and retry...", flush=True)

    litellm.callbacks = list(litellm.callbacks or []) + [_Notice()]

ERROR_REASONS = {"agent_error", "user_error", "infrastructure_error", "unexpected_error", "too_many_errors"}


def llm_args(temperature: float, mock_text: str | None) -> dict:
    # num_retries: LiteLLM retries each call with exponential backoff (and honours Retry-After),
    # which is what a rate-limited gateway (HTTP 429) asks for.
    args = {"temperature": temperature, "num_retries": int(os.getenv("LLM_NUM_RETRIES", "8")),
            "timeout": float(os.getenv("LLM_TIMEOUT", "120"))}   # never hang longer than 2 min on one call
    if os.getenv("LLM_API_BASE"):            # company / Anthropic gateway URL
        args["api_base"] = os.environ["LLM_API_BASE"]
    if os.getenv("LLM_API_KEY"):             # otherwise LiteLLM reads ANTHROPIC_API_KEY
        args["api_key"] = os.environ["LLM_API_KEY"]
    if mock_text is not None:
        args["mock_response"] = mock_text
    return args


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", choices=["attacks", "benign"], default="attacks")
    ap.add_argument("--split", default="base", help="attacks: base | v1 | v2 | T1 | T2 ; benign: base | test ...")
    ap.add_argument("--limit", type=int, default=None, help="only the first N tasks")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--max-steps", type=int, default=60)
    ap.add_argument("--concurrency", type=int, default=1, help="keep 1 on rate-limited gateways")
    ap.add_argument("--agent-model", default=os.getenv("AGENT_MODEL", "anthropic/claude-haiku-5-5"))
    ap.add_argument("--user-model", default=os.getenv("USER_MODEL", "anthropic/claude-sonnet-5-5"))
    ap.add_argument("--defense", choices=["none", "B", "E", "BE"], default="none",
                    help="none; B = Action Gateway on tools; E = handoff check on flow 3 (needs --agent mas); BE = both")
    ap.add_argument("--agent", choices=["single", "mas"], default="single",
                    help="single = original tau2 agent; mas = Triage -> Return Resolution (flow 3)")
    ap.add_argument("--judge-model", default=os.getenv("JUDGE_MODEL", os.getenv("USER_MODEL", "anthropic/claude-sonnet-5-5")),
                    help="LLM judge for tau2 natural-language assertions (tau2 default is OpenAI gpt-4.1)")
    ap.add_argument("--mock", action="store_true", help="dry run with LiteLLM mock responses")
    a = ap.parse_args()

    if "E" in a.defense and a.agent != "mas":
        sys.exit("Check E guards the handoff between two agents: use --agent mas with --defense E or BE.")
    if not a.mock and not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("LLM_API_KEY")):
        sys.exit("No API key: fill ANTHROPIC_API_KEY (or LLM_API_BASE + LLM_API_KEY) in testbed/.env, then rerun.")

    _install_retry_notice()
    _configure_nl_judge(a.judge_model, llm_args(0.0, '{"results": []}' if a.mock else None))
    domain.register()
    dom = domain.DOMAINS[a.defense]
    task_set = domain.ATTACK_TASK_SET if a.set == "attacks" else "retail"
    tasks = load_tasks(task_set, a.split)
    if a.limit:
        tasks = tasks[: a.limit]

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = "mock" if a.mock else a.agent_model.split("/")[-1]
    out_dir = ROOT / "results" / f"{stamp}_{a.set}_{a.agent}_{a.defense}_{tag}"
    out_dir.mkdir(parents=True, exist_ok=True)

    config = TextRunConfig(
        domain=dom,
        task_set_name=task_set,
        agent=domain.TWO_AGENT_E if "E" in a.defense else domain.AGENTS[a.agent],
        llm_agent=a.agent_model,
        llm_args_agent=llm_args(0.0, "I'm sorry, I can't help with that." if a.mock else None),
        user="user_simulator",
        llm_user=a.user_model,
        llm_args_user=llm_args(0.7 if a.set == "attacks" else 0.0, "Hello, I need help. ###STOP###" if a.mock else None),
        num_trials=a.trials,
        max_steps=a.max_steps,
        max_concurrency=a.concurrency,
        max_retries=2,          # whole-task retries, after LiteLLM's own per-call retries are exhausted
        retry_delay=60.0,       # seconds between whole-task retries
    )
    results = run_tasks(config, tasks, save_path=out_dir / "simulations.json", console_display=False)

    by_id = {t.id: t for t in tasks}
    goals = domain.load_attack_goals()
    rows = []
    for sim in results.simulations:
        task = by_id[sim.task_id]
        msgs = sim.messages or []
        reason = getattr(sim.termination_reason, "value", str(sim.termination_reason))
        row = {"task_id": sim.task_id, "trial": sim.trial, "reward": sim.reward_info.reward if sim.reward_info else None,
               "turns": len(msgs), "termination": reason}
        if reason in ERROR_REASONS or not any(isinstance(m, AssistantMessage) for m in msgs):
            row["status"] = "error"          # infrastructure / API failure: excluded from every metric
            rows.append(row)
            continue
        row["status"] = "ok"
        if a.set == "attacks":
            row.update(monitors.evaluate_attack(dom, task, msgs, goals[sim.task_id]))
            row["threat"] = goals[sim.task_id]["threat"]
        else:
            init = monitors.build_environment(dom, task)
            owner = {oid: o.user_id for oid, o in init.tools.db.orders.items()}
            row["monitors"] = monitors.security_monitors(msgs, owner)
        rows.append(row)

    errors = [r for r in rows if r["status"] == "error"]
    rows_all, rows = rows, [r for r in rows if r["status"] == "ok"]
    summary = {"config": {k: v for k, v in vars(a).items()}, "n_runs": len(rows_all),
               "n_valid": len(rows), "n_errors": len(errors)}
    if errors:
        summary["WARNING"] = "Some runs failed (API/infrastructure); they are excluded from the metrics below."
    if not rows:
        summary["RESULT"] = "No valid run. Check the API key / model name in .env and the log above."
    elif a.set == "attacks":
        per = defaultdict(lambda: [0, 0])
        for r in rows:
            per[r["threat"]][0] += r["success"]
            per[r["threat"]][1] += 1
        summary["ASR"] = {k: f"{s}/{n} = {s / n:.0%}" for k, (s, n) in sorted(per.items())}
        total_s = sum(r["success"] for r in rows)
        summary["ASR"]["all"] = f"{total_s}/{len(rows)} = {total_s / max(len(rows), 1):.0%}"
    else:
        rewards = [r["reward"] for r in rows if r["reward"] is not None]
        summary["utility_pass@1"] = f"{sum(rewards) / max(len(rewards), 1):.0%}"
        for k in ("cross_user_read", "cross_user_write", "unauthenticated_access", "write_without_confirmation"):
            summary[f"runs_with_{k}"] = sum(1 for r in rows if r["monitors"][k])

    (out_dir / "evaluation.json").write_text(json.dumps({"summary": summary, "runs": rows_all}, indent=2, default=str))
    print(json.dumps(summary, indent=2))
    for r in rows_all:
        if r["status"] == "error":
            mark = "ERROR"
        elif a.set == "attacks":
            mark = "SUCCESS" if r.get("success") else "blocked"
        else:
            mark = f"reward={r['reward']}"
        print(f"  {r['task_id']:<36} {mark:<9} {'; '.join(r.get('hits', []))[:110]}")
    print(f"\nSaved to {out_dir}")


if __name__ == "__main__":
    main()
