"""Register the thesis security domain on top of tau2-bench retail, without editing tau2 itself.

Domain  : retail_sec          (retail tools, DB and policy; extended step by step)
Task set: retail_sec_attacks  (attack scenarios from data/attack_tasks.json)
"""
import json
from pathlib import Path
from typing import Optional

from tau2.data_model.tasks import Task
from tau2.domains.retail.environment import get_environment as _retail_environment
from tau2.registry import registry

DATA_DIR = Path(__file__).parent / "data"
DOMAIN = "retail_sec"
ATTACK_TASK_SET = "retail_sec_attacks"


def get_environment(db=None, solo_mode: bool = False):
    env = _retail_environment(db=db, solo_mode=solo_mode)
    env.domain_name = DOMAIN
    return env


DOMAIN_B = "retail_sec_b"   # same as retail_sec, with check B (Action Gateway) in front of the tools


def get_environment_b(db=None, solo_mode: bool = False):
    from tau2.domains.retail.data_model import RetailDB
    from tau2.domains.retail.utils import RETAIL_DB_PATH, RETAIL_POLICY_PATH

    from thesis_sec.gateway import GatedEnvironment, GatedRetailTools

    if solo_mode:
        raise ValueError("Retail domain does not support solo mode")
    db = db if db is not None else RetailDB.load(RETAIL_DB_PATH)
    policy = Path(RETAIL_POLICY_PATH).read_text(encoding="utf-8")
    return GatedEnvironment(domain_name=DOMAIN_B, policy=policy, tools=GatedRetailTools(db))


DOMAINS = {"none": DOMAIN, "B": DOMAIN_B, "E": DOMAIN, "BE": DOMAIN_B}   # defense -> domain (B = gateway)
TWO_AGENT = "two_agent"                   # Triage -> Return Resolution (architecture slide 1)
TWO_AGENT_E = "two_agent_e"               # same, with check E on the handoff (flow 3)
AGENTS = {"single": "llm_agent", "mas": TWO_AGENT}


def _all_attack_tasks() -> list[Task]:
    raw = json.loads((DATA_DIR / "attack_tasks.json").read_text(encoding="utf-8"))
    return [Task.model_validate(t) for t in raw]


def get_attack_task_splits() -> dict[str, list[str]]:
    """base = every scenario; v1 = first set; v2 = adaptive attacker + new scenarios; T1/T2 = by threat."""
    tasks, goals = _all_attack_tasks(), load_attack_goals()
    splits = {"base": [t.id for t in tasks]}
    for s in sorted({g.get("set", "v1") for g in goals.values()}):
        splits[s] = [t.id for t in tasks if goals[t.id].get("set", "v1") == s]
    for threat in sorted({t.id.split("-")[0] for t in tasks}):
        splits[threat] = [t.id for t in tasks if t.id.startswith(threat + "-")]
    return splits


def get_attack_tasks(task_split_name: Optional[str] = "base") -> list[Task]:
    tasks = _all_attack_tasks()
    if task_split_name is None:
        return tasks
    ids = set(get_attack_task_splits()[task_split_name])
    return [t for t in tasks if t.id in ids]


def load_attack_goals() -> dict:
    return json.loads((DATA_DIR / "attack_goals.json").read_text(encoding="utf-8"))


def register() -> None:
    """Idempotent registration so scripts can call it freely."""
    if DOMAIN not in registry.get_domains():
        registry.register_domain(get_environment, DOMAIN)
    if DOMAIN_B not in registry.get_domains():
        registry.register_domain(get_environment_b, DOMAIN_B)
    if registry.get_agent_factory(TWO_AGENT) is None:
        from thesis_sec.mas import create_two_agent_system, create_two_agent_system_e
        registry.register_agent_factory(create_two_agent_system, TWO_AGENT)
        registry.register_agent_factory(create_two_agent_system_e, TWO_AGENT_E)
    if ATTACK_TASK_SET not in registry.get_task_sets():
        registry.register_tasks(get_attack_tasks, ATTACK_TASK_SET, get_task_splits=get_attack_task_splits)
