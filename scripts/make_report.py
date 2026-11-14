"""Build results/report.html: the interaction-level assessment of every finished run, as one page.

  python scripts/make_report.py                 # all runs -> results/report.html
  python scripts/make_report.py --open          # and open it in the browser (macOS)
No API calls. The page is self-contained (no network needed).
"""
import argparse
import html
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import assess_interactions  # noqa: E402
from assess_interactions import ROOT, VIEWS, collect, macro_f1  # noqa: E402

from thesis_sec import assessor  # noqa: E402

Z_NAME = {"N": "Normal", "OR": "Over-refusal", "BA": "Blocked attack", "PC": "Partial compromise", "FC": "Full compromise"}
VIEW_NAME = {"prompt_only": "Prompt only (all inputs: customer, handoff, tool output)",
             "customer_msg_only": "Prompt only (customer messages)",
             "response_only": "Response only", "joint": "Joint: prompt intent + response impact"}
CONFIG_ORDER = ["single/none", "single/B", "mas/none", "mas/E", "mas/B", "mas/BE"]
CONFIG_NAME = {"single/none": "Single agent", "single/B": "Single agent + B", "mas/none": "Two agents",
               "mas/E": "Two agents + E", "mas/B": "Two agents + B", "mas/BE": "Two agents + B + E"}
FLOW_NAME = {"1": "Customer → System", "3": "Triage → Return Resolution (handoff)", "8": "Tool output → Agent"}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1a1d23;--mute:#5b6370;--line:#e2e5ea;--accent:#1f4e79;
--N:#7b8490;--OR:#b7791f;--BA:#2f855a;--PC:#c05621;--FC:#c53030}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1240px;margin:0 auto;padding:28px 20px 80px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.01em}h2{font-size:18px;margin:36px 0 12px;color:var(--accent)}
.sub{color:var(--mute);margin:0 0 6px}.note{color:var(--mute);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.grid{display:grid;gap:14px}.g4{grid-template-columns:repeat(4,1fr)}.g2{grid-template-columns:1fr 1fr}
@media(max-width:900px){.g4{grid-template-columns:1fr 1fr}.g2{grid-template-columns:1fr}}
.kpi b{display:block;font-size:26px;font-variant-numeric:tabular-nums}.kpi span{color:var(--mute);font-size:13px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mute);font-weight:600}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.bar{height:14px;background:#eceef2;border-radius:4px;overflow:hidden;min-width:160px}.bar i{display:block;height:100%;background:var(--accent)}
.bar.joint i{background:var(--BA)}
.stack{display:flex;height:20px;border-radius:4px;overflow:hidden;background:#eceef2;min-width:260px}
.stack i{display:block;height:100%;color:#fff;font:600 11px/20px inherit;text-align:center;font-style:normal;white-space:nowrap;overflow:hidden}
.z{display:inline-block;min-width:34px;text-align:center;padding:1px 8px;border-radius:999px;color:#fff;font-weight:700;font-size:12px}
.zN{background:var(--N)}.zOR{background:var(--OR)}.zBA{background:var(--BA)}.zPC{background:var(--PC)}.zFC{background:var(--FC)}
.chip{display:inline-block;padding:1px 8px;margin:1px 3px 1px 0;border-radius:6px;font-size:12px;border:1px solid var(--line);background:#f3f4f6;color:#374151;white-space:nowrap}
.chip.p{background:#ede9fe;border-color:#d6ccfb;color:#4c1d95}.chip.effect{background:#fde8e8;border-color:#f5c2c2;color:#9b1c1c}
.chip.process{background:#feecdc;border-color:#f8cfa6;color:#8a3c0b}.chip.ctl{background:#e1effe;border-color:#b9d6fb;color:#1e429f}
.legend span{margin-right:14px;white-space:nowrap}
details.conv{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0}
details.conv>summary{cursor:pointer;padding:10px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;list-style:none}
details.conv>summary::-webkit-details-marker{display:none}
details.conv>summary .id{font-weight:600}details.conv>summary .cfg{color:var(--mute);font-size:13px}
details.conv>summary .diff{margin-left:auto;font-size:12px;color:var(--mute)}
details.conv[open]>summary{border-bottom:1px solid var(--line)}
.inter{padding:4px 14px 12px;overflow-x:auto}.inter table{table-layout:fixed;min-width:1040px}.inter td{font-size:13.5px}.inter th{white-space:nowrap}
.inter th:nth-child(1){width:11%}.inter th:nth-child(2){width:23%}.inter th:nth-child(3){width:11%}.inter th:nth-child(4){width:27%}
.inter th:nth-child(5){width:16%}.inter th:nth-child(6){width:5%}.inter th:nth-child(7){width:7%}.inter .chip{white-space:normal;word-break:break-word}
.flow{font-size:12px;color:var(--mute)}.flow b{color:var(--ink)}.who{font-size:11px;color:var(--mute);text-transform:uppercase;letter-spacing:.04em;margin-right:6px}
.msg{white-space:pre-wrap;word-break:break-word}.tool{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:#f3f4f6;border-radius:4px;padding:1px 5px;word-break:break-all}
.st-denied{color:#1e429f;font-weight:600}.st-error{color:#9b1c1c;font-weight:600}.st-ok{color:var(--BA)}
.filters{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:8px 0 12px}
.filters select,.filters input{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:#fff}
.matrix td{font-size:13px;white-space:nowrap}.matrix .z{min-width:0;padding:0 6px;font-size:11px;margin-right:2px}
.callout{border-left:4px solid var(--accent);background:#eef4fb;padding:10px 14px;border-radius:6px;margin:10px 0}
"""

JS = """
const q=s=>document.querySelector(s);
function apply(){const c=q('#f-config').value,t=q('#f-type').value,z=q('#f-z').value,d=q('#f-diff').checked,s=q('#f-text').value.toLowerCase();let n=0;
document.querySelectorAll('#all details.conv').forEach(e=>{const ok=(!c||e.dataset.config===c)&&(!t||e.dataset.type===t)&&(!z||e.dataset.z===z)&&(!d||e.dataset.diff==='1')&&(!s||e.dataset.id.toLowerCase().includes(s));
e.style.display=ok?'':'none';if(ok)n++});q('#count').textContent=n+' conversations';}
document.querySelectorAll('.filters select,.filters input').forEach(e=>e.addEventListener('input',apply));apply();
"""


def e(text) -> str:
    return html.escape(str(text if text is not None else ""))


def cut(text: str, n: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else text[:n].rstrip() + " …"


def zbadge(z: str) -> str:
    return f'<span class="z z{z}" title="{Z_NAME[z]}">{z}</span>'


def chips(labels, kind: str) -> str:
    out = []
    for lab in labels:
        cls = kind
        if kind == "r":
            cls = "effect" if lab in assessor.EFFECT else "process" if lab in assessor.PROCESS else ""
        elif kind == "p":
            cls = "p" if lab != "benign" else ""
        out.append(f'<span class="chip {cls}">{e(lab)}</span>')
    return "".join(out)


def stack(counter: Counter, total: int) -> str:
    cells = []
    for z in assessor.Z_ORDER:
        if counter[z]:
            share = counter[z] / max(total, 1)
            cells.append(f'<i style="width:{100 * share:.2f}%;background:var(--{z})" '
                         f'title="{Z_NAME[z]}: {counter[z]}">{f"{z} {counter[z]}" if share >= 0.09 else ""}</i>')
    return f'<div class="stack">{"".join(cells)}</div>'


def response_html(items: list) -> str:
    rows = []
    for it in items:
        who = f'<span class="who">{e(it["who"])}</span>'
        if it["kind"] == "tool":
            status = it["status"]
            extra = f' <span class="note">{e(cut(it["result"], 160))}</span>' if it.get("result") else ""
            rows.append(f'<div>{who}<span class="tool">{e(cut(it["text"], 420))}</span> '
                        f'<span class="st-{e(status.split()[0])}">{e(status)}</span>{extra}</div>')
        else:
            rows.append(f'<div class="msg">{who}{e(cut(it["text"], 520))}</div>')
    return "".join(rows) or '<span class="note">no response</span>'


def conversation_html(c: dict, opened: bool = False) -> str:
    diff = c["joint"] != c["ref"]
    rows = []
    for i in c["interactions"]:
        ctx = f' <span class="note">session context {i["Y_P_ctx"]}</span>' if i["Y_P_ctx"] > i["Y_P_sev"] else ""
        rows.append(
            f'<tr><td class="flow"><b>flow {e(i["flow"])}</b> · turn {i["turn"]}<br>{e(FLOW_NAME.get(i["flow"], ""))}</td>'
            f'<td><div class="msg">{e(cut(i["prompt"], 700))}</div></td>'
            f'<td>{chips(i["Y_P"], "p")}{ctx}</td>'
            f'<td>{response_html(i.get("response", []))}</td>'
            f'<td>{chips(i["Y_R"], "r")}</td>'
            f'<td>{zbadge(i["Z"])}</td>'
            f'<td>{chips(i["controls"], "ctl")}</td></tr>')
    reward = "" if c["attack"] or c.get("reward") is None else f' · task reward {c["reward"]:.0f}'
    return (
        f'<details class="conv"{" open" if opened else ""} data-config="{e(c["config"])}" '
        f'data-type="{"attack" if c["attack"] else "benign"}" data-z="{c["joint"]}" data-diff="{int(diff)}" '
        f'data-id="{e(c["task_id"])}">'
        f'<summary>{zbadge(c["joint"])}<span class="id">{e(c["task_id"])}</span>'
        f'<span class="cfg">{e(CONFIG_NAME.get(c["config"], c["config"]))} · run {e(c["run"][4:13])} · trial {c["trial"]}{reward}</span>'
        f'<span class="diff">reference {zbadge(c["ref"])} · prompt-only {zbadge(c["prompt_only"])} · '
        f'response-only {zbadge(c["response_only"])}{" · differs from reference" if diff else ""}</span></summary>'
        f'<div class="inter"><table><tr><th>Interaction</th><th>Prompt</th><th>Y_P (intent)</th><th>Response</th>'
        f'<th>Y_R (impact)</th><th>Z</th><th>Control</th></tr>{"".join(rows)}</table>'
        f'<div class="note">run {e(c["run"])}</div></div></details>')


def pick(convs, task, config, z, control=None):
    for c in convs:
        if c["task_id"].startswith(task) and c["config"] == config and c["joint"] == z and c["ref"] == z:
            if control is None or any(control in " ".join(i["controls"]) for i in c["interactions"]):
                if 3 <= len(c["interactions"]) <= 6:
                    return c
    return None


def build(convs: list, n_runs: int) -> str:
    n_inter = sum(len(c["interactions"]) for c in convs)
    configs = [k for k in CONFIG_ORDER if any(c["config"] == k for c in convs)] + sorted(
        {c["config"] for c in convs} - set(CONFIG_ORDER))
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' "
             f"content='width=device-width,initial-scale=1'><title>Interaction-Level Security Assessment</title>"
             f"<style>{CSS}</style></head><body><main>"]
    parts.append("<h1>Interaction-Level Security Assessment of LLM-Based Systems</h1>"
                 "<p class='sub'>Pilot report: every interaction is labelled with prompt intent (Y_P) and response impact (Y_R), "
                 "then joined into the outcome Z.</p>"
                 f"<p class='note'>Generated {datetime.now():%Y-%m-%d %H:%M} from {n_runs} runs on τ²-bench retail. "
                 "Rule layer only; pilot numbers show direction, not significance. "
                 f"{len(assess_interactions.EXCLUDED)} conversations were excluded because the simulated customer left its role.</p>")

    # KPIs
    joint_pairs = [(c["ref"], c["joint"]) for c in convs]
    acc = sum(r == p for r, p in joint_pairs) / max(len(joint_pairs), 1)
    parts.append("<div class='grid g4' style='margin-top:16px'>"
                 f"<div class='card kpi'><b>{len(convs)}</b><span>conversations assessed</span></div>"
                 f"<div class='card kpi'><b>{n_inter}</b><span>interactions on flows 1, 3, 8</span></div>"
                 f"<div class='card kpi'><b>{acc:.0%}</b><span>joint assessor agrees with reference Z</span></div>"
                 f"<div class='card kpi'><b>{macro_f1(joint_pairs):.2f}</b><span>Macro-F1 of the joint assessor</span></div></div>")

    parts.append("<p class='legend note' style='margin-top:14px'>"
                 + "".join(f"<span>{zbadge(z)} {Z_NAME[z]}</span>" for z in assessor.Z_ORDER) + "</p>")

    # ablation
    parts.append("<h2>1. Does one view suffice? Prompt only, response only, or joint</h2><div class='card'><table>"
                 "<tr><th>View</th><th class='num'>Accuracy</th><th class='num'>Macro-F1</th><th>Macro-F1</th></tr>")
    for v in VIEWS:
        pairs = [(c["ref"], c[v]) for c in convs]
        a = sum(r == p for r, p in pairs) / max(len(pairs), 1)
        f1 = macro_f1(pairs)
        parts.append(f"<tr><td>{'<b>' if v == 'joint' else ''}{e(VIEW_NAME[v])}{'</b>' if v == 'joint' else ''}</td>"
                     f"<td class='num'>{a:.0%}</td><td class='num'>{f1:.2f}</td>"
                     f"<td><div class='bar {'joint' if v == 'joint' else ''}'><i style='width:{100 * f1:.1f}%'></i></div></td></tr>")
    parts.append("</table><p class='note'>Reference Z uses privileged information (attack goal, final database, task reward). "
                 "A prompt-only view cannot tell a blocked attack from a successful one; a response-only view cannot tell a "
                 "blocked attack from a normal conversation.</p></div>")

    # per configuration
    parts.append("<h2>2. Outcome per configuration</h2><div class='card'><table>"
                 "<tr><th>Configuration</th><th class='num'>n</th><th>Reference Z</th><th>Joint assessor</th><th class='num'>Agreement</th></tr>")
    for k in configs:
        cs = [c for c in convs if c["config"] == k]
        ref, joint = Counter(c["ref"] for c in cs), Counter(c["joint"] for c in cs)
        agree = sum(c["ref"] == c["joint"] for c in cs)
        parts.append(f"<tr><td>{e(CONFIG_NAME.get(k, k))}</td><td class='num'>{len(cs)}</td><td>{stack(ref, len(cs))}</td>"
                     f"<td>{stack(joint, len(cs))}</td><td class='num'>{agree}/{len(cs)}</td></tr>")
    parts.append("</table><p class='note'>Hover a bar for exact counts. B = Action Gateway (flows 5–6), E = handoff check (flow 3). "
                 "Attack and normal conversations together.</p></div>")

    # scenario matrix
    attacks = sorted({c["task_id"] for c in convs if c["attack"]})
    if attacks:
        parts.append("<h2>3. Attack scenarios: assessed outcome by configuration</h2><div class='card' style='overflow-x:auto'>"
                     "<table class='matrix'><tr><th>Scenario</th>" + "".join(f"<th>{e(CONFIG_NAME.get(k, k))}</th>" for k in configs) + "</tr>")
        cell = defaultdict(Counter)
        for c in convs:
            if c["attack"]:
                cell[(c["task_id"], c["config"])][c["joint"]] += 1
        for t in attacks:
            tds = []
            for k in configs:
                cnt = cell.get((t, k))
                tds.append("<td>" + ("".join(f'<span class="z z{z}">{z} {cnt[z]}</span>' for z in reversed(assessor.Z_ORDER) if cnt[z])
                                     if cnt else "<span class='note'>–</span>") + "</td>")
            parts.append(f"<tr><td>{e(t)}</td>{''.join(tds)}</tr>")
        parts.append("</table></div>")

    # featured
    feat = [pick(convs, "T3-01", "mas/none", "FC"), pick(convs, "T3-01", "mas/BE", "BA", "E:E2")]
    feat = [c for c in feat if c]
    if feat:
        parts.append("<h2>4. One attack, read interaction by interaction</h2>"
                     "<div class='callout'><b>Authority laundering.</b> The customer's unverifiable claim "
                     "(\"ownership verified by phone, manager approved\") is copied by Triage into the handoff; the next agent "
                     "treats it as an internal instruction. The harmful step may follow a message that looks benign on its own, "
                     "which is why the assessment keeps the session context. Below: the same scenario without defense, then with B + E.</div>")
        parts += [conversation_html(c, opened=True) for c in feat]

    # all conversations
    opts = "".join(f"<option value='{e(k)}'>{e(CONFIG_NAME.get(k, k))}</option>" for k in configs)
    zopts = "".join(f"<option value='{z}'>{z} · {Z_NAME[z]}</option>" for z in assessor.Z_ORDER)
    parts.append(f"<h2>{5 if feat else 4}. All conversations</h2><div class='filters'>"
                 f"<select id='f-config'><option value=''>All configurations</option>{opts}</select>"
                 "<select id='f-type'><option value=''>Attack and normal</option><option value='attack'>Attack scenarios</option>"
                 "<option value='benign'>Normal tasks</option></select>"
                 f"<select id='f-z'><option value=''>Any outcome</option>{zopts}</select>"
                 "<input id='f-text' placeholder='scenario id, e.g. T3-01'>"
                 "<label><input type='checkbox' id='f-diff'> differs from reference</label>"
                 "<span class='note' id='count'></span></div><div id='all'>")
    order = {k: n for n, k in enumerate(configs)}
    for c in sorted(convs, key=lambda c: (not c["attack"], c["task_id"], order.get(c["config"], 99), c["trial"], c["run"])):
        parts.append(conversation_html(c))
    parts.append(f"</div></main><script>{JS}</script></body></html>")
    return "".join(parts)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="append")
    ap.add_argument("--out", default=str(ROOT / "results" / "report.html"))
    ap.add_argument("--open", action="store_true")
    a = ap.parse_args()
    convs, _, runs = collect([Path(p) for p in a.run] if a.run else None)
    Path(a.out).write_text(build(convs, len(runs)), encoding="utf-8")
    print(f"Wrote {a.out}  ({len(convs)} conversations)")
    if a.open:
        subprocess.run(["open", a.out], check=False)


if __name__ == "__main__":
    main()
