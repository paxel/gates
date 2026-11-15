"""Renders the audit as one HTML page: a matrix of checks by repository."""

from __future__ import annotations

import html
from typing import Any

STYLE = """
:root { --bg:#f7f7f5; --fg:#1d1d1b; --muted:#6b6b66; --line:#dcdcd6; --card:#fff; --head:#eeeee9;
  --ok:#1f7a3a; --ok-bg:#e3f3e7; --bad:#b3261e; --bad-bg:#fbe4e2; --na:#a0a09a; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { --bg:#151514; --fg:#ececea;
  --muted:#9a9a94; --line:#33332f; --card:#1d1d1b; --head:#232321; --ok:#7fd39a; --ok-bg:#173322;
  --bad:#ff8a80; --bad-bg:#3a1b19; --na:#5e5e58; } }
* { box-sizing:border-box }
body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.45 system-ui, sans-serif }
header, main { max-width:1800px; margin:0 auto; padding:16px }
h1 { font-size:22px; margin:8px 0 4px } p { color:var(--muted); margin:0 0 8px }
.wrap { overflow:auto; border:1px solid var(--line); border-radius:8px; background:var(--card); max-height:85vh }
table { border-collapse:separate; border-spacing:0; font-size:12.5px }
th, td { border-bottom:1px solid var(--line); padding:4px 6px }
thead th { position:sticky; top:0; background:var(--head); z-index:2 }
th.repo { writing-mode:vertical-rl; transform:rotate(180deg); text-align:left; padding:8px 4px; min-width:40px }
th.repo small { display:block; font-weight:400; color:var(--muted) }
th.label { position:sticky; left:0; background:var(--card); text-align:left; font-weight:500; white-space:nowrap; z-index:1 }
tr.group th { background:var(--head); text-align:left; color:var(--muted); font-size:12px; text-transform:uppercase; position:sticky; left:0 }
td.c { text-align:center; min-width:40px } td.present { background:var(--ok-bg); color:var(--ok) }
td.drift { background:var(--bad-bg); color:var(--bad); font-weight:700 } td.na { color:var(--na) }
td.miss { color:var(--bad); font-weight:600; text-align:right }
"""


def render(data: dict[str, Any], standard: dict[str, Any]) -> str:
    repos = data["repos"]
    esc = html.escape
    head = "".join(
        f'<th class="repo"><a href="https://github.com/paxel/{esc(r["repo"])}">{esc(r["repo"])}</a>'
        f"<small>{esc(' · '.join(r['stacks'] or r['contents']))}</small></th>"
        for r in repos
    )
    rows, group = [], None
    for check in standard.get("checks") or []:
        if check["group"] != group:
            group = check["group"]
            rows.append(f'<tr class="group"><th colspan="{len(repos) + 2}">{esc(str(group))}</th></tr>')
        cells, drift = [], 0
        for r in repos:
            res = next((x for x in r["results"] if x["check"] == check["id"]), {"state": "n/a", "detail": ""})
            state = res["state"]
            drift += state == "drift"
            sym = {"present": "✓", "drift": "✗"}.get(state, "–")
            cls = {"present": "present", "drift": "drift"}.get(state, "na")
            cells.append(f'<td class="c {cls}" title="{esc(str(res.get("detail", "")))}">{sym}</td>')
        rows.append(
            f'<tr><th class="label">{esc(str(check["label"]))}</th><td class="miss">{drift or ""}</td>{"".join(cells)}</tr>'
        )
    drifting = sum(1 for r in repos if any(x["state"] == "drift" for x in r["results"]))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gates Audit</title><style>{STYLE}</style></head><body>
<header><h1>Every active repository against the standard</h1>
<p>{len(repos)} active repositories, {drifting} drifting · audited {esc(str(data["when"]))} against gates {esc(str(data.get("gates") or "summer"))} ·
✓ present, ✗ drift (hover for what is wrong), – nothing for that check to look at.</p></header>
<main><div class="wrap"><table><thead><tr><th class="label">Check</th><th>✗</th>{head}</tr></thead>
<tbody>{"".join(rows)}</tbody></table></div></main></body></html>
"""
