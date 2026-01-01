"""Render hunt results to JSON, Markdown, HTML."""

from __future__ import annotations

import html
import json
import time

from digger.assets import svg_logo
from digger.hunts.base import HuntResult


def render_hunts_json(results: list[HuntResult]) -> str:
    return json.dumps([
        {
            "id":             r.hunt.id,
            "title":          r.hunt.title,
            "description":    r.hunt.description,
            "severity_hint":  r.hunt.severity_hint,
            "mitre":          r.hunt.mitre,
            "tags":           r.hunt.tags,
            "columns":        r.hunt.columns,
            "count":          r.count,
            "rows":           r.rows,
        }
        for r in results
    ], indent=2, default=str)


def render_hunts_markdown(results: list[HuntResult]) -> str:
    lines: list[str] = ["# digger threat-hunting report", ""]
    lines.append(f"Generated {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())}")
    lines.append("")
    lines.append(f"**Hunts run:** {len(results)} · "
                 f"**non-empty:** {sum(1 for r in results if r.count)}")
    lines.append("")
    for r in results:
        h = r.hunt
        lines.append(f"## {h.title}  *({h.id})*")
        lines.append(f"*severity hint:* `{h.severity_hint}` · *mitre:* `{h.mitre}` · *rows:* {r.count}")
        lines.append("")
        lines.append(h.description)
        lines.append("")
        if not r.rows:
            lines.append("_no rows_")
            lines.append("")
            continue
        cols = h.columns
        lines.append("| " + " | ".join(cols) + " |")
        lines.append("|" + "|".join("---" for _ in cols) + "|")
        for row in r.rows[:50]:
            lines.append("| " + " | ".join(_md_cell(row.get(c)) for c in cols) + " |")
        if r.count > 50:
            lines.append(f"\n_…and {r.count - 50} more rows truncated_")
        lines.append("")
    return "\n".join(lines)


def _md_cell(v) -> str:
    if v is None:
        return ""
    s = str(v)
    return s.replace("|", "\\|").replace("\n", " ")[:200]


_SEV_COLOR = {
    "info": "#8a8f99", "low": "#7cc4ff", "medium": "#ffd152",
    "high": "#ff9b3a", "critical": "#ff2e6c",
}


_HTML_STYLE = """
*{box-sizing:border-box}
body{margin:0;background:#0c0f14;color:#e6e8ec;font-family:-apple-system,Inter,system-ui,Segoe UI,sans-serif;line-height:1.55}
header.banner{display:flex;align-items:center;gap:24px;padding:24px 32px;background:linear-gradient(180deg,#181d27,#0c0f14);border-bottom:1px solid #2a2f3a}
header svg{width:96px;height:auto}
header h1{margin:0;font-size:26px;color:#d0c39a;letter-spacing:.5px}
header .meta{margin-top:4px;color:#aab0bd;font-size:13px;font-family:Iosevka,Menlo,Consolas,monospace}
.summary{padding:14px 32px;background:#10141c;border-bottom:1px solid #2a2f3a;display:flex;gap:14px;flex-wrap:wrap;color:#aab0bd;font-size:13px;font-family:Iosevka,Menlo,Consolas,monospace}
.summary .pill{padding:3px 10px;border-radius:999px;font-weight:700;color:#0a0f10;background:#69d49a}
.summary .pill.empty{background:#2a2f3a;color:#8a8f99}
.hunt{margin:18px 32px;background:#10141c;border:1px solid #2a2f3a;border-radius:10px;overflow:hidden}
.hunt header{display:flex;align-items:center;gap:12px;padding:14px 18px;cursor:pointer}
.hunt header:hover{background:#161b25}
.hunt header.empty{opacity:0.55}
.hunt .badge{padding:3px 9px;border-radius:999px;font-size:11px;font-weight:700;color:#0c0f14;text-transform:uppercase;letter-spacing:.5px}
.hunt .badge.clean{background:#2a2f3a;color:#8a8f99;border:1px solid #3a3f4a}
.hunt .sev-hint{color:#6a6f7c;font-size:10px;font-family:Iosevka,Menlo,Consolas,monospace;letter-spacing:.3px}
.hunt .id{font-family:Iosevka,Menlo,Consolas,monospace;color:#8a8f99;font-size:12px}
.hunt .title{flex:1;color:#e6e8ec;font-weight:600}
.hunt .count{color:#aab0bd;font-family:Iosevka,Menlo,Consolas,monospace;font-size:12px}
.hunt .body{display:none;padding:0 18px 18px;border-top:1px solid #1d222d}
.hunt.open .body{display:block}
.hunt .desc{color:#cfd4df;margin:14px 0 6px}
.hunt .tags{margin:6px 0 14px}
.tag{display:inline-block;padding:1px 8px;font-size:11px;background:#181d27;border:1px solid #2a2f3a;border-radius:5px;color:#aab0bd;font-family:Iosevka,Menlo,Consolas,monospace;margin-right:4px}
table.rows{width:100%;border-collapse:collapse;font-size:12px;font-family:Iosevka,Menlo,Consolas,monospace}
table.rows th{text-align:left;color:#d0c39a;font-weight:600;padding:8px 12px 8px 0;border-bottom:1px solid #2a2f3a;text-transform:uppercase;font-size:10px;letter-spacing:.5px;font-family:-apple-system,Inter,system-ui,sans-serif}
table.rows td{padding:6px 12px 6px 0;color:#cfd4df;border-bottom:1px solid #1d222d;vertical-align:top;word-break:break-word;max-width:540px}
table.rows tr:hover td{background:#0a0d13}
table.rows tr.self-row td{color:#9cd28a;opacity:.85}
table.rows tr.self-row td:first-child::before{content:"◆ ";color:#69d49a;font-weight:700}
.nope{color:#6a6f7c;padding:6px 0;font-style:italic}
"""


def render_hunts_html(results: list[HuntResult], host: dict | None = None) -> str:
    nonempty = sum(1 for r in results if r.count)
    by_sev: dict[str, int] = {}
    for r in results:
        if r.count:
            by_sev[r.hunt.severity_hint] = by_sev.get(r.hunt.severity_hint, 0) + 1

    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<title>digger hunt report</title>")
    parts.append(f"<style>{_HTML_STYLE}</style></head><body>")
    parts.append("<header class='banner'>")
    parts.append(svg_logo())
    parts.append("<div><h1>hunt report</h1>")
    parts.append(f"<div class='meta'>host {html.escape(str((host or {}).get('node', '?')))} · "
                 f"generated {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())}</div>")
    parts.append("</div></header>")

    parts.append("<section class='summary'>")
    parts.append(f"<span class='pill'>{nonempty} / {len(results)} non-empty</span>")
    for sev in ("critical", "high", "medium", "low", "info"):
        n = by_sev.get(sev, 0)
        if n == 0:
            # A 0-count severity pill should NEVER be painted with its
            # severity color — that makes "clean" look like "critical".
            parts.append(f"<span class='pill empty'>0 {sev}</span>")
        else:
            color = _SEV_COLOR.get(sev, "#8a8f99")
            parts.append(f"<span class='pill' style='background:{color}'>{n} {sev}</span>")
    parts.append("</section>")

    # Sort non-empty by severity then by row count desc, then empty ones grouped at bottom
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sortable = sorted(results, key=lambda r: (
        0 if r.count else 1,
        order.get(r.hunt.severity_hint, 5),
        -r.count,
        r.hunt.id,
    ))

    for r in sortable:
        h = r.hunt
        is_empty = not r.count
        parts.append(f"<div class='hunt{' open' if not is_empty else ''}'>")
        parts.append(f"<header class='{'empty' if is_empty else ''}' "
                     f"onclick='this.parentNode.classList.toggle(\"open\")'>")
        if is_empty:
            # A hunt that returned zero rows is *clean*, not critical.
            # Show a neutral "clean" pill so the eye doesn't read the
            # hunt's *potential* severity as actual present-tense risk.
            parts.append("<span class='badge clean'>clean</span>")
            parts.append(f"<span class='sev-hint'>(would-be: {html.escape(h.severity_hint)})</span>")
        else:
            sev_color = _SEV_COLOR.get(h.severity_hint, "#8a8f99")
            parts.append(f"<span class='badge' style='background:{sev_color}'>{html.escape(h.severity_hint)}</span>")
        parts.append(f"<span class='id'>{html.escape(h.id)}</span>")
        parts.append(f"<span class='title'>{html.escape(h.title)}</span>")
        parts.append(f"<span class='count'>{r.count} row{'s' if r.count != 1 else ''}</span>")
        parts.append("</header>")
        parts.append("<div class='body'>")
        parts.append(f"<div class='desc'>{html.escape(h.description)}</div>")
        if h.mitre or h.tags:
            parts.append("<div class='tags'>")
            if h.mitre:
                parts.append(f"<span class='tag'>MITRE {html.escape(h.mitre)}</span>")
            for t in h.tags:
                parts.append(f"<span class='tag'>{html.escape(t)}</span>")
            parts.append("</div>")
        if not r.rows:
            parts.append("<div class='nope'>no rows for this case</div>")
        else:
            parts.append("<table class='rows'><tr>")
            for c in h.columns:
                parts.append(f"<th>{html.escape(c)}</th>")
            parts.append("</tr>")
            for row in r.rows:
                row_class = " class='self-row'" if row.get("self") else ""
                parts.append(f"<tr{row_class}>")
                for c in h.columns:
                    v = row.get(c)
                    parts.append(f"<td>{html.escape('' if v is None else str(v))}</td>")
                parts.append("</tr>")
            parts.append("</table>")
        parts.append("</div></div>")
    parts.append("</body></html>")
    return "".join(parts)
