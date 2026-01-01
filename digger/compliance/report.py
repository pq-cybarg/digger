"""Compliance report renderers (JSON, Markdown, HTML)."""

from __future__ import annotations

import html
import json
import time
from dataclasses import asdict
from typing import Any

from digger.assets import svg_logo
from digger.compliance.assessor import ControlAssessment, Framework

_STATUS_COLOR = {
    "pass":           "#69d49a",
    "partial":        "#ffd152",
    "manual":         "#7cc4ff",
    "not_applicable": "#8a8f99",
    "fail":           "#ff6b6b",
}


def render_compliance_json(framework: Framework, assessments: list[ControlAssessment]) -> str:
    return json.dumps({
        "framework": asdict_framework(framework),
        "generated_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": _summary(assessments),
        "assessments": [asdict(a) for a in assessments],
    }, indent=2, default=str)


def asdict_framework(f: Framework) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "version": f.version,
        "publisher": f.publisher,
        "url": f.url,
        "description": f.description,
        "control_count": len(f.controls),
    }


def _summary(assessments: list[ControlAssessment]) -> dict[str, int]:
    out: dict[str, int] = {}
    for a in assessments:
        out[a.status] = out.get(a.status, 0) + 1
    out["total"] = len(assessments)
    return out


def render_compliance_md(framework: Framework, assessments: list[ControlAssessment]) -> str:
    summary = _summary(assessments)
    lines = [
        f"# {framework.title}",
        f"*{framework.id} · {framework.version} · {framework.publisher}*",
        f"_{framework.url}_",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())}",
        "",
        "## Summary",
    ]
    for status, count in summary.items():
        lines.append(f"  - {status}: {count}")
    lines.append("")
    lines.append("## Controls")
    for a in assessments:
        lines.append(f"### [{a.status.upper()}] {a.control_id} — {a.title}")
        lines.append(f"*family:* {a.family}  *severity-if-failed:* {a.severity_if_failed}")
        if a.summary:
            lines.append(f"\n{a.summary}\n")
        lines.append(f"*Rationale:* {a.rationale}\n")
        if a.references:
            lines.append(f"*References:* " + ", ".join(a.references))
        lines.append("\n---\n")
    return "\n".join(lines)


def render_compliance_html(framework: Framework, assessments: list[ControlAssessment]) -> str:
    summary = _summary(assessments)
    css = """
*{box-sizing:border-box}
body{margin:0;background:#0c0f14;color:#e6e8ec;font-family:-apple-system,Inter,system-ui,Segoe UI,sans-serif;line-height:1.55}
header.banner{display:flex;align-items:center;gap:24px;padding:24px 32px;background:linear-gradient(180deg,#181d27,#0c0f14);border-bottom:1px solid #2a2f3a}
header svg{width:96px;height:auto}
header h1{margin:0;font-size:24px}
header .meta{margin-top:4px;color:#aab0bd;font-size:12px;font-family:Iosevka,Menlo,Consolas,monospace}
.summary{padding:18px 32px;background:#10141c;border-bottom:1px solid #2a2f3a;display:flex;flex-wrap:wrap;gap:12px}
.pill{padding:8px 14px;border-radius:999px;font-size:12px;font-weight:700;color:#0c0f14}
.controls{padding:24px 32px}
.control{margin-bottom:12px;background:#10141c;border:1px solid #2a2f3a;border-radius:10px;overflow:hidden}
.control header{display:flex;align-items:center;gap:12px;padding:12px 18px;cursor:pointer}
.control header:hover{background:#161b25}
.control .body{display:none;padding:0 18px 18px;border-top:1px solid #1d222d}
.control.open .body{display:block}
.badge{padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#0c0f14}
.cid{font-family:Iosevka,Menlo,Consolas,monospace;color:#8a8f99;font-size:12px}
.body h4{margin:14px 0 4px;color:#cfd4df;font-size:12px;text-transform:uppercase;letter-spacing:.6px}
.body p{margin:0;color:#d6dae3}
.ref{display:inline-block;padding:2px 6px;background:#181d27;border-radius:6px;color:#aab0bd;font-size:11px;margin-right:4px}
"""
    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append(f"<title>{html.escape(framework.id)} — compliance report</title>")
    parts.append(f"<style>{css}</style></head><body>")
    parts.append("<header class='banner'>")
    parts.append(svg_logo())
    parts.append(f"<div><h1>{html.escape(framework.title)}</h1>")
    parts.append(
        f"<div class='meta'>{html.escape(framework.id)} · {html.escape(framework.version)} "
        f"· {html.escape(framework.publisher)}</div></div></header>"
    )
    parts.append("<section class='summary'>")
    for status, count in summary.items():
        color = _STATUS_COLOR.get(status, "#8a8f99")
        parts.append(f"<span class='pill' style='background:{color}'>{html.escape(status)}: {count}</span>")
    parts.append("</section>")
    parts.append("<section class='controls'>")
    for a in assessments:
        color = _STATUS_COLOR.get(a.status, "#8a8f99")
        parts.append("<div class='control'>")
        parts.append("<header onclick='this.parentNode.classList.toggle(\"open\")'>")
        parts.append(f"<span class='badge' style='background:{color}'>{html.escape(a.status)}</span>")
        parts.append(f"<span class='cid'>{html.escape(a.control_id)}</span>")
        parts.append(f"<span>{html.escape(a.title)}</span>")
        parts.append("</header>")
        parts.append("<div class='body'>")
        if a.summary:
            parts.append(f"<p>{html.escape(a.summary)}</p>")
        parts.append("<h4>Rationale</h4>")
        parts.append(f"<p>{html.escape(a.rationale)}</p>")
        if a.references:
            parts.append("<h4>References</h4>")
            for r in a.references:
                parts.append(f"<span class='ref'>{html.escape(r)}</span>")
        parts.append("</div></div>")
    parts.append("</section></body></html>")
    return "".join(parts)
