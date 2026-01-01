"""Self-contained HTML report.

Single .html file. Embeds the SVG logo, CSS, and a small JS for filter +
collapsible finding cards. No external assets.
"""

from __future__ import annotations

import html
import json
import time
from typing import Any

from digger.assets import svg_logo
from digger.core.evidence import EvidenceStore

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

_SEV_COLOR = {
    "critical": "#ff2e6c",
    "high": "#ff9b3a",
    "medium": "#ffd152",
    "low": "#7cc4ff",
    "info": "#8a8f99",
}


_STYLE = """
*{box-sizing:border-box}
body{margin:0;background:#0c0f14;color:#e6e8ec;font-family:-apple-system,Inter,system-ui,Segoe UI,Roboto,sans-serif;line-height:1.55}
.banner{display:flex;align-items:center;gap:24px;padding:24px 32px;background:linear-gradient(180deg,#181d27,#0c0f14);border-bottom:1px solid #2a2f3a}
.banner svg{width:120px;height:auto}
.banner h1{margin:0;font-size:28px;letter-spacing:1px}
.banner .meta{margin-top:6px;color:#aab0bd;font-size:13px;font-family:Iosevka,Menlo,Consolas,monospace}
.summary{padding:24px 32px;background:#10141c;border-bottom:1px solid #2a2f3a}
.summary h2{margin:0 0 12px;font-size:18px;letter-spacing:.3px;color:#cfd4df}
.summary .severity{display:inline-block;padding:4px 12px;border-radius:999px;font-size:13px;font-weight:600;color:#0c0f14}
.summary p{max-width:860px;margin:8px 0 0;color:#d6dae3}
.summary ul{margin:12px 0 0 20px;padding:0;color:#cfd4df}
.counts{display:flex;gap:16px;flex-wrap:wrap;padding:18px 32px;background:#0c0f14;border-bottom:1px solid #2a2f3a}
.counts .pill{padding:10px 14px;background:#181d27;border-radius:10px;font-size:13px;font-family:Iosevka,Menlo,Consolas,monospace}
.controls{padding:16px 32px;background:#0c0f14;border-bottom:1px solid #2a2f3a;display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.controls input,.controls select{padding:8px 12px;background:#181d27;border:1px solid #2a2f3a;color:#e6e8ec;border-radius:8px;font-size:14px}
.controls input{min-width:280px}
.findings{padding:24px 32px}
.finding{margin-bottom:14px;background:#10141c;border:1px solid #2a2f3a;border-radius:10px;overflow:hidden}
.finding header{display:flex;align-items:center;gap:12px;padding:14px 18px;cursor:pointer;user-select:none}
.finding header:hover{background:#161b25}
.finding .badge{padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;color:#0c0f14;text-transform:uppercase;letter-spacing:.5px}
.finding .title{flex:1;font-size:15px;color:#e6e8ec}
.finding .detector{color:#8a8f99;font-size:12px;font-family:Iosevka,Menlo,Consolas,monospace}
.finding .body{padding:0 18px 18px;border-top:1px solid #1d222d;display:none}
.finding.open .body{display:block}
.finding .body h4{margin:14px 0 6px;color:#cfd4df;font-size:13px;text-transform:uppercase;letter-spacing:.6px}
.finding .body p{margin:0;color:#d6dae3}
.finding pre{background:#0a0d13;border:1px solid #1d222d;padding:12px;border-radius:8px;color:#cfd4df;overflow-x:auto;font-size:12px;font-family:Iosevka,Menlo,Consolas,monospace}
.tag{display:inline-block;padding:2px 8px;background:#181d27;border:1px solid #2a2f3a;border-radius:6px;color:#aab0bd;font-size:11px;margin-right:4px;font-family:Iosevka,Menlo,Consolas,monospace}
.verdict-confirmed_malicious{color:#ff2e6c;font-weight:700}
.verdict-likely_malicious{color:#ff7a4a;font-weight:700}
.verdict-needs_investigation{color:#ffd152;font-weight:700}
.verdict-likely_benign{color:#9cd28a}
.verdict-false_positive{color:#8a8f99}
footer{padding:24px 32px;color:#6a6f7c;font-size:12px;border-top:1px solid #2a2f3a}
.chain-panel{background:#10141c;border:1px solid #2a2f3a;border-radius:10px;padding:14px 18px}
.chain-title{color:#d0c39a;font-size:12px;text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px;font-weight:700}
.chain-title .alg{display:inline-block;padding:1px 7px;font-size:10px;font-weight:700;border-radius:4px;background:#26230f;color:#d0c39a;margin-left:8px;letter-spacing:.5px}
.chain-tbl{width:100%;border-collapse:collapse;font-size:12px}
.chain-tbl th{text-align:left;font-weight:600;color:#aab0bd;padding:6px 12px 6px 0;border-bottom:1px solid #1d222d;text-transform:uppercase;font-size:10px;letter-spacing:.5px}
.chain-tbl td{padding:6px 12px 6px 0;color:#cfd4df;font-family:Iosevka,Menlo,Consolas,monospace;border-bottom:1px solid #1d222d}
.chain-tbl td:first-child{color:#d0c39a;font-family:-apple-system,Inter,system-ui,sans-serif;text-transform:uppercase;font-size:10px;letter-spacing:.6px;width:80px}
.chain-tbl td.hash{word-break:break-all;font-size:11px}
.chain-note{margin-top:10px;color:#6a6f7c;font-size:11px;font-family:Iosevka,Menlo,Consolas,monospace}
.chain-note code{color:#d0c39a}
"""


def _safe_text(x: Any) -> str:
    if x is None:
        return ""
    return html.escape(str(x))


def render_html(store: EvidenceStore) -> str:
    host = store.get_meta("host") or {}
    counts = store.counts()
    summary = store.get_meta("ai_case_summary") or {}
    findings = sorted(
        store.iter_findings(),
        key=lambda f: (_SEV_ORDER.index(f["severity"]) if f["severity"] in _SEV_ORDER else 99, f["title"]),
    )

    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<title>digger report — " + _safe_text(host.get("node", "")) + "</title>")
    parts.append("<style>" + _STYLE + "</style>")
    parts.append("</head><body>")

    parts.append("<header class='banner'>")
    parts.append(svg_logo())
    parts.append("<div>")
    parts.append("<h1>digger forensic report</h1>")
    parts.append("<div class='meta'>")
    parts.append(_safe_text(host.get("node", ""))
                 + " &middot; " + _safe_text(host.get("os", "")) + " " + _safe_text(host.get("release", ""))
                 + " &middot; case " + _safe_text(store.get_meta("case_id", "")))
    parts.append("<br>generated " + time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime()))
    parts.append("</div></div></header>")

    if summary:
        sev = summary.get("overall_severity", "info")
        parts.append("<section class='summary'>")
        parts.append("<h2>Executive summary <span class='severity' style='background:"
                     + _SEV_COLOR.get(sev, "#8a8f99") + "'>" + _safe_text(sev) + "</span></h2>")
        parts.append("<p>" + _safe_text(summary.get("one_paragraph", "")) + "</p>")
        if summary.get("top_actions"):
            parts.append("<h2 style='margin-top:18px;font-size:14px'>Top actions</h2><ul>")
            for a in summary["top_actions"]:
                parts.append("<li>" + _safe_text(a) + "</li>")
            parts.append("</ul>")
        if summary.get("if_compromised"):
            parts.append("<p style='margin-top:14px'><strong>If compromised:</strong> "
                         + _safe_text(summary["if_compromised"]) + "</p>")
        if summary.get("attribution_hint"):
            parts.append("<p style='margin-top:6px'><strong>Attribution hint:</strong> "
                         + _safe_text(summary["attribution_hint"]) + "</p>")
        parts.append("</section>")

    parts.append("<section class='counts'>")
    parts.append("<div class='pill'>artifacts: " + str(counts["artifacts"]) + "</div>")
    parts.append("<div class='pill'>findings: " + str(counts["findings"]) + "</div>")
    for sev in _SEV_ORDER:
        parts.append("<div class='pill' style='border-left:3px solid " + _SEV_COLOR[sev]
                     + "'>" + sev + ": " + str(counts["by_severity"].get(sev, 0)) + "</div>")
    parts.append("</section>")

    # ---- Storyline section (Aftermath-style narrative reconstruction) ---- #
    try:
        from digger.report.storyline import (
            build_storylines, render_storyline_html,
        )
        storylines = build_storylines(findings=findings)
        # Only render when at least one cluster has >1 finding —
        # singleton chains add no narrative value
        meaningful = [s for s in storylines if len(s.findings) > 1]
        if meaningful:
            parts.append(render_storyline_html(meaningful, top_n=10))
    except Exception:
        # Storyline synthesis is best-effort; never block the report
        pass

    parts.append("<section class='controls'>")
    parts.append("<input id='filter' type='text' placeholder='filter findings by text…'>")
    parts.append("<select id='sev'>")
    parts.append("<option value=''>all severities</option>")
    for sev in _SEV_ORDER:
        parts.append("<option value='" + sev + "'>" + sev + "</option>")
    parts.append("</select>")
    parts.append("</section>")

    parts.append("<section class='findings' id='findings'>")
    for f in findings:
        sev = f["severity"]
        t = f.get("triage") or {}
        parts.append("<div class='finding' data-sev='" + sev + "' data-text='"
                     + _safe_text((f["title"] + " " + f["summary"] + " " + (f["detector"] or "")).lower()) + "'>")
        parts.append("<header onclick='this.parentNode.classList.toggle(\"open\")'>")
        parts.append("<span class='badge' style='background:" + _SEV_COLOR[sev] + "'>" + sev + "</span>")
        parts.append("<span class='title'>" + _safe_text(f["title"]) + "</span>")
        parts.append("<span class='detector'>" + _safe_text(f["detector"]) + "</span>")
        parts.append("</header>")
        parts.append("<div class='body'>")
        if f.get("mitre"):
            parts.append("<span class='tag'>MITRE " + _safe_text(f["mitre"]) + "</span>")
        parts.append("<p>" + _safe_text(f["summary"]) + "</p>")
        if t:
            parts.append("<h4>AI triage</h4>")
            parts.append("<p><span class='verdict-" + _safe_text(t.get("verdict", "")) + "'>"
                         + _safe_text(t.get("verdict", "")) + "</span> "
                         + "(confidence " + _safe_text(t.get("confidence", "")) + ", "
                         + "reassessed severity <strong>" + _safe_text(t.get("severity", "")) + "</strong>)</p>")
            parts.append("<p>" + _safe_text(t.get("one_line", "")) + "</p>")
            parts.append("<p>" + _safe_text(t.get("rationale", "")) + "</p>")
            if t.get("next_steps"):
                parts.append("<h4>Next steps</h4><ul>")
                for ns in t["next_steps"]:
                    parts.append("<li>" + _safe_text(ns) + "</li>")
                parts.append("</ul>")
            if t.get("attribution"):
                parts.append("<p><strong>Attribution hint:</strong> " + _safe_text(t["attribution"]) + "</p>")
        if f.get("evidence"):
            parts.append("<h4>Evidence</h4><pre>"
                         + html.escape(json.dumps(f["evidence"], indent=2, default=str)[:6000])
                         + "</pre>")
        parts.append("</div></div>")
    parts.append("</section>")

    parts.append("<footer>")
    tip = store.chain_tip()
    art = tip.get("artifacts", {}) or {}
    fnd = tip.get("findings", {}) or {}
    algs = tip.get("algorithms", []) or []
    parts.append("<div class='chain-panel'>")
    parts.append("<div class='chain-title'>chain-tip integrity"
                 + "".join(f"<span class='alg'>{_safe_text(a)}</span>" for a in algs)
                 + "</div>")
    parts.append("<table class='chain-tbl'>")
    parts.append("<tr><th></th><th>SHA-256 (FIPS 180-4)</th><th>SHA3-256 (FIPS 202)</th></tr>")
    parts.append(
        f"<tr><td>artifacts</td>"
        f"<td class='hash'>{_safe_text(art.get('sha256','—'))}</td>"
        f"<td class='hash'>{_safe_text(art.get('sha3_256','—'))}</td></tr>"
    )
    parts.append(
        f"<tr><td>findings</td>"
        f"<td class='hash'>{_safe_text(fnd.get('sha256','—'))}</td>"
        f"<td class='hash'>{_safe_text(fnd.get('sha3_256','—'))}</td></tr>"
    )
    parts.append("</table>")
    parts.append(f"<div class='chain-note'>case id <code>{_safe_text(tip.get('case_id',''))}</code> · "
                 f"both chains must verify · "
                 f"<code>digger verify --case-dir &lt;case&gt;</code></div>")
    parts.append("</div>")
    parts.append("</footer>")

    parts.append("""
<script>
const f=document.getElementById('filter'),s=document.getElementById('sev');
function apply(){
  const q=(f.value||'').toLowerCase(), sv=s.value;
  document.querySelectorAll('.finding').forEach(el=>{
    const ok=(!q||el.dataset.text.includes(q))&&(!sv||el.dataset.sev===sv);
    el.style.display=ok?'':'none';
  });
}
f.addEventListener('input',apply); s.addEventListener('change',apply);
</script>
""")
    parts.append("</body></html>")
    return "".join(parts)
