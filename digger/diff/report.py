"""Render a DiffResult to JSON / Markdown / HTML."""

from __future__ import annotations

import html
import json
import time
from dataclasses import asdict
from typing import Any

from digger.assets import svg_logo
from digger.diff.comparator import DiffResult


# ---- JSON ----------------------------------------------------------- #


def render_diff_json(result: DiffResult) -> str:
    return json.dumps({
        "summary": result.summary(),
        "base_case_id": result.base_case_id,
        "new_case_id":  result.new_case_id,
        "base_host":    result.base_host,
        "new_host":     result.new_host,
        "same_host":    result.same_host,
        "base_collected": result.base_collected,
        "new_collected":  result.new_collected,
        "artifact_diffs": [asdict(d) for d in result.artifact_diffs],
        "findings": {
            "new":       result.findings.new,
            "resolved":  result.findings.resolved,
            "modified":  result.findings.modified,
            "persisted": result.findings.persisted,
        },
    }, indent=2, default=str)


# ---- Markdown ------------------------------------------------------- #


def render_diff_markdown(result: DiffResult) -> str:
    s = result.summary()
    lines: list[str] = []
    lines.append(f"# digger case diff")
    lines.append("")
    lines.append(f"**Base case id:** `{result.base_case_id}`  ")
    lines.append(f"**New case id:**  `{result.new_case_id}`  ")
    lines.append(f"**Host:** `{result.base_host.get('node', '?')}`  ")
    if not result.same_host:
        lines.append(f"  ⚠︎ host fingerprints differ — diff may not be meaningful")
    lines.append(f"  generated {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())}")
    lines.append("")
    # Chain-tip integrity table — both algorithms, both cases
    base_tip = result.base_chain_tip or {}
    new_tip  = result.new_chain_tip  or {}
    if base_tip or new_tip:
        lines.append("## Chain-tip integrity")
        lines.append("")
        lines.append("| | base case | new case |")
        lines.append("|---|---|---|")
        ba = (base_tip.get("artifacts") or {}); na = (new_tip.get("artifacts") or {})
        bf = (base_tip.get("findings")  or {}); nf = (new_tip.get("findings")  or {})
        lines.append(f"| artifacts · SHA-256   | `{ba.get('sha256','') or '—'}`   | `{na.get('sha256','') or '—'}`   |")
        lines.append(f"| artifacts · SHA3-256  | `{ba.get('sha3_256','') or '—'}` | `{na.get('sha3_256','') or '—'}` |")
        lines.append(f"| findings · SHA-256    | `{bf.get('sha256','') or '—'}`   | `{nf.get('sha256','') or '—'}`   |")
        lines.append(f"| findings · SHA3-256   | `{bf.get('sha3_256','') or '—'}` | `{nf.get('sha3_256','') or '—'}` |")
        lines.append("")

    lines.append("## Summary")
    for k, v in s.items():
        lines.append(f"  - **{k.replace('_', ' ')}**: {v}")
    lines.append("")

    if result.findings.new:
        lines.append("## New findings (in current, not in base)")
        for f in result.findings.new:
            lines.append(f"### [{f['severity'].upper()}] {f['title']}")
            lines.append(f"*detector:* `{f['detector']}` *mitre:* `{f.get('mitre', '')}`")
            lines.append(f"\n{f['summary']}\n")
        lines.append("")

    if result.findings.resolved:
        lines.append("## Resolved findings (in base, gone in current)")
        for f in result.findings.resolved:
            lines.append(f"  - `{f['detector']}` — {f['title']}")
        lines.append("")

    if result.findings.modified:
        lines.append("## Findings with changed content")
        for entry in result.findings.modified:
            lines.append(f"  - `{entry['key']}` — severity/evidence changed")
        lines.append("")

    lines.append("## Per-collector artifact changes")
    for d in result.artifact_diffs:
        if d.mode == "summarize":
            delta = d.new_count - d.base_count
            sign = "+" if delta > 0 else ""
            lines.append(f"### `{d.collector}`  *(summarized)*")
            lines.append(f"  artifacts: {d.base_count} → {d.new_count}  ({sign}{delta})")
            continue
        if not (d.added or d.removed or d.modified):
            lines.append(f"### `{d.collector}`")
            lines.append(f"  no change ({d.new_count} artifacts)")
            continue
        lines.append(f"### `{d.collector}`")
        lines.append(f"  added: {len(d.added)} · removed: {len(d.removed)} · modified: {len(d.modified)}")
        for art in d.added[:10]:
            lines.append(f"    + {art['subject']}")
        if len(d.added) > 10:
            lines.append(f"    + … and {len(d.added) - 10} more")
        for art in d.removed[:10]:
            lines.append(f"    − {art['subject']}")
        if len(d.removed) > 10:
            lines.append(f"    − … and {len(d.removed) - 10} more")
        for m in d.modified[:5]:
            lines.append(f"    ~ {m['new']['subject']}  (changed: {', '.join(m['changed_fields'][:5])})")

    return "\n".join(lines)


# ---- HTML ----------------------------------------------------------- #


_HTML_STYLE = """
*{box-sizing:border-box}
body{margin:0;background:#0c0f14;color:#e6e8ec;font-family:-apple-system,Inter,system-ui,Segoe UI,sans-serif;line-height:1.55}
header.banner{display:flex;align-items:center;gap:24px;padding:24px 32px;background:linear-gradient(180deg,#181d27,#0c0f14);border-bottom:1px solid #2a2f3a}
header svg{width:96px;height:auto}
header h1{margin:0;font-size:26px;color:#d0c39a;letter-spacing:.5px}
header .meta{margin-top:4px;color:#aab0bd;font-size:13px;font-family:Iosevka,Menlo,Consolas,monospace}
.summary{padding:18px 32px;background:#10141c;border-bottom:1px solid #2a2f3a;display:flex;flex-wrap:wrap;gap:12px}
.pill{padding:8px 14px;border-radius:999px;font-size:12px;font-weight:700;color:#0c0f14;background:#7cc4ff}
.pill.added{background:#69d49a;color:#0a0f10}
.pill.removed{background:#ff6b6b;color:#0a0f10}
.pill.modified{background:#ffd152;color:#0a0f10}
.pill.persisted{background:#8a8f99;color:#0a0f10}
.pill.new{background:#ff9b3a;color:#0a0f10}
.pill.resolved{background:#69d49a;color:#0a0f10}
section{padding:24px 32px}
section h2{margin:0 0 14px;font-size:18px;color:#d0c39a;text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid #2a2f3a;padding-bottom:8px}
.coll{background:#10141c;border:1px solid #2a2f3a;border-radius:10px;margin-bottom:12px;overflow:hidden}
.coll header{padding:10px 16px;display:flex;gap:12px;align-items:center;cursor:pointer;background:#10141c}
.coll header:hover{background:#161b25}
.coll header .name{flex:1;font-family:Iosevka,Menlo,Consolas,monospace;font-size:13px;color:#cfd4df}
.coll header .counts{color:#8a8f99;font-size:12px;font-family:Iosevka,Menlo,Consolas,monospace}
.coll .body{display:none;padding:6px 16px 12px;border-top:1px solid #1d222d}
.coll.open .body{display:block}
.row{padding:6px 4px;border-bottom:1px solid #1d222d;font-family:Iosevka,Menlo,Consolas,monospace;font-size:12px;line-height:1.5}
.row:last-child{border:0}
.row .glyph{display:inline-block;width:14px;text-align:center;font-weight:700}
.row.add{color:#9cd28a}     .row.add .glyph{color:#69d49a}
.row.del{color:#ff9b9b}     .row.del .glyph{color:#ff6b6b}
.row.mod{color:#ffd9a3}     .row.mod .glyph{color:#ffd152}
.finding{background:#10141c;border:1px solid #2a2f3a;border-radius:10px;padding:14px 16px;margin-bottom:10px}
.finding .title{color:#e6e8ec;font-weight:600}
.finding .meta{color:#8a8f99;font-size:12px;font-family:Iosevka,Menlo,Consolas,monospace;margin:4px 0}
.finding .summary{color:#cfd4df;margin-top:6px;font-size:14px}
.badge{padding:3px 9px;border-radius:999px;font-size:11px;font-weight:700;color:#0c0f14;text-transform:uppercase;letter-spacing:.5px;margin-right:6px}
.badge.crit{background:#ff2e6c}
.badge.high{background:#ff9b3a}
.badge.med{background:#ffd152}
.badge.low{background:#7cc4ff}
.badge.info{background:#8a8f99}
.warn{padding:10px 14px;background:#3a2520;border:1px solid #ff6b6b;border-radius:8px;margin:10px 32px;color:#ffc7c0}

/* case identity panel */
.identity{padding:18px 32px;background:#10141c;border-bottom:1px solid #2a2f3a}
.identity h3{margin:0 0 12px;color:#d0c39a;font-size:14px;text-transform:uppercase;letter-spacing:.6px}
.identity .grid{display:grid;grid-template-columns:max-content 1fr 1fr;gap:6px 18px;align-items:center}
.identity .label{color:#8a8f99;font-size:11px;text-transform:uppercase;letter-spacing:.6px;font-family:Iosevka,Menlo,Consolas,monospace}
.identity .colhead{color:#d0c39a;font-size:12px;text-transform:uppercase;letter-spacing:.6px;font-family:Iosevka,Menlo,Consolas,monospace;border-bottom:1px solid #2a2f3a;padding-bottom:4px}
.identity .val{font-family:Iosevka,Menlo,Consolas,monospace;font-size:12px;color:#cfd4df;word-break:break-all}
.identity .val.dim{color:#8a8f99}
.identity .val.match{color:#69d49a}
.identity .val.differ{color:#ffd152}
.identity .algchip{display:inline-block;padding:1px 7px;font-size:10px;font-weight:700;border-radius:4px;background:#26230f;color:#d0c39a;margin-right:6px;letter-spacing:.5px}
"""


def _short(hex_str: str, head: int = 12, tail: int = 6) -> str:
    if not hex_str or len(hex_str) <= head + tail + 3:
        return hex_str or ""
    return f"{hex_str[:head]}…{hex_str[-tail:]}"


def _render_case_identity_panel(result: "DiffResult") -> str:
    base_tip = result.base_chain_tip or {}
    new_tip  = result.new_chain_tip  or {}
    base_art = (base_tip.get("artifacts") or {})
    new_art  = (new_tip.get("artifacts")  or {})
    base_fnd = (base_tip.get("findings")  or {})
    new_fnd  = (new_tip.get("findings")   or {})

    def row(label: str, b: str, n: str, *, mono: bool = True, hover: bool = False) -> str:
        b_full = b or ""
        n_full = n or ""
        b_show = _short(b_full) if mono else (b_full or "—")
        n_show = _short(n_full) if mono else (n_full or "—")
        cls = "val" + (" mono" if mono else "")
        match_cls = " match" if (b_full and n_full and b_full == n_full) else ""
        title_b = f' title="{_h(b_full)}"' if hover and b_full else ""
        title_n = f' title="{_h(n_full)}"' if hover and n_full else ""
        return (
            f"<div class='label'>{_h(label)}</div>"
            f"<div class='{cls}{match_cls}'{title_b}>{_h(b_show) if b_show else '—'}</div>"
            f"<div class='{cls}{match_cls}'{title_n}>{_h(n_show) if n_show else '—'}</div>"
        )

    parts = ["<section class='identity'>"]
    parts.append("<h3>Case identity &amp; chain-tip integrity</h3>")
    parts.append("<div class='grid'>")
    parts.append("<div></div><div class='colhead'>base case</div><div class='colhead'>new case</div>")
    parts.append(row("case id",
                     result.base_case_id, result.new_case_id, mono=True, hover=True))
    parts.append(row("host", result.base_host.get("node", ""), result.new_host.get("node", ""), mono=False))
    parts.append(row("collected (UTC)",
                     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(result.base_collected)) if result.base_collected else "",
                     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(result.new_collected))  if result.new_collected  else "",
                     mono=True))

    # Spacer + integrity sub-header
    parts.append("<div></div><div></div><div></div>")
    parts.append(
        "<div class='label'>chain tip</div>"
        "<div class='val dim'>" + "".join(
            f"<span class='algchip'>{_h(a)}</span>" for a in (base_tip.get('algorithms') or [])
        ) + "</div>"
        "<div class='val dim'>" + "".join(
            f"<span class='algchip'>{_h(a)}</span>" for a in (new_tip.get('algorithms') or [])
        ) + "</div>"
    )
    parts.append(row("artifacts · SHA-256",   base_art.get("sha256"),   new_art.get("sha256"),   mono=True, hover=True))
    parts.append(row("artifacts · SHA3-256",  base_art.get("sha3_256"), new_art.get("sha3_256"), mono=True, hover=True))
    parts.append(row("findings  · SHA-256",   base_fnd.get("sha256"),   new_fnd.get("sha256"),   mono=True, hover=True))
    parts.append(row("findings  · SHA3-256",  base_fnd.get("sha3_256"), new_fnd.get("sha3_256"), mono=True, hover=True))
    parts.append("</div></section>")
    return "".join(parts)


def _h(x: Any) -> str:
    return html.escape("" if x is None else str(x))


def render_diff_html(result: DiffResult) -> str:
    s = result.summary()
    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append(f"<title>diff — {_h(result.base_host.get('node'))} {_h(result.base_case_id[:8])} → {_h(result.new_case_id[:8])}</title>")
    parts.append(f"<style>{_HTML_STYLE}</style></head><body>")

    parts.append("<header class='banner'>")
    parts.append(svg_logo())
    parts.append("<div>")
    parts.append(f"<h1>case diff</h1>")
    parts.append(
        f"<div class='meta'>host <strong>{_h(result.base_host.get('node'))}</strong>"
        f" · generated {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())}</div>"
    )
    parts.append("</div></header>")

    if not result.same_host:
        parts.append(f"<div class='warn'>host fingerprints differ: base <code>{_h(result.base_host.get('node'))}</code> vs new <code>{_h(result.new_host.get('node'))}</code> — diff may not be meaningful</div>")

    # ---- Case identity panel (clearly labels the case_ids and shows
    #      both chain-tip integrity hashes per case)
    parts.append(_render_case_identity_panel(result))

    parts.append("<section class='summary'>")
    parts.append(f"<span class='pill added'>+{s['artifact_added']} added</span>")
    parts.append(f"<span class='pill removed'>−{s['artifact_removed']} removed</span>")
    parts.append(f"<span class='pill modified'>~{s['artifact_modified']} modified</span>")
    parts.append(f"<span class='pill new'>{s['finding_new']} new finding{'s' if s['finding_new']!=1 else ''}</span>")
    parts.append(f"<span class='pill resolved'>{s['finding_resolved']} resolved</span>")
    parts.append(f"<span class='pill persisted'>{s['finding_persisted']} persisted</span>")
    parts.append("</section>")

    # Findings sections
    if result.findings.new:
        parts.append("<section><h2>New findings</h2>")
        for f in result.findings.new:
            sev = f.get("severity", "low")
            parts.append("<div class='finding'>")
            parts.append(f"<span class='badge {_h(sev)}'>{_h(sev)}</span>")
            parts.append(f"<span class='title'>{_h(f['title'])}</span>")
            parts.append(f"<div class='meta'>detector {_h(f['detector'])} · mitre {_h(f.get('mitre',''))}</div>")
            parts.append(f"<div class='summary'>{_h(f.get('summary',''))}</div>")
            parts.append("</div>")
        parts.append("</section>")

    if result.findings.resolved:
        parts.append("<section><h2>Resolved findings</h2>")
        for f in result.findings.resolved:
            parts.append("<div class='finding'>")
            parts.append(f"<span class='title'>✓ {_h(f['title'])}</span>")
            parts.append(f"<div class='meta'>detector {_h(f['detector'])} — no longer firing</div>")
            parts.append("</div>")
        parts.append("</section>")

    if result.findings.modified:
        parts.append("<section><h2>Findings with changed content</h2>")
        for entry in result.findings.modified:
            parts.append("<div class='finding'>")
            parts.append(f"<span class='title'>{_h(entry['new']['title'])}</span>")
            parts.append(f"<div class='meta'>severity: {_h(entry['base']['severity'])} → {_h(entry['new']['severity'])}</div>")
            parts.append("</div>")
        parts.append("</section>")

    # Per-collector changes
    parts.append("<section><h2>Per-collector artifact changes</h2>")
    for d in result.artifact_diffs:
        is_noop = (d.mode == "track" and not (d.added or d.removed or d.modified))
        if d.mode == "summarize":
            delta = d.new_count - d.base_count
            sign = "+" if delta > 0 else ""
            parts.append("<div class='coll'>")
            parts.append("<header>")
            parts.append(f"<span class='name'>{_h(d.collector)}</span>")
            parts.append(f"<span class='counts'>(summarized) {d.base_count} → {d.new_count}  ({sign}{delta})</span>")
            parts.append("</header></div>")
            continue
        if is_noop:
            parts.append(f"<div class='coll'><header><span class='name'>{_h(d.collector)}</span>"
                         f"<span class='counts'>no change · {d.new_count} artifacts</span></header></div>")
            continue
        parts.append("<div class='coll'>")
        parts.append("<header onclick='this.parentNode.classList.toggle(\"open\")'>")
        parts.append(f"<span class='name'>{_h(d.collector)}</span>")
        parts.append(f"<span class='counts'>+{len(d.added)} / −{len(d.removed)} / ~{len(d.modified)}</span>")
        parts.append("</header>")
        parts.append("<div class='body'>")
        for art in d.added:
            parts.append(f"<div class='row add'><span class='glyph'>+</span> {_h(art.get('subject'))}</div>")
        for art in d.removed:
            parts.append(f"<div class='row del'><span class='glyph'>−</span> {_h(art.get('subject'))}</div>")
        for m in d.modified:
            cf = ", ".join(m.get("changed_fields", [])[:6])
            parts.append(f"<div class='row mod'><span class='glyph'>~</span> {_h(m['new'].get('subject'))} "
                         f"<span style='color:#8a8f99'>(changed: {_h(cf)})</span></div>")
        parts.append("</div></div>")
    parts.append("</section>")

    parts.append("</body></html>")
    return "".join(parts)
