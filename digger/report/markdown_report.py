"""Markdown report renderer."""

from __future__ import annotations

import time
from typing import Any

from digger.core.evidence import EvidenceStore

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def render_markdown(store: EvidenceStore) -> str:
    host = store.get_meta("host") or {}
    counts = store.counts()
    summary = store.get_meta("ai_case_summary") or {}
    triage_run = store.get_meta("ai_triage_run") or {}

    parts: list[str] = []
    parts.append("# digger forensic report\n")
    parts.append(f"**Case:** `{store.get_meta('case_id')}`  ")
    parts.append(f"**Host:** `{host.get('node')}` ({host.get('os')} {host.get('release')})  ")
    parts.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())}  \n")

    if summary:
        parts.append("## Executive summary\n")
        parts.append(f"**Overall severity:** `{summary.get('overall_severity', 'n/a')}`\n")
        parts.append(summary.get("one_paragraph", "") + "\n")
        if summary.get("top_actions"):
            parts.append("**Top actions:**\n")
            for a in summary["top_actions"]:
                parts.append(f"  - {a}")
            parts.append("")
        if summary.get("if_compromised"):
            parts.append(f"**If compromised:** {summary['if_compromised']}\n")
        if summary.get("attribution_hint"):
            parts.append(f"**Attribution hint:** {summary['attribution_hint']}\n")

    parts.append("## Counts\n")
    parts.append(f"  - Artifacts: {counts['artifacts']}")
    parts.append(f"  - Findings: {counts['findings']}")
    for sev in _SEV_ORDER:
        parts.append(f"    - {sev}: {counts['by_severity'].get(sev, 0)}")
    parts.append("")

    parts.append("## Findings\n")
    findings = sorted(
        store.iter_findings(),
        key=lambda f: (_SEV_ORDER.index(f["severity"]) if f["severity"] in _SEV_ORDER else 99, f["title"]),
    )
    for f in findings:
        parts.append(f"### [{f['severity'].upper()}] {f['title']}")
        parts.append(f"*detector:* `{f['detector']}` *mitre:* `{f.get('mitre','')}` *uuid:* `{f['finding_uuid']}`\n")
        parts.append(f"{f['summary']}\n")
        if f.get("triage"):
            t = f["triage"]
            parts.append(f"**AI verdict:** `{t.get('verdict','?')}` (confidence {t.get('confidence','?')})  ")
            parts.append(f"**AI severity:** `{t.get('severity','?')}`  ")
            parts.append(f"**AI summary:** {t.get('one_line','')}\n")
            if t.get("rationale"):
                parts.append(f"_Rationale:_ {t['rationale']}\n")
            if t.get("next_steps"):
                parts.append("**Next steps:**\n")
                for ns in t["next_steps"]:
                    parts.append(f"  - {ns}")
                parts.append("")
        parts.append("---\n")

    parts.append("## Chain tip\n")
    parts.append("```json")
    import json
    parts.append(json.dumps(store.chain_tip(), indent=2))
    parts.append("```")

    if triage_run:
        parts.append("\n## Triage run\n")
        parts.append("```json")
        parts.append(json.dumps(triage_run, indent=2, default=str))
        parts.append("```")

    return "\n".join(parts)
