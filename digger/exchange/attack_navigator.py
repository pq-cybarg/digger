"""MITRE ATT&CK Navigator layer JSON export.

Compatible with https://mitre-attack.github.io/attack-navigator/ —
load the JSON via 'Open Existing Layer' / 'Upload from local' to get
a tinted matrix view of the techniques digger observed on this host.
"""

from __future__ import annotations

import time
from typing import Iterable


_SEVERITY_SCORE = {
    "info": 25,
    "low": 50,
    "medium": 75,
    "high": 90,
    "critical": 100,
}

_SEVERITY_COLOR = {
    "info": "#9cd28a",
    "low": "#7cc4ff",
    "medium": "#ffd152",
    "high": "#ff9b3a",
    "critical": "#ff2e6c",
}


def to_navigator_layer(
    case_meta: dict,
    findings: Iterable[dict],
    layer_name: str | None = None,
    domain: str = "enterprise-attack",
    navigator_version: str = "5.1.0",
    layer_version: str = "4.5",
) -> dict:
    host = case_meta.get("host") or {}
    name = layer_name or f"digger {case_meta.get('case_id', '?')[:8]} {host.get('node', '?')}"
    techniques: dict[str, dict] = {}
    for f in findings:
        # gather all mitre IDs referenced
        all_ids: list[str] = []
        if f.get("mitre"):
            all_ids.append(f["mitre"])
        all_ids += list((f.get("triage") or {}).get("mitre_attack") or [])
        for m in all_ids:
            if not m or not m.startswith("T"):
                continue
            cur = techniques.get(m)
            sev = f.get("severity", "low")
            if not cur or _SEVERITY_SCORE.get(sev, 0) > cur["score"]:
                techniques[m] = {
                    "techniqueID": m,
                    "score": _SEVERITY_SCORE.get(sev, 50),
                    "color": _SEVERITY_COLOR.get(sev, "#7cc4ff"),
                    "comment": f.get("title", "")[:200],
                    "enabled": True,
                    "showSubtechniques": "." in m,
                }
    return {
        "name": name,
        "versions": {
            "attack": "16",
            "navigator": navigator_version,
            "layer": layer_version,
        },
        "domain": domain,
        "description": f"digger findings for case {case_meta.get('case_id', '?')}",
        "techniques": list(techniques.values()),
        "gradient": {
            "colors": ["#9cd28a", "#ffd152", "#ff2e6c"],
            "minValue": 25,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "info", "color": _SEVERITY_COLOR["info"]},
            {"label": "low", "color": _SEVERITY_COLOR["low"]},
            {"label": "medium", "color": _SEVERITY_COLOR["medium"]},
            {"label": "high", "color": _SEVERITY_COLOR["high"]},
            {"label": "critical", "color": _SEVERITY_COLOR["critical"]},
        ],
        "metadata": [
            {"name": "tool", "value": "digger"},
            {"name": "case_id", "value": str(case_meta.get("case_id", ""))},
            {"name": "generated_at", "value": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        ],
    }
