"""MISP event export.

MISP events have a flat structure; we emit a single event with one
Attribute per IOC, plus Tags for MITRE ATT&CK and TLP. Compatible with
MISP 2.5+ via the standard JSON import.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Iterable


def _ioc_to_misp_attribute(kind: str, value: str) -> dict | None:
    kind = kind.lower()
    type_map = {
        "sha256": "sha256",
        "md5": "md5",
        "ipv4": "ip-dst",
        "domain": "domain",
        "url": "url",
        "path": "filename",
    }
    if kind not in type_map:
        return None
    return {
        "uuid": str(uuid.uuid4()),
        "type": type_map[kind],
        "category": "Network activity" if kind in {"ipv4", "domain", "url"} else "Payload delivery",
        "to_ids": True,
        "value": str(value),
        "comment": "",
        "timestamp": str(int(time.time())),
    }


def to_misp_event(
    case_meta: dict,
    findings: Iterable[dict],
    info: str | None = None,
    sharing_tlp: str = "TLP:AMBER",
    distribution: int = 0,   # 0 = your org only
    threat_level_id: int = 2,  # 1 high, 2 medium, 3 low, 4 undefined
    analysis: int = 1,        # 0 initial, 1 ongoing, 2 complete
) -> dict:
    host = case_meta.get("host") or {}
    event_info = info or f"digger case {case_meta.get('case_id', '?')} on {host.get('node', '?')}"
    attributes: list[dict] = []
    tags = [{"name": sharing_tlp, "exportable": True}]
    seen_mitre = set()
    for f in findings:
        if f.get("severity") in ("info", "low"):
            continue
        iocs = ((f.get("triage") or {}).get("iocs")) or (f.get("evidence") or {}).get("iocs") or {}
        for kind, values in (iocs.items() if isinstance(iocs, dict) else []):
            if not values:
                continue
            for v in values:
                attr = _ioc_to_misp_attribute(kind, v)
                if attr:
                    attributes.append(attr)
        mitre = f.get("mitre")
        if mitre and mitre not in seen_mitre:
            seen_mitre.add(mitre)
            tags.append({"name": f"misp-galaxy:mitre-attack-pattern=\"{mitre}\"", "exportable": True})
        for m in (f.get("triage") or {}).get("mitre_attack") or []:
            if m and m not in seen_mitre:
                seen_mitre.add(m)
                tags.append({"name": f"misp-galaxy:mitre-attack-pattern=\"{m}\"", "exportable": True})
    return {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": event_info,
            "date": time.strftime("%Y-%m-%d"),
            "timestamp": str(int(time.time())),
            "distribution": str(distribution),
            "threat_level_id": str(threat_level_id),
            "analysis": str(analysis),
            "published": False,
            "Attribute": attributes,
            "Tag": tags,
        }
    }
