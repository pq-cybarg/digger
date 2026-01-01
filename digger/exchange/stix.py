"""STIX 2.1 export.

We produce a syntactically valid STIX 2.1 bundle by hand so as not to
require the `stix2` package. The bundle contains:
  - One ``identity`` SDO for digger
  - One ``incident`` SDO summarizing the case (TLP-marked)
  - One ``indicator`` SDO per high/critical finding with IOCs
  - One ``attack-pattern`` SRO per ATT&CK technique referenced
  - ``relationship`` SROs binding indicators to attack patterns and to the incident
  - ``marking-definition`` objects for the TLP markings

Outputs JSON suitable for ingestion by TAXII servers, MISP (via stix2misp),
OpenCTI, etc.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Iterable, Optional


_DIGGER_IDENTITY_ID = "identity--00000000-0000-0000-0000-d166ed10001a"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def _uuid(kind: str) -> str:
    return f"{kind}--{uuid.uuid4()}"


# TLP 2.0 marking definitions per FIRST.org canonical IDs.
TLP_MARKING_IDS = {
    "TLP:CLEAR":         "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "TLP:GREEN":         "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "TLP:AMBER":         "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "TLP:AMBER+STRICT":  "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b03e",
    "TLP:RED":           "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}


def _digger_identity() -> dict:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _DIGGER_IDENTITY_ID,
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": "digger",
        "identity_class": "system",
        "description": "digger cross-platform endpoint forensics suite",
    }


def _ioc_to_pattern(kind: str, value: str) -> Optional[str]:
    kind = kind.lower()
    if kind == "sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"
    if kind == "md5":
        return f"[file:hashes.'MD5' = '{value}']"
    if kind == "ipv4":
        return f"[ipv4-addr:value = '{value}']"
    if kind == "domain":
        return f"[domain-name:value = '{value}']"
    if kind == "url":
        return f"[url:value = '{value.replace(chr(39), chr(92) + chr(39))}']"
    if kind == "path":
        return f"[file:name MATCHES '{value.replace(chr(39), chr(92) + chr(39))}']"
    return None


def _finding_to_indicators(finding: dict, tlp: str = "TLP:AMBER") -> list[dict]:
    iocs = ((finding.get("triage") or {}).get("iocs")) or finding.get("evidence", {}).get("iocs") or {}
    out: list[dict] = []
    for kind, values in (iocs.items() if isinstance(iocs, dict) else []):
        if not values:
            continue
        for v in values:
            pattern = _ioc_to_pattern(kind, str(v))
            if not pattern:
                continue
            out.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": _uuid("indicator"),
                "created": _now_iso(),
                "modified": _now_iso(),
                "created_by_ref": _DIGGER_IDENTITY_ID,
                "name": f"{kind} from {finding.get('title', '')[:96]}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": _now_iso(),
                "indicator_types": ["malicious-activity"],
                "labels": [finding.get("severity", "medium")],
                "object_marking_refs": [TLP_MARKING_IDS.get(tlp, TLP_MARKING_IDS["TLP:AMBER"])],
                "description": finding.get("summary", "")[:1000],
            })
    return out


def _mitre_to_attack_pattern(mitre_id: str) -> dict:
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": _uuid("attack-pattern"),
        "created": _now_iso(),
        "modified": _now_iso(),
        "created_by_ref": _DIGGER_IDENTITY_ID,
        "name": f"MITRE ATT&CK {mitre_id}",
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": mitre_id,
            "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
        }],
    }


def to_stix_bundle(
    case_meta: dict,
    findings: Iterable[dict],
    sharing_tlp: str = "TLP:AMBER",
) -> dict:
    objects: list[dict] = [_digger_identity()]
    # Add the TLP marking definition referenced
    objects.append({
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": TLP_MARKING_IDS.get(sharing_tlp, TLP_MARKING_IDS["TLP:AMBER"]),
        "created": _now_iso(),
        "definition_type": "tlp",
        "name": sharing_tlp,
        "definition": {"tlp": sharing_tlp.split(":")[-1].lower()},
    })

    # Build incident SDO for the case
    host = case_meta.get("host") or {}
    incident = {
        "type": "incident",
        "spec_version": "2.1",
        "id": _uuid("incident"),
        "created": _now_iso(),
        "modified": _now_iso(),
        "created_by_ref": _DIGGER_IDENTITY_ID,
        "name": f"digger case {case_meta.get('case_id', '?')} on {host.get('node', '?')}",
        "description": (case_meta.get("ai_case_summary") or {}).get("one_paragraph", ""),
        "object_marking_refs": [TLP_MARKING_IDS.get(sharing_tlp, TLP_MARKING_IDS["TLP:AMBER"])],
    }
    objects.append(incident)

    attack_pattern_by_id: dict[str, dict] = {}

    for f in findings:
        sev = f.get("severity", "low")
        if sev in ("info", "low"):
            continue
        indicators = _finding_to_indicators(f, tlp=(f.get("triage") or {}).get("tlp") or sharing_tlp)
        for ind in indicators:
            objects.append(ind)
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _uuid("relationship"),
                "created": _now_iso(),
                "modified": _now_iso(),
                "relationship_type": "indicates",
                "source_ref": ind["id"],
                "target_ref": incident["id"],
                "created_by_ref": _DIGGER_IDENTITY_ID,
            })
        mitre = f.get("mitre") or ""
        for m in [mitre] + list((f.get("triage") or {}).get("mitre_attack") or []):
            if not m:
                continue
            if m not in attack_pattern_by_id:
                ap = _mitre_to_attack_pattern(m)
                attack_pattern_by_id[m] = ap
                objects.append(ap)
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _uuid("relationship"),
                "created": _now_iso(),
                "modified": _now_iso(),
                "relationship_type": "uses",
                "source_ref": incident["id"],
                "target_ref": attack_pattern_by_id[m]["id"],
                "created_by_ref": _DIGGER_IDENTITY_ID,
            })

    return {
        "type": "bundle",
        "id": _uuid("bundle"),
        "objects": objects,
    }
