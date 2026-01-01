"""MITRE ATT&CK enterprise-attack STIX 2.1 fetcher.

Pulls the canonical ATT&CK Enterprise dataset (groups, software,
techniques + relationships) from the mitre-attack/attack-stix-data
repository and reduces it to the actors-list shape that
ThreatActorDetector consumes.

The full STIX bundle is ~15 MB and changes infrequently (ATT&CK ships
v17 / v18 / v19 minor + quarterly major releases). A 7-day refresh
cadence is plenty.

Output schema mirrors digger/rules/threat_actors/ttp_signatures.yaml:

    actors:
      - name: <primary name + aliases>
        severity: high
        attack_group_id: G0007
        aliases: [...]
        techniques: [{id, name}, ...]
        software:   [{id, name, type}, ...]
        notes: <one-line attribution + URL>

The detector treats ``software`` entries as proc_patterns (matched
case-insensitively against the cmdline). ``techniques`` are used for
MITRE-tag enrichment on each finding.
"""

from __future__ import annotations

import json
import re
import sys
import time

import requests


_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


def _external_id(obj: dict, source: str = "mitre-attack") -> str | None:
    """Extract an ATT&CK ID (G####, T####, S####) from external_references."""
    for ref in obj.get("external_references") or []:
        if (ref.get("source_name") or "").lower() == source:
            return ref.get("external_id")
    return None


def _safe_name(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()


def fetch_as_feed_bytes() -> bytes:
    """Download the STIX 2.1 bundle, reduce to the actor-centric schema."""
    from digger.opsec.airgap import assert_network_allowed
    assert_network_allowed("intel-feed:mitre_attack_groups")
    print("  [mitre-attack] downloading enterprise-attack.json ...",
          file=sys.stderr)
    try:
        r = requests.get(_STIX_URL, timeout=120)
        r.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"mitre-attack fetch failed: {exc}")
    bundle = r.json()
    actors = parse_bundle(bundle)
    print(f"  [mitre-attack] kept {len(actors)} groups",
          file=sys.stderr)
    return json.dumps({
        "source": "mitre/attack",
        "fetched_at": time.time(),
        "bundle_count": len(bundle.get("objects") or []),
        "actor_count": len(actors),
        "actors": actors,
    }, default=str).encode("utf-8")


def parse_bundle(bundle: dict) -> list[dict]:
    """Reduce the raw STIX 2.1 bundle into the ThreatActor schema."""
    objects = bundle.get("objects") or []
    by_id: dict[str, dict] = {o.get("id"): o for o in objects if o.get("id")}

    # Index relationships
    grp_to_software: dict[str, list[str]] = {}
    grp_to_technique: dict[str, list[str]] = {}
    for o in objects:
        if o.get("type") != "relationship":
            continue
        rt = o.get("relationship_type")
        if rt != "uses":
            continue
        src = o.get("source_ref") or ""
        dst = o.get("target_ref") or ""
        if not src.startswith("intrusion-set--"):
            continue
        if dst.startswith("malware--") or dst.startswith("tool--"):
            grp_to_software.setdefault(src, []).append(dst)
        elif dst.startswith("attack-pattern--"):
            grp_to_technique.setdefault(src, []).append(dst)

    actors: list[dict] = []
    for o in objects:
        if o.get("type") != "intrusion-set":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        group_id = _external_id(o, "mitre-attack")
        if not group_id:
            continue
        aliases = list(o.get("aliases") or [])
        primary = _safe_name(o.get("name") or aliases[0] if aliases else group_id)
        # Display name = primary + a few aliases
        display = primary
        extra_aliases = [a for a in aliases if a and a != primary]
        if extra_aliases:
            display += " / " + " / ".join(extra_aliases[:3])

        # Software the group uses (proc_patterns candidates)
        software = []
        for sid in grp_to_software.get(o["id"], []):
            s = by_id.get(sid)
            if not s or s.get("revoked"):
                continue
            sname = _safe_name(s.get("name") or "")
            sext = _external_id(s, "mitre-attack")
            if sname:
                software.append({
                    "id": sext or "",
                    "name": sname,
                    "type": s.get("type"),  # "malware" or "tool"
                    "aliases": list(s.get("aliases") or [])[:5],
                })

        # Techniques (for MITRE tag enrichment)
        techniques = []
        for tid in grp_to_technique.get(o["id"], []):
            t = by_id.get(tid)
            if not t or t.get("revoked"):
                continue
            tname = _safe_name(t.get("name") or "")
            text = _external_id(t, "mitre-attack")
            if text:
                techniques.append({"id": text, "name": tname})

        # Derive proc_patterns from software names + aliases.
        # We escape regex-special chars and word-boundary the literal.
        seen_pat: set[str] = set()
        proc_patterns: list[str] = []
        for s in software:
            for nm in [s["name"], *s.get("aliases", [])]:
                nm = nm.strip()
                # Reject extremely generic names that would produce FP storms
                if not nm or len(nm) < 3:
                    continue
                low = nm.lower()
                if low in seen_pat:
                    continue
                # Skip catchphrases like "PowerShell", "cmd.exe" themselves
                if low in {"powershell", "cmd.exe", "cmd", "ssh", "ftp",
                           "wget", "curl", "rsync", "tar", "zip", "ping"}:
                    continue
                seen_pat.add(low)
                proc_patterns.append(r"\b" + re.escape(nm) + r"\b")

        actors.append({
            "name": display,
            "primary_name": primary,
            "severity": "high",
            "attack_group_id": group_id,
            "aliases": [a for a in aliases if a != primary][:10],
            "proc_patterns": proc_patterns[:40],
            "techniques":    techniques[:30],
            "software":      software[:30],
            "mitre": techniques[0]["id"] if techniques else "",
            "notes": (
                f"Source: MITRE ATT&CK Enterprise {group_id}. "
                f"Software linked: {len(software)}, techniques: {len(techniques)}."
            ),
        })
    actors.sort(key=lambda a: a["attack_group_id"])
    return actors


def parse_feed_payload(raw: bytes) -> dict:
    return json.loads(raw)
