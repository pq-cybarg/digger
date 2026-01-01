"""Named-threat-actor TTP detector.

Pattern-matches collected artifacts against actor TTPs sourced (in
order of preference) from:

  1. Live MITRE ATT&CK Enterprise feed (``load_intel("mitre_attack_groups")``)
     — groups + their associated software, refreshed weekly. This is the
     canonical, authoritative source.

  2. Bundled ``threat_actors/ttp_signatures.yaml`` — small handful of
     compact behavioral signatures that capture patterns the ATT&CK
     software list doesn't (specific cmdline shapes, GTFOBins-style
     uses). Kept as additive supplement, not replacement.

Attribution is a heuristic — multiple actors share TTPs — so we report
the matched actor and what was matched, not a definitive call.
"""

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors._rules_io import load_intel, load_yaml
from digger.detectors.base import Detector


def _live_actors() -> list[dict]:
    """Return actors derived from the live MITRE ATT&CK feed, or []."""
    data = load_intel("mitre_attack_groups")
    if not data or not isinstance(data, dict):
        return []
    return list(data.get("actors") or [])


def _bundled_actors() -> list[dict]:
    """Return actors from the bundled ttp_signatures.yaml seed."""
    rules = load_yaml("threat_actors/ttp_signatures.yaml") or {}
    return list(rules.get("actors") or [])


def _merge_actors(live: list[dict], bundled: list[dict]) -> list[dict]:
    """Live actors first (preserve order); bundled entries that don't
    duplicate an existing primary_name are appended."""
    seen: set[str] = set()
    out: list[dict] = []
    for a in live + bundled:
        key = (a.get("primary_name") or a.get("name") or "").lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    return out


class ThreatActorDetector(Detector):
    name = "threat_actor"
    description = (
        "Behavioral TTPs associated with named threat-actor groups. Live "
        "MITRE ATT&CK Enterprise feed + bundled supplemental patterns."
    )

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        actors = _merge_actors(_live_actors(), _bundled_actors())

        # Build compiled regex pairs
        compiled = []
        for actor in actors:
            proc_pats = [re.compile(p, re.I) for p in actor.get("proc_patterns", [])]
            file_pats = [re.compile(p, re.I) for p in actor.get("file_path_patterns", [])]
            compiled.append((actor, proc_pats, file_pats))

        for art in store.iter_artifacts(collector="processes"):
            cmd = " ".join(art["data"].get("cmdline") or [])
            exe = art["data"].get("exe") or ""
            for actor, proc_pats, file_pats in compiled:
                for pat in proc_pats:
                    if pat.search(cmd):
                        yield Finding(
                            detector=self.name,
                            severity=actor.get("severity", "high"),
                            title=f"{actor['name']} TTP match: pid {art['data'].get('pid')}",
                            summary=(
                                f"Process command line matches behavioral signature attributed "
                                f"to {actor['name']}: `{pat.pattern}`. "
                                f"{actor.get('notes', '')}\n\nCmdline: {cmd[:300]}"
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={"actor": actor["name"], "pattern": pat.pattern, "cmdline": cmd},
                            mitre=actor.get("mitre", ""),
                        )
                        break
                for pat in file_pats:
                    if pat.search(exe):
                        yield Finding(
                            detector=self.name,
                            severity=actor.get("severity", "high"),
                            title=f"{actor['name']} path signature: {exe}",
                            summary=(
                                f"Process executable path {exe} matches a path signature "
                                f"attributed to {actor['name']}: `{pat.pattern}`."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={"actor": actor["name"], "pattern": pat.pattern, "exe": exe},
                            mitre=actor.get("mitre", ""),
                        )
                        break
