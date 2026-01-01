"""Generic persistence outlier detection across platforms.

Looks at every persistence artifact (launchd plist, cron entry, systemd unit,
registry Run value, scheduled task XML) and flags entries whose command
lives in a writable user directory or temp directory — the highest-signal
"this shouldn't be there" cue.
"""

from __future__ import annotations

import os
import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector

_RED_FLAG_PATHS = [
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/Users/Shared/", "/private/tmp/",
    "/Users/Public/",
    r"\\Temp\\", r"\\AppData\\Local\\Temp\\",
    r"\\Users\\Public\\",
]


def _looks_red(text: str | None) -> str | None:
    if not text:
        return None
    for needle in _RED_FLAG_PATHS:
        if needle in text:
            return needle
    return None


def _is_apple_system_launchd(art: dict, data: dict) -> bool:
    """Recognize Apple-shipped LaunchDaemons/Agents that legitimately
    reference /tmp/ (Unix socket paths, scratch dirs for system
    services). The combination of "lives in /System/Library/Launch{Daemons,Agents}/"
    + ``com.apple.*`` Label is unforgeable without already having
    rooted SIP, in which case the persistence-outlier detector is the
    wrong place to catch the compromise anyway.
    """
    if art.get("collector") != "macos.launchd":
        return False
    path = (data.get("path") or "").lower()
    if not (path.startswith("/system/library/launchdaemons/")
            or path.startswith("/system/library/launchagents/")):
        return False
    label = (data.get("label") or "").lower()
    return label.startswith("com.apple.")


class PersistenceDetector(Detector):
    name = "persistence_outlier"
    description = "Persistence entries referencing writable/temp paths."

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(category="persistence"):
            data = art["data"]
            # Apple's own LaunchDaemons/Agents that ship in
            # /System/Library/ legitimately reference /tmp/ for Unix
            # socket paths (kdumpd, nfsconf, etc). Don't fire on them.
            if _is_apple_system_launchd(art, data):
                continue
            blob = ""
            # Collapse to one searchable blob — fields differ wildly across collectors.
            for k in (
                "program", "program_arguments", "contents", "raw", "values",
                "entries", "exe", "command",
            ):
                v = data.get(k)
                if v is None:
                    continue
                if isinstance(v, str):
                    blob += v + "\n"
                else:
                    blob += repr(v) + "\n"
            hit = _looks_red(blob)
            if hit:
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=f"Persistence entry references {hit}",
                    summary=(
                        f"Persistence artifact {art['subject']} (collector "
                        f"{art['collector']}) references a writable/world-shared "
                        f"path containing '{hit}'. Programs in persistence points "
                        "should live in protected system or signed app directories, "
                        "not user-writable scratch space."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"subject": art["subject"], "match": hit},
                    mitre=data.get("mitre", "T1547"),
                )

            # Unsigned/unusual binary references — heuristic: things in /Users, /home, /tmp.
            paths = re.findall(r"/(?:Users|home|tmp|var/tmp|Library)\S+", blob)
            paths += re.findall(r"[A-Z]:\\\\Users\\\\[^\"\s]+", blob)
            paths = [p for p in paths if any(p.endswith(ext) for ext in (".sh", ".py", ".pl", ".exe", ".dll", ".dylib", ".bin"))]
            if paths:
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=f"Persistence entry references unusual binary path",
                    summary=(
                        f"Persistence artifact {art['subject']} references binaries "
                        f"in user/scratch directories: {paths[:5]}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"paths": paths[:10]},
                    mitre=data.get("mitre", "T1547"),
                )
