"""IOC matching.

Reads simple text feeds of indicators (one per line, # comments allowed)
from `digger/rules/iocs/` and any user-supplied directory. Supported
indicator types are auto-detected by format:

    sha256   — 64 hex chars
    md5      — 32 hex chars
    domain   — contains a dot, no slash, no scheme
    ipv4     — dotted quad
    url      — starts with http:// or https://
    path     — anything containing a path separator

All artifacts are then scanned for substring/exact matches against the
loaded indicators.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector

_RULES_DIR = Path(__file__).parent.parent / "rules" / "iocs"

_HEX64 = re.compile(r"^[a-fA-F0-9]{64}$")
_HEX32 = re.compile(r"^[a-fA-F0-9]{32}$")
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _classify(token: str) -> str | None:
    t = token.strip()
    if not t or t.startswith("#"):
        return None
    if _HEX64.match(t):
        return "sha256"
    if _HEX32.match(t):
        return "md5"
    if _IPV4.match(t):
        return "ipv4"
    if t.startswith(("http://", "https://")):
        return "url"
    if "/" in t or "\\" in t:
        return "path"
    if "." in t:
        return "domain"
    return None


def _load_iocs(*dirs: Path) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"sha256": set(), "md5": set(), "ipv4": set(),
                                 "url": set(), "path": set(), "domain": set()}
    for d in dirs:
        if not d.is_dir():
            continue
        for f in d.glob("*.txt"):
            try:
                for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    kind = _classify(line)
                    if kind:
                        out[kind].add(line.strip().lower())
            except OSError:
                continue
    return out


class IocDetector(Detector):
    name = "ioc"
    description = "Match collected hashes, IPs, domains, URLs, paths against IOC feeds."

    def __init__(self, extra_dirs: Iterable[Path] = ()):
        self.extra_dirs = list(extra_dirs)

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        iocs = _load_iocs(_RULES_DIR, *self.extra_dirs)
        if not any(iocs.values()):
            return
        # Hashes — check process exe hashes
        for art in store.iter_artifacts(collector="processes"):
            h = art["data"].get("exe_sha256")
            if h and h.lower() in iocs["sha256"]:
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=f"IOC hash match: process exe {art['data'].get('name')}",
                    summary=f"SHA-256 of running process executable matches IOC feed: {h}",
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"sha256": h, "process": art["data"]},
                    mitre="T1059",
                )
        # Network connections + browser history — IP/domain/URL substring
        for art in store.iter_artifacts():
            blob = json.dumps(art["data"], default=str).lower()
            for ip in iocs["ipv4"]:
                if ip in blob:
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=f"IOC IP match: {ip}",
                        summary=f"IP {ip} referenced in artifact {art['subject']} ({art['collector']}).",
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"indicator": ip, "kind": "ipv4"},
                    )
            for dom in iocs["domain"]:
                if dom in blob:
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=f"IOC domain match: {dom}",
                        summary=f"Domain {dom} referenced in artifact {art['subject']} ({art['collector']}).",
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"indicator": dom, "kind": "domain"},
                    )
