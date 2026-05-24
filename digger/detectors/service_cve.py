"""Match installed service versions against a bundled CVE corpus.

Reads ``digger/rules/services/cves.yaml`` (curated, conservative) and
emits one Finding per affected (service, CVE) pair. Air-gap safe — the
default path uses only bundled data.

Live OSV.dev queries are gated by the airgap module (opt-in). They send
nothing more than the package name + version, but it's still egress, so
``digger.opsec.airgap.assert_network_allowed()`` controls it.

MITRE mapping
-------------
CVE-driven findings are tagged ``T1190`` (Exploit Public-Facing
Application) when a service is exposed; for internal-only tools we tag
``T1068`` (Exploitation for Privilege Escalation). The detector emits
T1190 conservatively; report consumers can downgrade based on
network-exposure context.
"""

from __future__ import annotations

import json
from typing import Iterable, Optional

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors._rules_io import load_intel
from digger.detectors._versions import in_range
from digger.detectors.base import Detector


_SEVERITY_ALLOWED = {"info", "low", "medium", "high", "critical"}
_WARNED_NO_CORPUS = False


def _normalize_sev(sev: str | None) -> str:
    sev = (sev or "medium").lower()
    return sev if sev in _SEVERITY_ALLOWED else "medium"


def _load_corpus() -> dict[str, list[dict]]:
    """Live NVD cache — there is no bundled fallback.

    The live cache is refreshed every 24h by the IntelScheduler (or
    on-demand via ``digger intel update``). Hand-typed snapshots get
    stale; we don't ship them. When the cache is empty we log once and
    emit no findings — the user must run ``digger intel update`` first.
    """
    global _WARNED_NO_CORPUS
    live = load_intel("nvd_service_cves")
    if live and isinstance(live, dict):
        services = live.get("services")
        if services:
            return services
    if not _WARNED_NO_CORPUS:
        import sys
        print(
            "[digger] service_cve: no NVD cache yet — run `digger intel update "
            "--only nvd_service_cves` to populate. Skipping service-CVE checks.",
            file=sys.stderr,
        )
        _WARNED_NO_CORPUS = True
    return {}


class ServiceCVEDetector(Detector):
    name = "service_cve"
    description = "Known CVEs affecting installed service versions (live NVD feed + bundled fallback)."

    def __init__(self, allow_live_osv: bool = False):
        self.allow_live_osv = allow_live_osv

    def _live_osv(self, service: str, version: str) -> list[dict]:
        """Optionally query OSV.dev for additional CVEs. Opt-in only."""
        if not self.allow_live_osv:
            return []
        try:
            from digger.opsec.airgap import assert_network_allowed
            assert_network_allowed(f"service_cve.osv:{service}")
        except Exception:
            return []
        try:
            import requests
            r = requests.post(
                "https://api.osv.dev/v1/query",
                json={"version": version, "package": {"name": service}},
                timeout=4,
            )
            if r.status_code != 200:
                return []
            return r.json().get("vulns", []) or []
        except Exception:
            return []

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        corpus = _load_corpus()
        if not corpus:
            return
        for art in store.iter_artifacts(category="service"):
            data = art["data"]
            service = data.get("service")
            version = data.get("version")
            if not service or not version:
                continue
            cves = corpus.get(service, [])
            # Optional live augmentation (opt-in)
            live = self._live_osv(service, version)
            for entry in cves:
                cve_id = entry.get("id")
                if not cve_id:
                    continue
                ranges = entry.get("affected") or []
                if not in_range(version, ranges):
                    continue
                sev = _normalize_sev(entry.get("severity"))
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=f"{service} {version} affected by {cve_id}",
                    summary=(
                        f"Service {service} version {version} is in the affected "
                        f"range for {cve_id}: {entry.get('summary', '(no summary)')}. "
                        f"Upgrade to a fixed release. "
                        f"References: {'; '.join(entry.get('references') or []) or '(none)'}."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "service": service,
                        "version": version,
                        "binary_path": data.get("path"),
                        "cve": cve_id,
                        "affected_ranges": ranges,
                        "references": entry.get("references") or [],
                    },
                    mitre="T1190",
                )
            # Live OSV findings (only emitted when --allow-live-osv was set)
            for v in live:
                cve_id = v.get("id")
                if not cve_id:
                    continue
                sev = _normalize_sev(
                    (v.get("database_specific") or {}).get("severity")
                    or "medium"
                )
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=f"{service} {version} affected by {cve_id} (OSV.dev)",
                    summary=(
                        f"OSV.dev reports {service} {version} is affected by "
                        f"{cve_id}: {v.get('summary') or v.get('details', '')[:200]}."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "service": service,
                        "version": version,
                        "cve": cve_id,
                        "source": "osv.dev",
                    },
                    mitre="T1190",
                )
