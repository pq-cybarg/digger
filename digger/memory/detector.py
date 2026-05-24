"""Memory-region anomaly detector — runs over MemoryRegionsCollector artifacts.

Extension over the pure region-level checks: when a process has any of
the memory anomalies AND its parent process is a listening network
service (sshd, nginx, httpd, php-fpm, java, mysqld, postgres, …), the
severity is escalated to *critical* — the canonical "RCE landed in this
process" signature. This is correlated locally; no cross-detector
plumbing required.
"""

from __future__ import annotations

from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# Listening-service parents that should never have a child with shellcode
# / RWX / drop-loaded modules. Kept in sync with
# ``digger.detectors.exploitation._LISTENING_SERVICE_PARENTS`` — we import
# at use-site to avoid an import cycle.
def _listening_service_set() -> set[str]:
    try:
        from digger.detectors.exploitation import _LISTENING_SERVICE_PARENTS
        return set(_LISTENING_SERVICE_PARENTS.keys())
    except Exception:
        return set()


def _parent_pid_map(store: EvidenceStore) -> dict[int, dict]:
    """One-pass scan: pid -> {name, ppid}."""
    out: dict[int, dict] = {}
    for art in store.iter_artifacts(collector="processes"):
        d = art["data"]
        pid = d.get("pid")
        if pid is None:
            continue
        nm = (d.get("name") or "").lower()
        if "/" in nm:
            nm = nm.rsplit("/", 1)[1]
        if "\\" in nm:
            nm = nm.rsplit("\\", 1)[1]
        out[pid] = {"name": nm, "ppid": d.get("ppid")}
    return out


def _parent_service(procs: dict[int, dict], pid: int,
                    services: set[str]) -> str | None:
    """Return the parent's process name if it's a listening service."""
    me = procs.get(pid)
    if not me:
        return None
    ppid = me.get("ppid")
    if ppid is None:
        return None
    parent = procs.get(ppid)
    if not parent:
        return None
    pname = parent.get("name") or ""
    return pname if pname in services else None


class MemoryAnomalyDetector(Detector):
    name = "memory_anomaly"
    description = (
        "RWX regions, anonymous executable regions, and libraries loaded "
        "from drop locations — three high-signal injection / shellcode "
        "tells visible from VM region info alone. Severity escalates to "
        "critical when the affected process is parented by a listening "
        "network service (post-RCE landing pattern)."
    )

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        services = _listening_service_set()
        procs = _parent_pid_map(store) if services else {}

        for art in store.iter_artifacts(collector="memory_regions"):
            d = art["data"]
            pid = d.get("pid")
            name = d.get("name")
            counts = d.get("counts") or {}
            regions = d.get("suspect_regions") or []
            parent_svc = _parent_service(procs, pid, services) if pid is not None else None

            # 1. RWX regions — strong injection signal.
            rwx = [r for r in regions if r.get("is_rwx")]
            if rwx:
                sev = "critical" if parent_svc else "high"
                rce_suffix = (
                    f" + parented by listening service {parent_svc!r} → "
                    "post-RCE landing pattern" if parent_svc else ""
                )
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=f"RWX region(s) in pid {pid} ({name}){rce_suffix}",
                    summary=(
                        f"Process {name} (pid {pid}) holds {len(rwx)} "
                        f"region(s) that are simultaneously readable, "
                        "writable, and executable. Some legitimate JIT "
                        "runtimes do this — but a plain native process "
                        "with RWX pages is strongly suggestive of code "
                        "injection." + (
                            f" The process's parent is {parent_svc}, a "
                            "listening network service; the combination of "
                            "injection-shaped memory + network-service "
                            "parentage is the canonical post-RCE signature."
                            if parent_svc else ""
                        )
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"pid": pid, "name": name,
                              "count": len(rwx),
                              "parent_service": parent_svc,
                              "sample": rwx[:5]},
                    mitre="T1055",
                )

            # 2. Anonymous executable regions — shellcode landing pads.
            anon = [r for r in regions if r.get("is_anonymous_exec") and not r.get("is_rwx")]
            # de-dup: if it's already in the rwx list, don't double-fire
            if anon:
                sev = "critical" if parent_svc else "medium"
                rce_suffix = (
                    f" + parented by listening service {parent_svc!r}"
                    if parent_svc else ""
                )
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=f"Anonymous executable region(s) in pid {pid} ({name}){rce_suffix}",
                    summary=(
                        f"Process {name} (pid {pid}) holds {len(anon)} "
                        "executable VM region(s) with no on-disk file "
                        "backing. Plausible for some runtime stubs but "
                        "rare in well-behaved processes; characteristic "
                        "of shellcode." + (
                            f" The process's parent is {parent_svc}, a "
                            "listening network service — post-RCE pattern."
                            if parent_svc else ""
                        )
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"pid": pid, "name": name,
                              "count": len(anon),
                              "parent_service": parent_svc,
                              "sample": anon[:5]},
                    mitre="T1055.002",
                )

            # 3. Library loaded from a drop location.
            drop = [r for r in regions if r.get("is_backing_in_drop")]
            if drop:
                sev = "critical" if parent_svc else "high"
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=f"Loaded module from drop location in pid {pid} ({name})",
                    summary=(
                        f"Process {name} (pid {pid}) has mapped one or "
                        "more modules from a writable/world-shared "
                        "directory (/tmp, /Users/Shared, %TEMP%). "
                        "Sideloaded malicious libraries appear this way." + (
                            f" The process is parented by {parent_svc} — "
                            "library-side-loading via RCE is a textbook "
                            "T1574.001 chain."
                            if parent_svc else ""
                        )
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"pid": pid, "name": name,
                              "parent_service": parent_svc,
                              "modules": [r.get("backing") for r in drop][:10]},
                    mitre="T1574.001",
                )
