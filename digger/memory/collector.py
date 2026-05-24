"""Memory-region collector — captures suspect VM regions per process."""

from __future__ import annotations

from typing import Iterable

import psutil

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS, current_os
from digger.memory.maps import list_regions_for_pid


class MemoryRegionsCollector(Collector):
    name = "memory_regions"
    category = "memory"
    description = (
        "Per-process VM region snapshot. Records suspect regions only — "
        "anonymous-executable, RWX, or file-backed by a drop location. "
        "Cross-platform: /proc on Linux, vmmap on macOS, ctypes on Windows."
    )
    requires_admin = False   # works for own user; more processes with root

    def collect(self) -> Iterable[Artifact]:
        os_ = current_os()
        # On Windows our ctypes path can be slow if attempted against
        # every PID; cap to a manageable set.
        proc_limit = 500 if os_ == OS.WINDOWS else None

        seen = 0
        for proc in psutil.process_iter(attrs=["pid", "name", "username", "exe"]):
            try:
                info = proc.info
                pid = info["pid"]
                if not pid or pid in (0,):
                    continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            try:
                regions = list_regions_for_pid(pid)
            except Exception:
                continue
            if not regions:
                continue

            suspect = [r for r in regions if r.is_anonymous_exec or r.is_rwx or r.is_backing_in_drop]
            counts = {
                "total":            len(regions),
                "executable":       sum(1 for r in regions if r.executable),
                "rwx":              sum(1 for r in regions if r.is_rwx),
                "anonymous_exec":   sum(1 for r in regions if r.is_anonymous_exec),
                "backing_in_drop":  sum(1 for r in regions if r.is_backing_in_drop),
                "private":          sum(1 for r in regions if r.private),
            }

            yield self.make(
                subject=f"pid={pid} {info.get('name')}",
                pid=pid,
                name=info.get("name"),
                username=info.get("username"),
                exe=info.get("exe"),
                counts=counts,
                # Only ship suspect regions in the artifact body to keep
                # the case DB small; full region maps can be enormous.
                suspect_regions=[r.to_dict() for r in suspect[:200]],
                suspect_count=len(suspect),
            )
            seen += 1
            if proc_limit and seen >= proc_limit:
                break
