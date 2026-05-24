"""Windows services snapshot."""

from __future__ import annotations

from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


class ServicesCollector(Collector):
    name = "windows.services"
    category = "persistence"
    supported_os = (OS.WINDOWS,)
    description = "All Windows services with start type, binary path, account, status."

    def collect(self) -> Iterable[Artifact]:
        try:
            import psutil  # already a dependency
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                except Exception:
                    continue
                yield self.make(
                    subject=f"svc={svc.name()}",
                    **info,
                )
        except (AttributeError, ImportError):
            return
