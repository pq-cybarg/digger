"""WMI persistence: EventFilter / EventConsumer / FilterToConsumerBinding."""

from __future__ import annotations

import shutil
import subprocess
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


def _ps(script: str) -> str:
    if not shutil.which("powershell"):
        return ""
    try:
        return subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=60, check=False,
        ).stdout
    except Exception:
        return ""


class WmiPersistenceCollector(Collector):
    name = "windows.wmi_persistence"
    category = "persistence"
    supported_os = (OS.WINDOWS,)
    description = "WMI EventFilter, EventConsumer, FilterToConsumerBinding (MITRE T1546.003)."

    def collect(self) -> Iterable[Artifact]:
        yield self.make(
            subject="event-filters",
            mitre="T1546.003",
            raw=_ps(r"Get-WmiObject -Namespace root\subscription -Class __EventFilter | ConvertTo-Json -Depth 4"),
        )
        yield self.make(
            subject="event-consumers",
            mitre="T1546.003",
            raw=_ps(r"Get-WmiObject -Namespace root\subscription -Class __EventConsumer | ConvertTo-Json -Depth 4"),
        )
        yield self.make(
            subject="bindings",
            mitre="T1546.003",
            raw=_ps(r"Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | ConvertTo-Json -Depth 4"),
        )
