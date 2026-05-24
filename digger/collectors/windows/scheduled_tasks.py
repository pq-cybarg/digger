"""Scheduled tasks via schtasks /query /XML."""

from __future__ import annotations

import shutil
import subprocess
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


class ScheduledTasksCollector(Collector):
    name = "windows.scheduled_tasks"
    category = "persistence"
    supported_os = (OS.WINDOWS,)
    description = "All Windows scheduled tasks, XML form (full trigger/principal/action detail)."

    def collect(self) -> Iterable[Artifact]:
        if not shutil.which("schtasks"):
            return
        try:
            out = subprocess.run(
                ["schtasks", "/query", "/XML", "ONE"],
                capture_output=True, text=True, timeout=60, check=False,
            ).stdout
            yield self.make(subject="schtasks-xml", raw=out)
        except Exception:
            pass
        try:
            out = subprocess.run(
                ["schtasks", "/query", "/FO", "CSV", "/V"],
                capture_output=True, text=True, timeout=60, check=False,
            ).stdout
            yield self.make(subject="schtasks-csv", raw=out)
        except Exception:
            pass
