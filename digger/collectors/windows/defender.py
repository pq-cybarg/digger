"""Windows Defender state and detection history."""

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


class DefenderCollector(Collector):
    name = "windows.defender"
    category = "security_posture"
    supported_os = (OS.WINDOWS,)
    description = "Defender status, real-time/cloud protection, current threats, exclusions."

    def collect(self) -> Iterable[Artifact]:
        if shutil.which("powershell"):
            yield self.make(
                subject="get-mpcomputerstatus",
                raw=_ps("Get-MpComputerStatus | ConvertTo-Json -Depth 6"),
            )
            yield self.make(
                subject="get-mppreference",
                raw=_ps("Get-MpPreference | ConvertTo-Json -Depth 6"),
            )
            yield self.make(
                subject="get-mpthreat",
                raw=_ps("Get-MpThreat | ConvertTo-Json -Depth 6"),
            )
            yield self.make(
                subject="get-mpthreatdetection",
                raw=_ps("Get-MpThreatDetection | ConvertTo-Json -Depth 6"),
            )
