"""Windows firewall rules and profile state."""

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


class FirewallCollector(Collector):
    name = "windows.firewall"
    category = "security_posture"
    supported_os = (OS.WINDOWS,)
    description = "Windows Defender Firewall profiles and rules."

    def collect(self) -> Iterable[Artifact]:
        yield self.make(
            subject="profiles",
            raw=_ps("Get-NetFirewallProfile | ConvertTo-Json -Depth 4"),
        )
        yield self.make(
            subject="rules",
            raw=_ps(
                "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | "
                "Select-Object Name,DisplayName,Direction,Action,Profile,Enabled | "
                "ConvertTo-Json -Depth 4"
            ),
        )
