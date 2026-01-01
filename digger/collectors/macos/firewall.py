"""macOS firewall posture: pf rules + Application Firewall state.

Both reads are pure observation. ``pfctl`` requires no privilege escalation
to read the active ruleset on most macOS configurations; we still degrade
gracefully if denied.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


def _run(cmd: list[str], timeout: int = 10) -> str:
    if not shutil.which(cmd[0]):
        return ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return r.stdout or r.stderr or ""
    except (subprocess.SubprocessError, OSError):
        return ""


class MacFirewallCollector(Collector):
    name = "macos.firewall"
    category = "security_posture"
    supported_os = (OS.MACOS,)
    description = "pf ruleset, pf info, and Application Firewall (socketfilterfw) state."

    def collect(self) -> Iterable[Artifact]:
        yield self.make(
            subject="pf-info",
            backend="pf",
            raw=_run(["pfctl", "-s", "info"]),
        )
        yield self.make(
            subject="pf-rules",
            backend="pf",
            raw=_run(["pfctl", "-sr"]),
        )
        yield self.make(
            subject="pf-nat",
            backend="pf",
            raw=_run(["pfctl", "-s", "nat"]),
        )
        # Application Firewall (separate from pf — controls per-application access)
        yield self.make(
            subject="appfw-state",
            backend="socketfilterfw",
            global_state=_run(["/usr/libexec/ApplicationFirewall/socketfilterfw",
                               "--getglobalstate"]),
            stealth_mode=_run(["/usr/libexec/ApplicationFirewall/socketfilterfw",
                               "--getstealthmode"]),
            block_all=_run(["/usr/libexec/ApplicationFirewall/socketfilterfw",
                            "--getblockall"]),
            logging=_run(["/usr/libexec/ApplicationFirewall/socketfilterfw",
                          "--getloggingmode"]),
        )
