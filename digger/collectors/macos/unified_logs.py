"""macOS unified logs via `log show`.

Pulls a last-N-hour window of high-signal subsystems. Full unified-log
parsing requires `/private/var/db/diagnostics` and root.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS

# How far back to look — last 24 hours.
_LOG_PREDICATES = [
    ("authentication",
     'subsystem == "com.apple.opendirectoryd" OR subsystem == "com.apple.authd" '
     'OR processImagePath contains "loginwindow"'),
    ("network",
     'subsystem == "com.apple.network" OR processImagePath contains "configd"'),
    ("xprotect",
     'subsystem contains "XProtect" OR subsystem contains "Endpoint" '
     'OR processImagePath contains "XProtect"'),
    ("gatekeeper",
     'subsystem == "com.apple.syspolicy" OR eventMessage contains "Gatekeeper"'),
    ("sudo",
     'process == "sudo" OR eventMessage contains "sudo"'),
]


class UnifiedLogsCollector(Collector):
    name = "macos.unified_logs"
    category = "logs"
    supported_os = (OS.MACOS,)
    requires_admin = True
    description = "macOS unified-log slices for auth, network, XProtect, Gatekeeper, sudo."

    def collect(self) -> Iterable[Artifact]:
        if not shutil.which("log"):
            return
        for label, predicate in _LOG_PREDICATES:
            try:
                out = subprocess.run(
                    ["log", "show", "--last", "24h", "--predicate", predicate, "--style", "ndjson"],
                    capture_output=True, text=True, timeout=120, check=False,
                ).stdout
                yield self.make(
                    subject=f"unified-log:{label}",
                    predicate=predicate,
                    raw=out,
                )
            except Exception:
                continue
