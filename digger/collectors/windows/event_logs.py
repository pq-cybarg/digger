"""Windows event log parsing.

If `python-evtx` is installed and we have read access to the .evtx files,
we parse Security/System/Application/Sysmon. Otherwise we shell out to
`wevtutil` and capture the last N events of key channels.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS

# Channels and the last-N count we pull when shelling to wevtutil.
_CHANNELS = [
    ("Security", 5000),
    ("System", 5000),
    ("Application", 2000),
    ("Microsoft-Windows-Sysmon/Operational", 5000),
    ("Microsoft-Windows-PowerShell/Operational", 2000),
    ("Microsoft-Windows-Windows Defender/Operational", 2000),
    ("Microsoft-Windows-TaskScheduler/Operational", 2000),
    ("Microsoft-Windows-WMI-Activity/Operational", 2000),
    ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 2000),
]


class EventLogCollector(Collector):
    name = "windows.event_logs"
    category = "logs"
    supported_os = (OS.WINDOWS,)
    requires_admin = True
    description = "Security/System/Sysmon/PowerShell/Defender/etc. event channels."

    def collect(self) -> Iterable[Artifact]:
        if shutil.which("wevtutil"):
            for channel, n in _CHANNELS:
                try:
                    out = subprocess.run(
                        [
                            "wevtutil", "qe", channel,
                            f"/c:{n}", "/rd:true", "/f:xml",
                        ],
                        capture_output=True, text=True, timeout=120, check=False,
                    ).stdout
                    yield self.make(subject=f"channel:{channel}", count_hint=n, raw=out)
                except Exception:
                    continue
        # Best-effort direct .evtx parsing via python-evtx if installed
        try:
            from Evtx.Evtx import Evtx  # type: ignore[import-not-found]
            from Evtx.Views import evtx_file_xml_view  # type: ignore[import-not-found]
        except ImportError:
            return
        evtx_dir = Path("C:/Windows/System32/winevt/Logs")
        if not evtx_dir.exists():
            return
        for evtx_file in evtx_dir.glob("*.evtx"):
            try:
                with Evtx(str(evtx_file)) as ev:
                    rows = []
                    for i, (xml, _) in enumerate(evtx_file_xml_view(ev.get_file_header())):
                        rows.append(xml)
                        if i > 2000:
                            break
                    yield self.make(
                        subject=f"evtx:{evtx_file.name}",
                        path=str(evtx_file),
                        records=rows,
                    )
            except Exception:
                continue
