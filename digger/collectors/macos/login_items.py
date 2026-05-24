"""macOS user login items (modern: btm.plist; classic: System Events osascript)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from digger.collectors.macos._plist import read_plist
from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


class LoginItemsCollector(Collector):
    name = "macos.login_items"
    category = "persistence"
    supported_os = (OS.MACOS,)
    description = "Background Task Management (btm.plist) + classic login items."

    def collect(self) -> Iterable[Artifact]:
        # Modern: BackgroundTaskManagementAgent — the database underpinning macOS Ventura+'s
        # Login Items / Background Items pane. Apple has been moving the path; check both.
        btm_candidates = [
            Path("/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v8.btm"),
            Path("/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v7.btm"),
            Path("/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm"),
        ]
        for btm in btm_candidates:
            if btm.exists():
                try:
                    data = btm.read_bytes()
                    yield self.make(
                        subject=f"btm:{btm.name}",
                        path=str(btm),
                        size=len(data),
                        sha256=__import__("hashlib").sha256(data).hexdigest(),
                        mitre="T1547.015",
                    )
                except (PermissionError, OSError):
                    continue
        # Classic: osascript fallback
        if shutil.which("osascript"):
            try:
                out = subprocess.run(
                    ["osascript", "-e",
                     'tell application "System Events" to get the name of every login item'],
                    capture_output=True, text=True, timeout=10, check=False,
                ).stdout.strip()
                yield self.make(subject="login-items", names=out.split(", ") if out else [])
            except Exception:
                pass
