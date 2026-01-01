"""macOS security posture: SIP, Gatekeeper, FileVault, XProtect/MRT versions."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from digger.collectors.macos._plist import read_plist
from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


def _run(cmd: list[str]) -> str:
    if not shutil.which(cmd[0]):
        return ""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except Exception:
        return ""


class SecurityPostureCollector(Collector):
    name = "macos.security_posture"
    category = "security_posture"
    supported_os = (OS.MACOS,)
    description = "SIP, Gatekeeper, FileVault, XProtect/MRT/AMRA versions."

    def collect(self) -> Iterable[Artifact]:
        yield self.make(subject="csrutil-status", raw=_run(["csrutil", "status"]))
        yield self.make(subject="spctl-status", raw=_run(["spctl", "--status"]))
        yield self.make(
            subject="fdesetup-status", raw=_run(["fdesetup", "status"])
        )
        # XProtect / MRT version plists
        for plist in [
            "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
            "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist",
            "/System/Library/CoreServices/MRT.app/Contents/Info.plist",
        ]:
            p = Path(plist)
            if p.exists():
                data = read_plist(p) or {}
                yield self.make(
                    subject=f"posture:{p.name}",
                    path=str(p),
                    bundle_id=data.get("CFBundleIdentifier"),
                    version=data.get("CFBundleShortVersionString"),
                )
