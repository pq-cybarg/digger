"""Authentication & shell history logs."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/btmp",
    "/var/log/wtmp",
    "/var/log/lastlog",
]


class AuthLogsCollector(Collector):
    name = "linux.auth_logs"
    category = "logs"
    supported_os = (OS.LINUX,)
    description = "auth.log/secure, last/lastb, journalctl auth slice."

    def collect(self) -> Iterable[Artifact]:
        for p in _LOG_PATHS:
            path = Path(p)
            if path.exists() and path.suffix not in {".log", ""}:
                continue
            if path.exists():
                try:
                    text = path.read_text(errors="replace")
                    yield self.make(
                        subject=f"log:{p}",
                        path=p,
                        size=len(text),
                        tail=text[-200_000:],
                    )
                except (PermissionError, OSError):
                    continue
        for cmd, label in [(["last", "-Fxw"], "last"), (["lastb", "-Fxw"], "lastb"), (["who"], "who")]:
            if not shutil.which(cmd[0]):
                continue
            try:
                out = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10, check=False
                ).stdout
                yield self.make(subject=label, raw=out)
            except Exception:
                continue
        if shutil.which("journalctl"):
            try:
                out = subprocess.run(
                    ["journalctl", "_COMM=sshd", "--since", "30 days ago", "--no-pager"],
                    capture_output=True, text=True, timeout=60, check=False,
                ).stdout
                yield self.make(subject="journalctl-sshd", raw=out)
            except Exception:
                pass
            try:
                out = subprocess.run(
                    ["journalctl", "_COMM=sudo", "--since", "30 days ago", "--no-pager"],
                    capture_output=True, text=True, timeout=60, check=False,
                ).stdout
                yield self.make(subject="journalctl-sudo", raw=out)
            except Exception:
                pass
