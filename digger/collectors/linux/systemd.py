"""systemd unit enumeration (system + per-user)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS

_UNIT_DIRS = [
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/system",
]


def _user_unit_dirs() -> list[Path]:
    """Per-user systemd unit dirs: ~/.config/systemd/user for every /home/*.

    Persistent attacker sessions often hide here because the install
    requires no root, only a logged-in user — and any process they
    spawn survives the user's logout if Linger is enabled.
    """
    out: list[Path] = []
    for parent in (Path("/home"), Path("/root")):
        if not parent.is_dir():
            continue
        try:
            entries = list(parent.iterdir()) if parent.name == "home" else [parent]
        except (PermissionError, OSError):
            continue
        for u in entries:
            d = u / ".config" / "systemd" / "user"
            if d.is_dir():
                out.append(d)
    return out


class SystemdCollector(Collector):
    name = "linux.systemd"
    category = "persistence"
    supported_os = (OS.LINUX,)
    description = "systemctl list-units, list-unit-files; full unit text from /etc/systemd."

    def collect(self) -> Iterable[Artifact]:
        if shutil.which("systemctl"):
            try:
                out = subprocess.run(
                    ["systemctl", "list-units", "--all", "--no-pager", "--no-legend", "--type=service"],
                    capture_output=True, text=True, timeout=30, check=False,
                ).stdout
                yield self.make(subject="list-units", raw=out, mitre="T1543.002")
            except Exception:
                pass
            try:
                out = subprocess.run(
                    ["systemctl", "list-unit-files", "--no-pager", "--no-legend"],
                    capture_output=True, text=True, timeout=30, check=False,
                ).stdout
                yield self.make(subject="list-unit-files", raw=out, mitre="T1543.002")
            except Exception:
                pass
            try:
                out = subprocess.run(
                    ["systemctl", "--user", "list-units", "--no-pager", "--no-legend"],
                    capture_output=True, text=True, timeout=30, check=False,
                ).stdout
                if out:
                    yield self.make(subject="user-list-units", raw=out, mitre="T1543.002")
            except Exception:
                pass
        for d in _UNIT_DIRS:
            p = Path(d)
            if not p.exists():
                continue
            units = []
            for unit in list(p.glob("*.service")) + list(p.glob("*.timer")) + list(p.glob("*.path")):
                try:
                    if unit.is_symlink():
                        target = str(unit.resolve())
                    else:
                        target = None
                    units.append({
                        "name": unit.name,
                        "path": str(unit),
                        "symlink_target": target,
                        "size": unit.stat().st_size,
                    })
                except OSError:
                    continue
            yield self.make(subject=f"unit-dir:{d}", path=d, count=len(units), entries=units)

        # Per-user systemd unit files. We capture the full text body since
        # the persistent-session detector needs to inspect ExecStart paths.
        for d in _user_unit_dirs():
            for unit in list(d.glob("*.service")) + list(d.glob("*.timer")) + list(d.glob("*.path")):
                try:
                    text = unit.read_text(errors="replace")
                except (PermissionError, OSError):
                    continue
                try:
                    st = unit.stat()
                except OSError:
                    continue
                yield self.make(
                    subject=f"user-unit:{unit}",
                    path=str(unit),
                    owner_uid=st.st_uid,
                    size=st.st_size,
                    mtime=st.st_mtime,
                    contents=text[:65536],
                    mitre="T1543.002",
                )
