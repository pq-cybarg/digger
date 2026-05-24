"""Recently modified files in common attacker drop locations."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS, current_os

# Lookback window: files modified in the last N days.
_LOOKBACK_DAYS = 14


def _drop_locations() -> list[Path]:
    home = Path.home()
    os_ = current_os()
    paths: list[Path] = [
        home / "Downloads",
        home / "Desktop",
        Path("/tmp"),
        Path("/var/tmp"),
    ]
    if os_ == OS.WINDOWS:
        paths += [
            Path(os.environ.get("TEMP", "C:/Windows/Temp")),
            Path(os.environ.get("LOCALAPPDATA", str(home / "AppData/Local"))) / "Temp",
            Path("C:/Windows/Temp"),
            Path(os.environ.get("ProgramData", "C:/ProgramData")),
            Path(os.environ.get("PUBLIC", "C:/Users/Public")),
        ]
    elif os_ == OS.MACOS:
        paths += [
            home / "Library/Caches",
            Path("/Library/Application Support"),
            Path("/var/folders"),
        ]
    elif os_ == OS.LINUX:
        paths += [
            Path("/dev/shm"),
            home / ".cache",
        ]
    return [p for p in paths if p.exists()]


def _walk(root: Path, cutoff: float, limit: int = 4000) -> Iterable[dict]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            try:
                st = os.lstat(full)
            except (PermissionError, OSError, FileNotFoundError):
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if st.st_mtime < cutoff:
                continue
            count += 1
            if count > limit:
                return
            yield {
                "path": full,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "ctime": st.st_ctime,
                "mode": oct(st.st_mode),
                "uid": st.st_uid if hasattr(st, "st_uid") else None,
                "gid": st.st_gid if hasattr(st, "st_gid") else None,
                "executable": bool(st.st_mode & 0o111),
            }


class RecentFilesCollector(Collector):
    name = "recent_files"
    category = "filesystem"
    description = f"Files modified in the last {_LOOKBACK_DAYS} days in common drop locations."

    def collect(self) -> Iterable[Artifact]:
        cutoff = time.time() - _LOOKBACK_DAYS * 86400
        for loc in _drop_locations():
            entries = list(_walk(loc, cutoff))
            if entries:
                yield self.make(
                    subject=f"recent:{loc}",
                    location=str(loc),
                    cutoff=cutoff,
                    count=len(entries),
                    entries=entries,
                )
