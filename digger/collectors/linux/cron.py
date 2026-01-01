"""cron/anacron/at persistence."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS

_CRON_PATHS = [
    "/etc/crontab",
    "/etc/anacrontab",
]
_CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/var/spool/anacron",
    "/var/spool/at",
]


class CronCollector(Collector):
    name = "linux.cron"
    category = "persistence"
    supported_os = (OS.LINUX,)
    description = "/etc/cron* /etc/anacron* /var/spool/cron /var/spool/at"

    def collect(self) -> Iterable[Artifact]:
        for path in _CRON_PATHS:
            p = Path(path)
            if p.exists():
                try:
                    yield self.make(
                        subject=f"cron:{path}",
                        mitre="T1053.003",
                        path=path,
                        contents=p.read_text(errors="replace"),
                    )
                except (PermissionError, OSError):
                    continue
        for d in _CRON_DIRS:
            dp = Path(d)
            if not dp.is_dir():
                continue
            try:
                files = list(dp.iterdir())
            except PermissionError:
                continue
            entries = []
            for f in files:
                try:
                    st = f.stat()
                    contents = ""
                    if f.is_file() and st.st_size < 1_000_000:
                        try:
                            contents = f.read_text(errors="replace")
                        except (PermissionError, OSError):
                            contents = ""
                    entries.append({
                        "name": f.name,
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                        "mode": oct(st.st_mode),
                        "contents": contents,
                    })
                except OSError:
                    continue
            yield self.make(subject=f"cron-dir:{d}", mitre="T1053.003", path=d, entries=entries)
