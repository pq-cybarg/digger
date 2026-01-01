"""sudoers configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


class SudoersCollector(Collector):
    name = "linux.sudoers"
    category = "identity"
    supported_os = (OS.LINUX,)
    description = "/etc/sudoers and /etc/sudoers.d/*"

    def collect(self) -> Iterable[Artifact]:
        for path in [Path("/etc/sudoers")]:
            if path.exists():
                try:
                    yield self.make(
                        subject="sudoers",
                        path=str(path),
                        contents=path.read_text(errors="replace"),
                    )
                except (PermissionError, OSError):
                    pass
        d = Path("/etc/sudoers.d")
        if d.is_dir():
            for f in d.iterdir():
                if not f.is_file():
                    continue
                try:
                    yield self.make(
                        subject=f"sudoers.d:{f.name}",
                        path=str(f),
                        contents=f.read_text(errors="replace"),
                    )
                except (PermissionError, OSError):
                    continue
