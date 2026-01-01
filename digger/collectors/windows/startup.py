"""Startup folder contents (common low-rent persistence)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


class StartupFoldersCollector(Collector):
    name = "windows.startup_folders"
    category = "persistence"
    supported_os = (OS.WINDOWS,)
    description = "Per-user and all-users Start Menu Startup folders."

    def collect(self) -> Iterable[Artifact]:
        roaming = os.environ.get("APPDATA", "")
        program_data = os.environ.get("ProgramData", "C:/ProgramData")
        locations = [
            Path(roaming) / "Microsoft/Windows/Start Menu/Programs/Startup",
            Path(program_data) / "Microsoft/Windows/Start Menu/Programs/StartUp",
        ]
        for loc in locations:
            if not loc.exists():
                continue
            entries = []
            for f in loc.iterdir():
                try:
                    st = f.stat()
                    entries.append({
                        "name": f.name,
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                    })
                except OSError:
                    continue
            yield self.make(subject=f"startup:{loc}", path=str(loc), entries=entries)
