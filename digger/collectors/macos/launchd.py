"""macOS launchd persistence: LaunchAgents, LaunchDaemons.

Walks the four canonical directories and parses each plist. Picks up
ProgramArguments, RunAtLoad, KeepAlive, MachServices — everything the
ATT&CK 'Launchd' technique cares about.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from digger.collectors.macos._plist import read_plist
from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


_DIRS = [
    Path("/System/Library/LaunchDaemons"),
    Path("/System/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
    Path("/Library/LaunchAgents"),
    Path.home() / "Library/LaunchAgents",
]


class LaunchdCollector(Collector):
    name = "macos.launchd"
    category = "persistence"
    supported_os = (OS.MACOS,)
    description = "All LaunchAgent/LaunchDaemon plists, parsed."

    def collect(self) -> Iterable[Artifact]:
        for d in _DIRS:
            if not d.is_dir():
                continue
            for plist in d.glob("*.plist"):
                try:
                    data = read_plist(plist)
                except (PermissionError, OSError):
                    continue
                if data is None:
                    continue
                yield self.make(
                    subject=f"launchd:{plist}",
                    mitre="T1543.001",
                    path=str(plist),
                    location=str(d),
                    label=data.get("Label"),
                    program=data.get("Program"),
                    program_arguments=data.get("ProgramArguments"),
                    run_at_load=data.get("RunAtLoad"),
                    keep_alive=data.get("KeepAlive"),
                    start_interval=data.get("StartInterval"),
                    start_calendar=data.get("StartCalendarInterval"),
                    user_name=data.get("UserName"),
                    group_name=data.get("GroupName"),
                    mach_services=list((data.get("MachServices") or {}).keys()) if data.get("MachServices") else None,
                    watch_paths=data.get("WatchPaths"),
                    queue_directories=data.get("QueueDirectories"),
                    raw=data,
                )
