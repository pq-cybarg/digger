"""Loaded kernel modules + /etc/modules-load.d configuration."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


class KmodCollector(Collector):
    name = "linux.kmod"
    category = "kernel"
    supported_os = (OS.LINUX,)
    description = "Loaded kernel modules; persistent module-load config."

    def collect(self) -> Iterable[Artifact]:
        proc_modules = Path("/proc/modules")
        if proc_modules.exists():
            try:
                yield self.make(subject="proc-modules", raw=proc_modules.read_text(errors="replace"))
            except (PermissionError, OSError):
                pass
        if shutil.which("lsmod"):
            try:
                out = subprocess.run(
                    ["lsmod"], capture_output=True, text=True, timeout=5, check=False
                ).stdout
                yield self.make(subject="lsmod", raw=out)
            except Exception:
                pass
        for d in ["/etc/modules-load.d", "/etc/modprobe.d"]:
            dp = Path(d)
            if not dp.is_dir():
                continue
            for f in dp.glob("*"):
                if not f.is_file():
                    continue
                try:
                    yield self.make(
                        subject=f"{d}:{f.name}",
                        path=str(f),
                        contents=f.read_text(errors="replace"),
                    )
                except (PermissionError, OSError):
                    continue
