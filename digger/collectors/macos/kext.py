"""macOS kernel extensions and system extensions."""

from __future__ import annotations

import shutil
import subprocess
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


class KextCollector(Collector):
    name = "macos.kext"
    category = "kernel"
    supported_os = (OS.MACOS,)
    description = "Loaded kexts (kmutil) and system extensions (systemextensionsctl)."

    def collect(self) -> Iterable[Artifact]:
        if shutil.which("kmutil"):
            try:
                out = subprocess.run(
                    ["kmutil", "showloaded"],
                    capture_output=True, text=True, timeout=30, check=False,
                ).stdout
                yield self.make(subject="kmutil-showloaded", raw=out)
            except Exception:
                pass
        if shutil.which("systemextensionsctl"):
            try:
                out = subprocess.run(
                    ["systemextensionsctl", "list"],
                    capture_output=True, text=True, timeout=15, check=False,
                ).stdout
                yield self.make(subject="systemextensionsctl-list", raw=out)
            except Exception:
                pass
