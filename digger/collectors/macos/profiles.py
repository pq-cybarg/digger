"""macOS configuration profiles."""

from __future__ import annotations

import shutil
import subprocess
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


class ProfilesCollector(Collector):
    name = "macos.profiles"
    category = "config"
    supported_os = (OS.MACOS,)
    description = "Configuration profiles installed via MDM or pkg."

    def collect(self) -> Iterable[Artifact]:
        if not shutil.which("profiles"):
            return
        for args, label in [
            (["profiles", "show", "-type", "configuration", "-output", "stdout-xml"], "config"),
            (["profiles", "show", "-type", "enrollment"], "enrollment"),
        ]:
            try:
                out = subprocess.run(
                    args, capture_output=True, text=True, timeout=30, check=False,
                ).stdout
                yield self.make(subject=f"profiles:{label}", raw=out)
            except Exception:
                continue
