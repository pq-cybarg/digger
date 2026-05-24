"""Python environments and installed packages — supply-chain inspection."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact


class PythonPackagesCollector(Collector):
    name = "python_packages"
    category = "inventory"
    description = "Packages installed in the active Python and discovered virtualenvs."

    def collect(self) -> Iterable[Artifact]:
        yield from self._inspect(sys.executable, label="current")
        # Common venv locations
        home = Path.home()
        for venv in list(home.glob(".virtualenvs/*/bin/python")) + \
                    list(home.glob("venvs/*/bin/python")) + \
                    list(home.glob("*/.venv/bin/python")):
            if venv.exists():
                yield from self._inspect(str(venv), label=str(venv.parent.parent))

    def _inspect(self, python: str, label: str) -> Iterable[Artifact]:
        try:
            out = subprocess.run(
                [python, "-m", "pip", "list", "--format=json"],
                capture_output=True, text=True, timeout=20, check=False,
            ).stdout
            pkgs = json.loads(out) if out else []
        except Exception:
            return
        yield self.make(
            subject=f"pip:{label}",
            interpreter=python,
            count=len(pkgs),
            entries=pkgs,
        )
