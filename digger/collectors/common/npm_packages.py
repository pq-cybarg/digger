"""npm / yarn / pnpm package inventories across project dirs.

Walks common project locations and parses `package.json` +
`package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` to produce a flat
list of (package, version, project_root) tuples. Used by the supply-chain
and Shai-Hulud detectors.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact

_PROJECT_SEARCH_ROOTS = [
    "~",
    "~/code",
    "~/projects",
    "~/dev",
    "~/Desktop",
    "~/Documents",
    "~/src",
    "~/work",
    "~/repos",
]
_MAX_DEPTH = 4


def _walk(root: Path, max_depth: int) -> Iterable[Path]:
    if not root.exists():
        return
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = len(Path(dirpath).relative_to(root).parts)
        if depth > max_depth:
            dirnames.clear()
            continue
        # Skip large noise dirs
        dirnames[:] = [d for d in dirnames if d not in {
            "node_modules", ".git", ".venv", "venv", "__pycache__",
            "dist", "build", ".next", ".nuxt", "vendor",
        }]
        if "package.json" in filenames:
            yield Path(dirpath) / "package.json"


def _parse_lockfile(project: Path) -> dict[str, str]:
    """Return name -> version pairs from any lockfile present."""
    pkgs: dict[str, str] = {}
    pl = project / "package-lock.json"
    if pl.exists():
        try:
            data = json.loads(pl.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            data = {}
        for name, info in (data.get("packages") or {}).items():
            if not name:
                continue
            short = name.split("node_modules/")[-1]
            v = (info or {}).get("version")
            if v:
                pkgs[short] = v
        for name, info in (data.get("dependencies") or {}).items():
            v = (info or {}).get("version")
            if v:
                pkgs[name] = v
    yarn = project / "yarn.lock"
    if yarn.exists():
        try:
            text = yarn.read_text(encoding="utf-8", errors="replace")
            # yarn.lock entries look like:
            #   "pkg@version", "pkg@npm:version":
            #     version "1.2.3"
            current_names: list[str] = []
            for line in text.splitlines():
                m = re.match(r'^"?([^"\s].*?)"?:\s*$', line)
                if m and "@" in m.group(1):
                    current_names = [
                        part.rsplit("@", 1)[0] for part in m.group(1).split(", ")
                    ]
                    continue
                m = re.match(r'^\s+version\s+"([^"]+)"', line)
                if m and current_names:
                    for name in current_names:
                        pkgs[name] = m.group(1)
                    current_names = []
        except OSError:
            pass
    pnpm = project / "pnpm-lock.yaml"
    if pnpm.exists():
        try:
            text = pnpm.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r"^\s+/([^/]+)/([^:]+):\s*$", text, re.M):
                pkgs[m.group(1)] = m.group(2)
        except OSError:
            pass
    return pkgs


class NpmPackagesCollector(Collector):
    name = "npm_packages"
    category = "inventory"
    description = "Project package.json + lockfile inventory across common dev dirs."

    def collect(self) -> Iterable[Artifact]:
        seen: set[Path] = set()
        for r in _PROJECT_SEARCH_ROOTS:
            root = Path(os.path.expanduser(r))
            if not root.exists():
                continue
            for pj in _walk(root, _MAX_DEPTH):
                project = pj.parent.resolve()
                if project in seen:
                    continue
                seen.add(project)
                try:
                    manifest = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    manifest = {}
                lock_pkgs = _parse_lockfile(project)
                yield self.make(
                    subject=f"npm:{project}",
                    project=str(project),
                    name=manifest.get("name"),
                    version=manifest.get("version"),
                    declared_deps=manifest.get("dependencies") or {},
                    declared_dev_deps=manifest.get("devDependencies") or {},
                    declared_scripts=manifest.get("scripts") or {},
                    locked_packages=lock_pkgs,
                    locked_count=len(lock_pkgs),
                )
