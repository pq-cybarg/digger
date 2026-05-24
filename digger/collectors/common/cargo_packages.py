"""crates.io / Cargo project inventory.

Walks the same dev-dir roots as the npm collector, finds ``Cargo.lock``
files, parses them, and emits one artifact per Cargo project with a
flat ``locked_packages`` dict ({name: version}). Used by the TrapDoor
and supply-chain detectors.

The lockfile is the source of truth for what actually got built — a
``Cargo.toml`` constraint of ``"^1.0"`` can resolve to any 1.x version,
so version-pinned IOC matches must consult Cargo.lock, not Cargo.toml.
"""

from __future__ import annotations

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
        dirnames[:] = [d for d in dirnames if d not in {
            "node_modules", ".git", ".venv", "venv", "__pycache__",
            "dist", "build", ".next", ".nuxt", "vendor",
            "target",  # Cargo build dir — skipping saves both time and
                       # spurious hits from registry-extracted source
        }]
        if "Cargo.lock" in filenames:
            yield Path(dirpath) / "Cargo.lock"


def _parse_cargo_lock(path: Path) -> dict[str, str]:
    """Return {name: version} from a ``Cargo.lock`` file.

    Tries ``tomllib`` (3.11+) → ``tomli`` → regex fallback so the
    collector works on any reasonable host without forcing a hard
    dependency."""
    text: str
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    parsed = None
    try:
        import tomllib  # type: ignore[import-not-found]
        parsed = tomllib.loads(text)
    except Exception:
        try:
            import tomli  # type: ignore[import-not-found]
            parsed = tomli.loads(text)
        except Exception:
            parsed = None

    pkgs: dict[str, str] = {}
    if isinstance(parsed, dict):
        for entry in parsed.get("package", []) or []:
            name = entry.get("name") if isinstance(entry, dict) else None
            ver = entry.get("version") if isinstance(entry, dict) else None
            if name and ver:
                pkgs[name] = ver
        if pkgs:
            return pkgs

    # Regex fallback — naive but matches the well-known Cargo.lock
    # block format:
    #   [[package]]
    #   name = "serde"
    #   version = "1.0.193"
    block_re = re.compile(
        r'\[\[package\]\]\s*[\r\n]+\s*name\s*=\s*"([^"]+)"\s*[\r\n]+'
        r'\s*version\s*=\s*"([^"]+)"',
        re.M,
    )
    for m in block_re.finditer(text):
        pkgs[m.group(1)] = m.group(2)
    return pkgs


class CargoPackagesCollector(Collector):
    name = "cargo_packages"
    category = "inventory"
    description = "Cargo (Rust / crates.io) project Cargo.lock inventory across common dev dirs."

    def collect(self) -> Iterable[Artifact]:
        seen: set[Path] = set()
        for r in _PROJECT_SEARCH_ROOTS:
            root = Path(os.path.expanduser(r))
            if not root.exists():
                continue
            for lock in _walk(root, _MAX_DEPTH):
                project = lock.parent.resolve()
                if project in seen:
                    continue
                seen.add(project)
                manifest_name = None
                manifest_path = project / "Cargo.toml"
                if manifest_path.exists():
                    try:
                        for line in manifest_path.read_text(
                            encoding="utf-8", errors="replace",
                        ).splitlines():
                            m = re.match(r'^\s*name\s*=\s*"([^"]+)"', line)
                            if m:
                                manifest_name = m.group(1)
                                break
                    except OSError:
                        pass
                locked = _parse_cargo_lock(lock)
                yield self.make(
                    subject=f"cargo:{project}",
                    project=str(project),
                    name=manifest_name,
                    locked_packages=locked,
                    locked_count=len(locked),
                )
