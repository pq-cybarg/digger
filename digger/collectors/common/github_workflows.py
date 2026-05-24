"""GitHub Actions workflow files across project dirs.

Critical for detecting the Shai-Hulud npm worm, which drops a
`.github/workflows/shai-hulud-workflow.yml` into every repo it can touch.
Also flags any workflow that exfiltrates secrets to non-GitHub endpoints.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact

_SEARCH_ROOTS = [
    "~",
    "~/code",
    "~/projects",
    "~/dev",
    "~/src",
    "~/work",
    "~/repos",
    "~/Desktop",
    "~/Documents",
]
_MAX_DEPTH = 5


def _walk_for_workflow_dirs(root: Path):
    if not root.exists():
        return
    root = root.resolve()
    for dirpath, dirnames, _ in os.walk(root, followlinks=False):
        rel_depth = len(Path(dirpath).relative_to(root).parts)
        if rel_depth > _MAX_DEPTH:
            dirnames.clear()
            continue
        # Skip directories that are package/module caches or build outputs.
        # These contain vendored upstream code with their *own* GitHub
        # workflows — interesting if you maintain the upstream, but noise
        # when you're scanning a developer machine. Walking the Go
        # module cache alone can return thousands of unrelated workflow
        # files; doing so means every Shai-Hulud rule fires per upstream
        # CI file.
        dirnames[:] = [d for d in dirnames if d not in {
            "node_modules", ".venv", "venv", "__pycache__",
            "dist", "build", ".next", ".nuxt", "vendor",
            "pkg",          # Go module cache root under $GOPATH
            ".cargo",       # Rust crate cache
            ".rustup",
            ".gradle",
            ".m2",          # Maven local repo
            "Pods",         # CocoaPods
            "Carthage",
            ".bundle",      # Ruby gem caches
            ".cache",
            "site-packages",
        }]
        # And skip anything pathwise under a Go module cache no matter
        # how it was reached. /Users/.../go/pkg/mod/ is the canonical
        # path; matching it directly catches walks that began deeper.
        rel = str(Path(dirpath).relative_to(root))
        if "go/pkg/mod" in rel or "/pkg/mod/" in rel or rel.endswith("pkg/mod"):
            dirnames.clear()
            continue
        if ".github" in dirnames:
            wf_dir = Path(dirpath) / ".github" / "workflows"
            if wf_dir.is_dir():
                yield wf_dir


class GithubWorkflowsCollector(Collector):
    name = "github_workflows"
    category = "inventory"
    description = "Contents of .github/workflows/*.yml across local repos."

    def collect(self) -> Iterable[Artifact]:
        seen: set[Path] = set()
        for r in _SEARCH_ROOTS:
            root = Path(os.path.expanduser(r))
            if not root.exists():
                continue
            for wf_dir in _walk_for_workflow_dirs(root):
                if wf_dir in seen:
                    continue
                seen.add(wf_dir)
                entries = []
                for wf in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
                    try:
                        text = wf.read_text(encoding="utf-8", errors="replace")
                        entries.append({
                            "name": wf.name,
                            "path": str(wf),
                            "size": wf.stat().st_size,
                            "mtime": wf.stat().st_mtime,
                            "contents": text,
                        })
                    except (PermissionError, OSError):
                        continue
                if entries:
                    yield self.make(
                        subject=f"workflows:{wf_dir}",
                        path=str(wf_dir),
                        count=len(entries),
                        entries=entries,
                    )
