"""YAML loader for ForensicArtifacts definitions.

The upstream repo (github.com/ForensicArtifacts/artifacts) stores
artifact definitions under ``artifacts/data/*.yaml``. Each file is a
multi-document YAML stream — many small artifacts per file.

We parse every YAML document into an Artifact dataclass and return
them as a flat list. Unknown source types are preserved verbatim so
the runner can decide whether to skip or implement them later.

This module has NO hard dependency on the upstream repo: when the
cache is empty or PyYAML missing, ``load_artifacts()`` returns ``[]``
instead of erroring. Callers degrade to "run ``digger fa update``."
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---- Cache location ---- #


def cache_dir() -> Path:
    """``$DIGGER_FA_DIR`` or ``~/.cache/digger/forensic-artifacts``."""
    env = os.environ.get("DIGGER_FA_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".cache" / "digger" / "forensic-artifacts"


def data_root(root: Path | None = None) -> Path:
    """Where the ``artifacts/data/*.yaml`` tree lives."""
    base = root or cache_dir()
    candidates = [
        base / "artifacts" / "data",  # standard layout
        base / "data",                 # if user pointed straight at it
        base,                          # last resort
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return base / "artifacts" / "data"


# ---- Data model ---- #


@dataclass
class ArtifactSource:
    """One source clause of an artifact. ForensicArtifacts type set:
    FILE / DIRECTORY / PATH / COMMAND / REGISTRY_KEY / REGISTRY_VALUE
    / WMI / ARTIFACT_GROUP / VOLATILE_REGISTRY_KEY."""
    type: str
    attributes: dict[str, Any] = field(default_factory=dict)
    supported_os: list[str] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)


@dataclass
class Artifact:
    name: str
    doc: str = ""
    sources: list[ArtifactSource] = field(default_factory=list)
    supported_os: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)

    @property
    def os_supported(self) -> set[str]:
        """Return lowercased OS names this artifact supports."""
        return {s.lower() for s in self.supported_os}

    def supports(self, os_name: str) -> bool:
        """Cross-platform-tolerant OS check.

        Maps the OS names digger uses (``windows`` / ``darwin`` /
        ``linux``) to the variants ForensicArtifacts uses (``Windows``
        / ``Darwin`` / ``Linux``). Empty supported_os means the
        artifact is OS-agnostic — return True."""
        if not self.supported_os:
            return True
        norm = os_name.lower()
        translations = {"macos": "darwin", "mac": "darwin", "osx": "darwin"}
        norm = translations.get(norm, norm)
        return any(s.lower() == norm for s in self.supported_os)

    def matches_tags(self, tags: list[str]) -> bool:
        """Loose OR-match of labels + name against requested tags."""
        if not tags:
            return True
        all_terms = {t.lower() for t in tags}
        own_terms = {t.lower() for t in self.labels} | {self.name.lower()}
        return bool(all_terms & own_terms)


# ---- Loader ---- #


def _normalize_source(raw: dict) -> ArtifactSource:
    return ArtifactSource(
        type=str(raw.get("type") or "").upper(),
        attributes=dict(raw.get("attributes") or {}),
        supported_os=list(raw.get("supported_os") or []),
        conditions=list(raw.get("conditions") or []),
    )


def _normalize_artifact(doc: dict) -> Artifact | None:
    name = doc.get("name")
    if not name or not isinstance(name, str):
        return None
    sources = [_normalize_source(s) for s in (doc.get("sources") or [])
               if isinstance(s, dict)]
    return Artifact(
        name=name,
        doc=str(doc.get("doc") or ""),
        sources=sources,
        supported_os=[str(s) for s in (doc.get("supported_os") or [])],
        labels=[str(label) for label in (doc.get("labels") or [])],
        urls=[str(u) for u in (doc.get("urls") or [])],
        conditions=[str(c) for c in (doc.get("conditions") or [])],
        provides=[str(p) for p in (doc.get("provides") or [])],
        aliases=[str(a) for a in (doc.get("aliases") or [])],
    )


def load_artifacts(root: Path | None = None) -> list[Artifact]:
    """Parse every YAML document under the data root.

    Returns an empty list (without error) when the cache is missing
    or PyYAML isn't available — callers should treat empty as
    "ForensicArtifacts corpus not installed; run ``digger fa update``."."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return []
    base = data_root(root)
    if not base.is_dir():
        return []
    out: list[Artifact] = []
    for path in sorted(base.glob("*.yaml")):
        try:
            with path.open("r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
        except Exception:
            continue
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            art = _normalize_artifact(doc)
            if art is not None:
                out.append(art)
    return out
