"""ForensicArtifacts knowledge-base ingestion.

The ForensicArtifacts project (https://github.com/ForensicArtifacts/
artifacts) is a Google/DFIR-community YAML library of standardized
forensic-artifact definitions: hundreds of pre-specified registry
keys, file paths, command outputs, and groupings — covering Windows,
macOS, Linux, and ESXi.

Each artifact is a YAML document like::

    name: BashShellHistoryFile
    doc: User's bash shell history.
    sources:
    - type: FILE
      attributes:
        paths: ['%%users.homedir%%/.bash_history']
    supported_os: [Darwin, Linux]

Ingesting this knowledge base lets digger run hundreds of additional
collections without writing each by hand. The runner here implements
the most common source types (FILE / DIRECTORY / COMMAND / PATH /
ARTIFACT_GROUP); the heavier-weight ones (REGISTRY_*, WMI) are
parsed and skipped on non-Windows hosts.

Public API
----------
``load_artifacts(root)``      — parse the cloned YAML tree
``Artifact``                  — one normalized artifact definition
``ArtifactResolver``          — expand ``%%users.homedir%%`` etc.
``run_artifact(art, store)``  — execute the artifact's sources and
                                  emit digger Artifacts into the
                                  evidence store
``update_corpus(dest)``       — clone or fast-forward the upstream
                                  ForensicArtifacts repo
"""

from __future__ import annotations

from digger.forensic_artifacts.loader import (
    Artifact,
    ArtifactSource,
    cache_dir,
    load_artifacts,
)
from digger.forensic_artifacts.resolver import ArtifactResolver
from digger.forensic_artifacts.runner import run_artifact
from digger.forensic_artifacts.update import update_corpus

__all__ = [
    "Artifact",
    "ArtifactResolver",
    "ArtifactSource",
    "cache_dir",
    "load_artifacts",
    "run_artifact",
    "update_corpus",
]
