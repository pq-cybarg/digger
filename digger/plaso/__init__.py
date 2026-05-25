"""Plaso (log2timeline) ``.plaso`` storage-file ingestion.

Plaso (https://plaso.readthedocs.io/) is the standard open-source
DFIR timeline tool. A ``.plaso`` storage file is a SQLite-backed
"super-timeline" containing thousands of timestamped events extracted
from a target system: NTFS MFT, Windows event logs, prefetch,
browser history, syslog, plist files, registry hives, etc.

Ingesting ``.plaso`` lets digger consume cases that were processed
by Plaso elsewhere — common DFIR workflow is log2timeline first to
build the timeline, then analysts read it with their tool of choice.
This bridge lets digger be that tool: every Plaso event becomes a
digger Artifact, and the existing detectors / storyline / watch /
query / ELK pipeline runs over it.

Architecture
------------
Mirrors ``digger.volatility``: shell out to a user-installed ``psort``
binary (Plaso's output sorter), use ``-o json_line`` for stable
line-delimited JSON output, parse one event per line, emit Artifacts.

Public API
----------
``discover_binary()`` — find ``psort`` / ``psort.py`` / ``log2timeline``
                         in PATH
``ingest(plaso_path, store, ...)`` — convert + ingest a whole .plaso
``info(plaso_path)`` — count events + summarize parsers seen
"""

from __future__ import annotations

from digger.plaso.runner import (
    PlasoError,
    PlasoIngestSummary,
    discover_binary,
    info,
    ingest,
)

__all__ = [
    "PlasoError",
    "PlasoIngestSummary",
    "discover_binary",
    "info",
    "ingest",
]
