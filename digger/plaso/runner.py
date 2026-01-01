"""Plaso .plaso ingestion via the user-installed psort binary.

We shell out to ``psort`` (Plaso 2x) or ``psort.py`` (older Plaso) with
the ``-o json_line`` output module, which produces one JSON object per
event on its own line. This is the most stable interchange surface
Plaso exposes and avoids depending on the heavy ``plaso`` Python
library directly.

Per-event JSON shape (from plaso/output/json_line.py)::

    {
      "__container_type__": "event",
      "__type__": "AttributeContainer",
      "timestamp": 1715000000123456,        # microseconds since epoch
      "timestamp_desc": "Last Visited Time",
      "source": "WEBHIST", "source_long": "Chrome History",
      "message": "Visited: https://example.com — Example",
      "display_name": "/profiles/Default/History",
      "parser": "chrome_history",
      "data_type": "chrome:history:page_visited",
      "filename": "...",
      ...arbitrary parser-specific fields
    }

Bridge artifact shape
---------------------
Each event becomes::

    Artifact(
        collector=f"plaso:{parser_or_dt}",
        category="timeline",
        subject=f"plaso:{ts_iso}:{data_type}",
        data={
            "plaso_ts_us": ...,         # microseconds since epoch
            "plaso_ts": ...,            # float seconds for storyline
            "plaso_event": full_event_dict,
        },
    )

The storyline reconstructor and watch daemon will pick up these
events via their existing artifact-iteration machinery.

Safety
------
Plaso events can carry arbitrary attacker-controlled strings (e.g., a
poisoned MFT entry). We cap per-event field length to keep the
evidence store bounded. Filter options can scope the ingest to
"events between TS1 and TS2" or "parsers matching X" so an analyst
doesn't have to ingest 10M events when they want 100.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---- exception ---- #


class PlasoError(RuntimeError):
    """Raised on binary-missing / .plaso-rejected / parse failure."""


# ---- binary discovery ---- #


_CANDIDATES = ("psort", "psort.py", "psteal", "psteal.py", "log2timeline")


def discover_binary() -> str | None:
    """Honors ``$DIGGER_PLASO_BIN`` if set; otherwise PATH-scans for
    psort (preferred), psteal, or log2timeline."""
    env = os.environ.get("DIGGER_PLASO_BIN")
    if env:
        return env if (Path(env).is_file() and os.access(env, os.X_OK)) else None
    for name in _CANDIDATES:
        p = shutil.which(name)
        if p:
            return p
    return None


def _require_binary() -> str:
    b = discover_binary()
    if not b:
        raise PlasoError(
            "no psort / psteal / log2timeline binary found in PATH. "
            "Install Plaso via `pip install plaso` or `apt install "
            "plaso-tools`. Set DIGGER_PLASO_BIN to override."
        )
    return b


# ---- safety caps ---- #


_MAX_PLASO_BYTES = 16 * 1024 * 1024 * 1024   # 16 GiB
_MAX_FIELD_LEN = 8192
_PSORT_TIMEOUT_S = 1800   # 30 min — large plaso files take a while


def _check_plaso(plaso_path: str | Path) -> Path:
    p = Path(plaso_path)
    if not p.is_file():
        raise PlasoError(f"plaso file not found: {p}")
    try:
        sz = p.stat().st_size
    except OSError as exc:
        raise PlasoError(f"plaso stat failed: {exc}") from exc
    if sz > _MAX_PLASO_BYTES:
        raise PlasoError(
            f"plaso file {p} is {sz} bytes (> {_MAX_PLASO_BYTES}-byte "
            "cap). Filter the source case or override via env."
        )
    return p


def _normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Truncate per-field strings so a runaway message doesn't blow
    the evidence store."""
    out: dict[str, Any] = {}
    for k, v in event.items():
        if isinstance(v, str) and len(v) > _MAX_FIELD_LEN:
            out[k] = v[:_MAX_FIELD_LEN] + " …<truncated>…"
        else:
            out[k] = v
    return out


def _us_to_seconds(us: int | float | None) -> float | None:
    if us is None:
        return None
    try:
        return float(us) / 1_000_000.0
    except (TypeError, ValueError):
        return None


def _ts_iso(us: int | float | None) -> str:
    # Treat 0-microseconds as "no timestamp" — Plaso events with a
    # missing timestamp serialize as 0 rather than null.
    if us in (None, 0, 0.0):
        return "0"
    s = _us_to_seconds(us)
    if s is None:
        return "0"
    try:
        return datetime.fromtimestamp(s, tz=timezone.utc).strftime(
            "%Y%m%dT%H%M%S",
        )
    except (OverflowError, ValueError, OSError):
        return "0"


# ---- summary / info ---- #


@dataclass
class PlasoIngestSummary:
    plaso_path: str
    events_total: int = 0
    events_emitted: int = 0
    events_filtered: int = 0
    parsers_seen: dict[str, int] = field(default_factory=dict)
    data_types_seen: dict[str, int] = field(default_factory=dict)
    elapsed_s: float = 0.0
    psort_stderr: str = ""
    psort_returncode: int = 0


def info(
    plaso_path: str | Path,
    *,
    binary: str | None = None,
    limit: int = 5000,
) -> PlasoIngestSummary:
    """Lightweight summary: count events, parsers seen, data-types
    seen. Reads the first ``limit`` events to keep info cheap."""
    bin_path = binary or _require_binary()
    plaso_path = _check_plaso(plaso_path)
    summary = PlasoIngestSummary(plaso_path=str(plaso_path))
    started = time.time()
    for ev in _stream_events(bin_path, plaso_path, limit=limit):
        summary.events_total += 1
        parser = ev.get("parser") or "unknown"
        summary.parsers_seen[parser] = summary.parsers_seen.get(parser, 0) + 1
        dt = ev.get("data_type") or "unknown"
        summary.data_types_seen[dt] = summary.data_types_seen.get(dt, 0) + 1
    summary.elapsed_s = time.time() - started
    return summary


# ---- streaming psort runner ---- #


def _stream_events(
    binary: str, plaso_path: Path, *, limit: int | None = None,
    extra_args: list[str] | None = None,
) -> Iterable[dict[str, Any]]:
    """Spawn psort -o json_line, yield parsed events one at a time.

    json_line output is line-delimited so we can stream it instead of
    loading the whole result in memory — crucial for multi-GB plasos."""
    extra_args = extra_args or []
    args = [
        binary,
        "-o", "json_line",
        "-w", "/dev/stdout",
        str(plaso_path),
        *extra_args,
    ]
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        bufsize=1,
    )
    try:
        n = 0
        for raw in proc.stdout or []:
            line = raw.strip()
            if not line:
                continue
            # psort can sometimes prepend a JSON-array opening or
            # status lines; skip if not parseable as a dict
            try:
                ev = json.loads(line.rstrip(","))
            except json.JSONDecodeError:
                continue
            if not isinstance(ev, dict):
                continue
            yield ev
            n += 1
            if limit is not None and n >= limit:
                break
    finally:
        try:
            if limit is not None:
                # Drain rest of stdout so the child can exit cleanly
                proc.terminate()
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


# ---- whole-file ingest ---- #


def ingest(
    plaso_path: str | Path,
    store,
    *,
    binary: str | None = None,
    parsers: Iterable[str] | None = None,
    data_types: Iterable[str] | None = None,
    after_ts: float | None = None,
    before_ts: float | None = None,
    limit: int | None = None,
) -> PlasoIngestSummary:
    """Ingest a whole .plaso into the EvidenceStore as digger Artifacts.

    Filters (applied post-stream so they work even when psort doesn't
    natively support them):
      parsers     keep only events whose ``parser`` is in this set
      data_types  keep only events whose ``data_type`` is in this set
      after_ts    keep only events with ts >= after_ts (epoch seconds)
      before_ts   keep only events with ts <= before_ts (epoch seconds)
      limit       cap the total emitted events
    """
    from digger.core.evidence import Artifact

    bin_path = binary or _require_binary()
    plaso_path = _check_plaso(plaso_path)
    summary = PlasoIngestSummary(plaso_path=str(plaso_path))
    parser_set = set(parsers) if parsers else None
    dt_set = set(data_types) if data_types else None
    started = time.time()

    for ev in _stream_events(bin_path, plaso_path):
        summary.events_total += 1
        parser = ev.get("parser") or "unknown"
        dt = ev.get("data_type") or "unknown"
        summary.parsers_seen[parser] = summary.parsers_seen.get(parser, 0) + 1
        summary.data_types_seen[dt] = summary.data_types_seen.get(dt, 0) + 1
        # Apply filters
        if parser_set is not None and parser not in parser_set:
            summary.events_filtered += 1
            continue
        if dt_set is not None and dt not in dt_set:
            summary.events_filtered += 1
            continue
        ts_s = _us_to_seconds(ev.get("timestamp"))
        if after_ts is not None and (ts_s is None or ts_s < after_ts):
            summary.events_filtered += 1
            continue
        if before_ts is not None and (ts_s is None or ts_s > before_ts):
            summary.events_filtered += 1
            continue

        normalized = _normalize_event(ev)
        store.add_artifact(Artifact(
            collector=f"plaso:{parser}",
            category="timeline",
            subject=f"plaso:{_ts_iso(ev.get('timestamp'))}:{dt}",
            data={
                "plaso_ts_us": ev.get("timestamp"),
                "plaso_ts": ts_s,
                "plaso_timestamp_desc": ev.get("timestamp_desc"),
                "plaso_source": ev.get("source"),
                "plaso_source_long": ev.get("source_long"),
                "plaso_parser": parser,
                "plaso_data_type": dt,
                "plaso_message": ev.get("message"),
                "plaso_event": normalized,
            },
        ))
        summary.events_emitted += 1
        if limit is not None and summary.events_emitted >= limit:
            break

    summary.elapsed_s = time.time() - started
    return summary
