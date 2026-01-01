"""Falco event ingestion + live-stream runner.

Falco emits one JSON object per event when configured with
``json_output: true``. Each event has a stable shape::

    {
      "time":     "2026-05-25T13:00:00.000000000Z",
      "priority": "Warning",                  # Emergency..Debug
      "rule":     "Read sensitive file untrusted",
      "output":   "Sensitive file opened ... user=root program=cat ...",
      "output_fields": {
        "proc.cmdline":  "cat /etc/shadow",
        "proc.pname":    "bash",
        "fd.name":       "/etc/shadow",
        "container.id":  "host",
        "user.name":     "root",
        ...
      },
      "tags":     ["filesystem", "mitre_credential_access"]
    }

ingest_file
-----------
Cross-platform. Reads an NDJSON file (one event per line) and emits
one Artifact per event. Useful when a Falco-running Linux host is
acquired and its event log is analyzed elsewhere.

stream_events
-------------
Linux-only (Falco itself is Linux-only). Spawns ``falco -o
json_output=true`` and pipes the live event stream into the store.
Pairs with ``digger watch`` for continuous monitoring. Refuses to
run on non-Linux to give a clean error rather than a confusing
binary-not-found.

Artifact shape
--------------
Each event becomes::

    Artifact(
        collector=f"falco:{rule}",
        category="runtime_alert",
        subject=f"falco:{iso_ts}:{rule}",
        data={
            "falco_time":     <event["time"]>,
            "falco_priority": <event["priority"]>,
            "falco_rule":     <event["rule"]>,
            "falco_output":   <event["output"]>,
            "falco_tags":     <event["tags"]>,
            "output_fields":  <full output_fields dict>,
            # Promoted top-level for storyline-walker joins:
            "pid":      output_fields.proc.pid,
            "name":     output_fields.proc.name,
            "cmdline":  output_fields.proc.cmdline,
            "username": output_fields.user.name,
            "path":     output_fields["fd.name"] (when file event),
            "host":     output_fields["fd.sip"] (when net event),
        },
        mitre=mitre_tag_from_tags,
    )

The promoted top-level fields are what the storyline walker reads
when clustering — that's how a Falco "Read sensitive file" event on
PID 4242 automatically clusters with a SuspiciousProcessDetector
finding on PID 4242 from the live ProcessCollector.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---- exception ---- #


class FalcoError(RuntimeError):
    """Raised on binary-missing / non-Linux stream / parse failure."""


# ---- binary discovery ---- #


def discover_binary() -> str | None:
    """Honors ``$DIGGER_FALCO_BIN`` if set; otherwise PATH-scans ``falco``."""
    env = os.environ.get("DIGGER_FALCO_BIN")
    if env:
        return env if (Path(env).is_file() and os.access(env, os.X_OK)) else None
    return shutil.which("falco")


# ---- safety caps ---- #


_MAX_FALCO_LOG_BYTES = 4 * 1024 * 1024 * 1024     # 4 GiB
_MAX_FIELD_LEN = 8192


# ---- mitre-tag extraction ---- #


# Falco tags use the convention ``mitre_<technique_snake>`` where the
# technique-snake matches the lowercase tactic name (e.g.
# ``mitre_credential_access``, ``mitre_persistence``,
# ``mitre_privilege_escalation``). Map these to the Sigma tactic slug.
_TAG_TO_TACTIC = {
    "mitre_initial_access":      "initial-access",
    "mitre_execution":           "execution",
    "mitre_persistence":         "persistence",
    "mitre_privilege_escalation": "privilege-escalation",
    "mitre_defense_evasion":     "defense-evasion",
    "mitre_credential_access":   "credential-access",
    "mitre_discovery":           "discovery",
    "mitre_lateral_movement":    "lateral-movement",
    "mitre_collection":          "collection",
    "mitre_command_and_control": "command-and-control",
    "mitre_exfiltration":        "exfiltration",
    "mitre_impact":              "impact",
}


_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _mitre_from_tags(tags: Iterable[str]) -> str:
    """Pick the MITRE technique ID from Falco's tags list, preferring
    explicit T#### tags. Falls back to empty string when none present."""
    for t in tags or []:
        # Some Falco rule packs emit raw T#### tags directly
        m = _TECHNIQUE_RE.match(t.upper())
        if m:
            return t.upper()
    return ""


# ---- per-event normalization ---- #


def _truncate(v: Any) -> Any:
    if isinstance(v, str) and len(v) > _MAX_FIELD_LEN:
        return v[:_MAX_FIELD_LEN] + " …<truncated>…"
    return v


def _parse_ts(time_str: str | None) -> float | None:
    """Parse Falco's ISO-8601 nanosecond-precision time to epoch seconds."""
    if not time_str:
        return None
    try:
        # Falco emits "2026-05-25T13:00:00.000000000Z" — strip the
        # 9-digit ns suffix to fit datetime's 6-digit microseconds.
        s = time_str.rstrip("Z")
        if "." in s:
            base, frac = s.split(".", 1)
            frac = (frac + "000000000")[:6]   # pad/trim to 6 digits
            s = f"{base}.{frac}+00:00"
        else:
            s = f"{s}+00:00"
        from datetime import datetime
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, OSError, OverflowError):
        return None


def parse_event(raw: str | dict) -> dict[str, Any] | None:
    """Parse one Falco event (JSON string or already-parsed dict) into
    the digger-Artifact-data shape. Returns None for non-event lines
    (e.g., Falco status messages mixed into stdout)."""
    if isinstance(raw, str):
        line = raw.strip()
        if not line:
            return None
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            return None
    else:
        ev = raw
    if not isinstance(ev, dict):
        return None
    if "rule" not in ev:
        # Falco status / hot-reload notifications lack "rule"
        return None

    fields = ev.get("output_fields") or {}
    tags = list(ev.get("tags") or [])

    return {
        "falco_time":     ev.get("time"),
        "falco_ts":       _parse_ts(ev.get("time")),
        "falco_priority": ev.get("priority") or "",
        "falco_rule":     ev.get("rule") or "",
        "falco_output":   _truncate(ev.get("output") or ""),
        "falco_tags":     tags,
        "output_fields":  {k: _truncate(v) for k, v in fields.items()},
        # Promoted top-level for storyline-walker joins
        "pid":      fields.get("proc.pid"),
        "ppid":     fields.get("proc.ppid"),
        "name":     fields.get("proc.name"),
        "cmdline":  _truncate(fields.get("proc.cmdline") or ""),
        "username": fields.get("user.name"),
        "path":     fields.get("fd.name"),
        "host":     fields.get("fd.sip") or fields.get("fd.cip"),
        "container_id": fields.get("container.id"),
        "mitre":    _mitre_from_tags(tags),
    }


# ---- priority → severity mapping ---- #


# Falco priority levels (per syslog) → digger severity buckets.
_PRIORITY_TO_SEVERITY = {
    "emergency": "critical",
    "alert":     "critical",
    "critical":  "critical",
    "error":     "high",
    "warning":   "high",
    "notice":    "medium",
    "info":      "low",
    "informational": "low",
    "debug":     "info",
}


def _severity(priority: str | None) -> str:
    if not priority:
        return "low"
    return _PRIORITY_TO_SEVERITY.get(priority.lower(), "low")


# ---- summary ---- #


@dataclass
class FalcoIngestSummary:
    source: str
    events_total: int = 0
    events_emitted: int = 0
    events_skipped: int = 0
    rules_seen: dict[str, int] = field(default_factory=dict)
    elapsed_s: float = 0.0


# ---- ingest_file ---- #


def _check_log_file(path: str | Path) -> Path:
    p = Path(path)
    if not p.is_file():
        raise FalcoError(f"falco log not found: {p}")
    try:
        sz = p.stat().st_size
    except OSError as exc:
        raise FalcoError(f"falco log stat failed: {exc}") from exc
    if sz > _MAX_FALCO_LOG_BYTES:
        raise FalcoError(
            f"falco log {p} is {sz} bytes (> {_MAX_FALCO_LOG_BYTES}-byte "
            "cap). Filter the log or override via env."
        )
    return p


def ingest_file(
    log_path: str | Path,
    store,
    *,
    priorities: Iterable[str] | None = None,
    rules: Iterable[str] | None = None,
    after_ts: float | None = None,
    before_ts: float | None = None,
    limit: int | None = None,
) -> FalcoIngestSummary:
    """Read a Falco NDJSON event log and emit Artifacts.

    Filters:
      priorities  Keep only events whose priority is in this set
                  (case-insensitive)
      rules       Keep only events whose rule is in this set
      after_ts    Keep only events with ts >= after_ts (epoch seconds)
      before_ts   Keep only events with ts <= before_ts
      limit       Cap total emitted events
    """
    from digger.core.evidence import Artifact, Finding

    p = _check_log_file(log_path)
    prio_set = {x.lower() for x in priorities} if priorities else None
    rule_set = set(rules) if rules else None
    summary = FalcoIngestSummary(source=str(p))
    started = time.time()

    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            summary.events_total += 1
            parsed = parse_event(raw_line)
            if parsed is None:
                summary.events_skipped += 1
                continue
            rule = parsed.get("falco_rule") or ""
            summary.rules_seen[rule] = summary.rules_seen.get(rule, 0) + 1
            prio = (parsed.get("falco_priority") or "").lower()
            if prio_set is not None and prio not in prio_set:
                summary.events_skipped += 1
                continue
            if rule_set is not None and rule not in rule_set:
                summary.events_skipped += 1
                continue
            ts_s = parsed.get("falco_ts")
            if after_ts is not None and (ts_s is None or ts_s < after_ts):
                summary.events_skipped += 1
                continue
            if before_ts is not None and (ts_s is None or ts_s > before_ts):
                summary.events_skipped += 1
                continue

            _emit_event(store, parsed, Artifact, Finding)
            summary.events_emitted += 1
            if limit is not None and summary.events_emitted >= limit:
                break

    summary.elapsed_s = time.time() - started
    return summary


def _emit_event(store, parsed: dict[str, Any], Artifact, Finding) -> None:
    """Emit BOTH an Artifact (timeline event) and a Finding (alert) for
    each Falco event. Artifact for the storyline walker; Finding for
    the report's severity-sorted list and watch-mode alerting."""
    rule = parsed.get("falco_rule") or "unknown"
    ts = parsed.get("falco_ts")
    iso = parsed.get("falco_time") or "0"
    iso_compact = iso.replace(":", "").replace("-", "")[:15] if iso else "0"
    artifact_uuid = None
    art = Artifact(
        collector=f"falco:{rule}",
        category="runtime_alert",
        subject=f"falco:{iso_compact}:{rule}",
        data=parsed,
    )
    store.add_artifact(art)
    artifact_uuid = art.artifact_uuid
    # And a Finding so the report + watch-alert pipeline sees it
    severity = _severity(parsed.get("falco_priority"))
    store.add_finding(Finding(
        detector="falco",
        severity=severity,
        title=f"Falco: {rule}",
        summary=(parsed.get("falco_output") or "")[:600],
        artifact_refs=[artifact_uuid] if artifact_uuid else [],
        evidence={
            "rule":          rule,
            "priority":      parsed.get("falco_priority"),
            "tags":          parsed.get("falco_tags") or [],
            "pid":           parsed.get("pid"),
            "ppid":          parsed.get("ppid"),
            "name":          parsed.get("name"),
            "cmdline":       parsed.get("cmdline") or "",
            "username":      parsed.get("username"),
            "path":          parsed.get("path"),
            "host":          parsed.get("host"),
            "container_id":  parsed.get("container_id"),
            "ts":            ts,
        },
        mitre=parsed.get("mitre") or "",
    ))


# ---- stream (Linux-only) ---- #


def stream_events(
    store,
    *,
    binary: str | None = None,
    extra_args: list[str] | None = None,
    max_events: int | None = None,
) -> FalcoIngestSummary:
    """Spawn falco and pipe its live JSON output into the store.

    Linux-only by design (Falco itself is Linux-only). Refuses on
    non-Linux with a clean error. Caller is responsible for SIGTERM
    handling if they want a clean shutdown — we exit when the child
    exits or ``max_events`` is reached."""
    if sys.platform != "linux":
        raise FalcoError(
            f"falco stream requires Linux (sys.platform={sys.platform!r}). "
            "Use `digger falco ingest --log PATH` to read a Falco event "
            "log from a Linux host on any OS."
        )
    bin_path = binary or discover_binary()
    if not bin_path:
        raise FalcoError(
            "no falco binary in PATH. Install via your distro's package "
            "manager (e.g. `apt install falco`) or set DIGGER_FALCO_BIN."
        )

    from digger.core.evidence import Artifact, Finding
    extra_args = extra_args or []
    args = [
        bin_path,
        "-o", "json_output=true",
        "-o", "log_stderr=true",
        "-o", "stdout_output.enabled=true",
        *extra_args,
    ]
    summary = FalcoIngestSummary(source="falco-stream")
    started = time.time()
    proc = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    try:
        for raw_line in proc.stdout or []:
            summary.events_total += 1
            parsed = parse_event(raw_line)
            if parsed is None:
                summary.events_skipped += 1
                continue
            rule = parsed.get("falco_rule") or "unknown"
            summary.rules_seen[rule] = summary.rules_seen.get(rule, 0) + 1
            _emit_event(store, parsed, Artifact, Finding)
            summary.events_emitted += 1
            if max_events is not None and summary.events_emitted >= max_events:
                break
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    summary.elapsed_s = time.time() - started
    return summary
