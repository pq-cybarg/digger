"""Self-identification — recognize digger's own process(es).

If a hunt or detector turns up a row that is in fact digger doing its
job, the right behavior isn't to silently filter it out (that would
hide signal). It's to **annotate** the row with a clear self-attribution
so the analyst sees "yes this fired, and yes it's digger collecting on
itself" rather than being confused.

This module is a single small helper used by hunts, detectors, and the
opsec status page. It does not modify or hide any data.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Optional


# Canonical entry-point hints. A process is "digger" iff its cmdline
# matches any of these in a few orthogonal ways.
_DIGGER_BASENAMES = ("digger", "digger.exe", "digger-cli")
_INTERPRETER_BASENAMES = (
    "python", "python3", "python2", "python.exe", "python3.exe",
)
_SUBCOMMANDS = (
    "collect", "scan", "triage", "report", "investigate", "verify",
    "intel", "pqc", "fips", "compliance", "export", "sigma", "loki",
    "diff", "hunt", "opsec",
)


def _basename(p: str | None) -> str:
    if not p:
        return ""
    s = str(p).replace("\\", "/").rstrip("/")
    return s.rsplit("/", 1)[-1].lower()


def identify(process_data: dict) -> Optional[str]:
    """Return a human-readable self-attribution string if ``process_data``
    looks like a digger invocation, otherwise None.

    ``process_data`` is one of digger's `processes`-collector data dicts
    (or any dict carrying ``name``, ``exe``, ``cmdline``, ``pid``).
    """
    name   = _basename(process_data.get("name"))
    exe    = _basename(process_data.get("exe"))
    cmd    = process_data.get("cmdline") or []
    pid    = process_data.get("pid")

    # Same process? Quick check first.
    if pid is not None and pid == os.getpid():
        return _fmt(cmd, "digger (current process)")

    # 1. argv[0] is the digger CLI directly
    if name in _DIGGER_BASENAMES or exe in _DIGGER_BASENAMES:
        return _fmt(cmd, "digger CLI invocation")

    # 2. python <…>/digger <subcommand>
    if cmd and len(cmd) >= 2 and _basename(cmd[0]) in _INTERPRETER_BASENAMES:
        second = _basename(cmd[1])
        if second in _DIGGER_BASENAMES or "digger" in second:
            return _fmt(cmd, "digger via python")

    # 3. python -m digger.cli
    if "-m" in cmd:
        try:
            i = cmd.index("-m")
            mod = cmd[i + 1] if i + 1 < len(cmd) else ""
            if mod.startswith("digger"):
                return _fmt(cmd, f"python -m {mod}")
        except (ValueError, IndexError):
            pass

    # 4. python script-path-containing-digger
    for token in cmd:
        if "/digger/" in (token or "").lower() and token.endswith(".py"):
            return _fmt(cmd, "digger internal script")

    return None


def _fmt(cmd: list, label: str) -> str:
    sub = ""
    for c in cmd or []:
        b = _basename(c)
        if b in _SUBCOMMANDS:
            sub = b
            break
    return f"{label}{' [' + sub + ']' if sub else ''}"


def digger_self_pids() -> list[int]:
    """Return PIDs that ``identify()`` would classify as digger right now."""
    try:
        import psutil
    except ImportError:
        return [os.getpid()]
    out: list[int] = []
    for p in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]):
        try:
            if identify(p.info):
                out.append(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out
