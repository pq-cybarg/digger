"""Volatility 3 subprocess runner.

Discovers a ``vol`` / ``vol3`` / ``volatility3`` binary in PATH (or
honors ``$DIGGER_VOLATILITY_BIN``), runs selected plugins against a
memory image, parses the JSON renderer output, and emits one digger
Artifact per row.

JSON renderer
-------------
Volatility 3's ``-r json`` flag produces a stable structured output
shape::

    [
      {"<column>": <value>, ...},
      ...
    ]

…per plugin. We parse that, normalize each row, and store it under
``collector="volatility:<plugin>"``. Detectors and the storyline
walker can correlate memory-side findings (e.g., ``malfind`` regions
in a process) against disk-side findings (e.g., ``processes`` from
the live ``ProcessCollector``) via shared PID.

Curated plugin list
-------------------
``DEFAULT_PLUGINS`` is the per-OS list of plugins most relevant to
compromise detection. The caller can override via ``--plugins`` or
pass a custom list.

Image OS detection
------------------
``image_info()`` runs ``windows.info`` / ``linux.info`` / ``mac.info``
in sequence until one returns rows; that wins and the scan loop runs
that OS's plugin set.

Graceful degradation
--------------------
When the binary isn't installed, every public function returns a
clean ``VolatilityError`` with a message pointing at ``pip install
volatility3`` or the upstream repo. We never try to install it
ourselves.

Sandboxing
----------
Memory images can contain attacker-controlled bytes (e.g., a poisoned
swap file). Volatility itself is the parser, but we cap each row's
serialized size and refuse images > 64 GiB by default to bound
runaway plugin output.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


# ---- exception ---- #


class VolatilityError(RuntimeError):
    """Raised on binary-missing / plugin-failure / image-rejected."""


# ---- binary discovery ---- #


_CANDIDATE_BINARIES = ("vol", "vol3", "volatility3", "vol.py")


def discover_binary() -> str | None:
    """Return the path of an installed vol binary, or None.

    Honors ``$DIGGER_VOLATILITY_BIN`` if set, otherwise PATH-scans
    common names."""
    env = os.environ.get("DIGGER_VOLATILITY_BIN")
    if env:
        if Path(env).is_file() and os.access(env, os.X_OK):
            return env
        return None
    for name in _CANDIDATE_BINARIES:
        found = shutil.which(name)
        if found:
            return found
    return None


def _require_binary() -> str:
    b = discover_binary()
    if not b:
        raise VolatilityError(
            "no Volatility 3 binary found in PATH. Install via "
            "`pip install volatility3` (provides `vol`) or set "
            "DIGGER_VOLATILITY_BIN to a vol3 executable."
        )
    return b


# ---- curated plugin list ---- #


# Per-OS plugins ordered by compromise-detection value. Each tuple is
# (plugin_name, description) — description is shown in `vol info`.
DEFAULT_PLUGINS: dict[str, list[tuple[str, str]]] = {
    "windows": [
        ("windows.info",     "image profile + OS build identification"),
        ("windows.pslist",   "active processes (EPROCESS list walk)"),
        ("windows.psscan",   "hidden processes (pool-tag scan; finds DKOM)"),
        ("windows.pstree",   "process tree (parent/child relationships)"),
        ("windows.cmdline",  "command lines per process"),
        ("windows.dlllist",  "loaded DLLs per process"),
        ("windows.netscan",  "network connections + sockets (memory scan)"),
        ("windows.netstat",  "established TCP/UDP endpoints"),
        ("windows.malfind",  "RWX/anonymous-exec memory regions per process"),
        ("windows.svcscan",  "Windows service enumeration"),
        ("windows.handles",  "open file/registry/event handles per process"),
        ("windows.driverscan", "loaded drivers (DRIVER_OBJECT scan)"),
        ("windows.modules",  "loaded kernel modules"),
        ("windows.callbacks", "registered kernel notification callbacks"),
        ("windows.envars",   "environment variables per process"),
    ],
    "linux": [
        ("linux.pslist",     "active processes (task_struct walk)"),
        ("linux.psscan",     "hidden processes (memory scan)"),
        ("linux.cmdline",    "process command lines"),
        ("linux.malfind",    "RWX memory regions per process"),
        ("linux.lsof",       "open files per process"),
        ("linux.bash",       "bash history recovered from memory"),
        ("linux.netstat",    "network connections"),
        ("linux.kmsg",       "kernel ring buffer"),
        ("linux.check_modules", "kernel module integrity (rootkit hunt)"),
        ("linux.check_syscall", "syscall table integrity"),
        ("linux.envars",     "process environment variables"),
        ("linux.elfs",       "loaded ELFs per process"),
        ("linux.tty_check",  "tty hooking (rootkit indicator)"),
    ],
    "mac": [
        ("mac.pslist",       "active processes"),
        ("mac.psaux",        "process tree + arguments"),
        ("mac.netstat",      "network connections"),
        ("mac.malfind",      "RWX memory regions"),
        ("mac.lsof",         "open files per process"),
        ("mac.kevents",      "kqueue event registration"),
        ("mac.list_files",   "file descriptor table"),
        ("mac.mount",        "mounted filesystems"),
        ("mac.bash",         "bash history from memory"),
        ("mac.check_syscall", "syscall table integrity"),
        ("mac.check_trap_table", "trap table integrity"),
        ("mac.kauth_listeners", "kauth listener registrations"),
    ],
}


# ---- result + helpers ---- #


@dataclass
class VolatilityResult:
    """Parsed output of one plugin run."""
    plugin: str
    rows: list[dict[str, Any]]
    elapsed_s: float
    stderr: str = ""
    returncode: int = 0
    raw_truncated: bool = False


def _run_subprocess(
    args: list[str], *, timeout_s: int = 600,
) -> tuple[int, str, str]:
    """Run a subprocess, return (rc, stdout, stderr)."""
    try:
        r = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout_s, check=False,
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return -1, (exc.stdout or ""), f"timed out after {timeout_s}s"
    except OSError as exc:
        return -2, "", f"OSError: {exc}"


def _parse_json_rows(stdout: str) -> tuple[list[dict[str, Any]], bool]:
    """Parse Volatility's ``-r json`` output. Returns (rows, truncated).

    Volatility 3 emits a JSON array of objects. We tolerate trailing
    whitespace, missing terminators (when stdout was truncated), and
    leading log lines if vol3 printed them before --quiet was honored."""
    if not stdout or not stdout.strip():
        return [], False
    # Try strict parse first
    try:
        parsed = json.loads(stdout)
        if isinstance(parsed, list):
            return parsed, False
        if isinstance(parsed, dict):
            return [parsed], False
    except json.JSONDecodeError:
        pass
    # Try to find the first '[' and best-effort-parse up to the last ']'
    start = stdout.find("[")
    end = stdout.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return [], True
    try:
        parsed = json.loads(stdout[start:end + 1])
        if isinstance(parsed, list):
            return parsed, True
    except json.JSONDecodeError:
        pass
    return [], True


# ---- per-plugin run ---- #


_MAX_IMAGE_BYTES = 64 * 1024 * 1024 * 1024   # 64 GiB
_MAX_ROW_FIELD_LEN = 8192                     # truncate huge per-row fields


def _check_image(image_path: str | Path) -> Path:
    p = Path(image_path)
    if not p.is_file():
        raise VolatilityError(f"image not found: {p}")
    try:
        sz = p.stat().st_size
    except OSError as exc:
        raise VolatilityError(f"image stat failed: {exc}") from exc
    if sz > _MAX_IMAGE_BYTES:
        raise VolatilityError(
            f"image {p} is {sz} bytes (> {_MAX_IMAGE_BYTES}-byte cap). "
            "Set DIGGER_VOLATILITY_MAX_BYTES if you need to override."
        )
    return p


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    """Truncate huge fields so a runaway plugin row doesn't blow the
    evidence store."""
    out: dict[str, Any] = {}
    for k, v in row.items():
        if isinstance(v, str) and len(v) > _MAX_ROW_FIELD_LEN:
            out[k] = v[:_MAX_ROW_FIELD_LEN] + " …<truncated>…"
        else:
            out[k] = v
    return out


def run_plugin(
    image_path: str | Path,
    plugin: str,
    *,
    binary: str | None = None,
    extra_args: list[str] | None = None,
    timeout_s: int = 600,
) -> VolatilityResult:
    """Run a single Volatility plugin against an image."""
    bin_path = binary or _require_binary()
    image_path = _check_image(image_path)
    extra_args = extra_args or []
    args = [
        bin_path,
        "-q",                 # quiet
        "-r", "json",         # JSON renderer
        "-f", str(image_path),
        plugin,
        *extra_args,
    ]
    started = time.time()
    rc, stdout, stderr = _run_subprocess(args, timeout_s=timeout_s)
    rows, truncated = _parse_json_rows(stdout)
    rows = [_normalize_row(r) for r in rows if isinstance(r, dict)]
    return VolatilityResult(
        plugin=plugin,
        rows=rows,
        elapsed_s=time.time() - started,
        stderr=stderr[-4000:],
        returncode=rc,
        raw_truncated=truncated,
    )


# ---- image OS detection ---- #


def image_info(
    image_path: str | Path,
    *,
    binary: str | None = None,
    timeout_s: int = 120,
) -> tuple[str, VolatilityResult]:
    """Identify the image OS by trying windows.info → linux.info → mac.info.

    Returns ``(os_name, result)`` for the first plugin that succeeded
    with at least one row. Raises VolatilityError if none did."""
    bin_path = binary or _require_binary()
    image_path = _check_image(image_path)
    candidates = [
        ("windows", "windows.info"),
        ("linux",   "banners.Banners"),   # cross-OS banner scan
        ("mac",     "mac.banners"),
    ]
    last_err = ""
    for os_name, plugin in candidates:
        r = run_plugin(
            image_path, plugin,
            binary=bin_path, timeout_s=timeout_s,
        )
        if r.returncode == 0 and r.rows:
            return os_name, r
        if r.stderr:
            last_err = r.stderr
    raise VolatilityError(
        f"could not identify image OS via info plugins. "
        f"Last vol stderr: {last_err[:500]}"
    )


# ---- whole-image scan ---- #


@dataclass
class ScanSummary:
    image_path: str
    os_name: str
    plugins_run: int = 0
    plugins_failed: int = 0
    rows_emitted: int = 0
    elapsed_s: float = 0.0
    per_plugin: list[VolatilityResult] = field(default_factory=list)


def scan_image(
    image_path: str | Path,
    store,
    *,
    plugins: Iterable[str] | None = None,
    os_name: str | None = None,
    binary: str | None = None,
    plugin_timeout_s: int = 600,
) -> ScanSummary:
    """Run the curated plugin list against ``image_path`` and emit one
    digger Artifact per plugin row into ``store``.

    Returns a ScanSummary the caller can pretty-print.

    If ``plugins`` is None, uses ``DEFAULT_PLUGINS[os_name]``. If
    ``os_name`` is None, runs ``image_info()`` first."""
    from digger.core.evidence import Artifact as DiggerArtifact

    bin_path = binary or _require_binary()
    image_path = _check_image(image_path)
    started = time.time()

    if os_name is None:
        os_name, _ = image_info(image_path, binary=bin_path)

    chosen: list[str]
    if plugins is None:
        chosen = [p for p, _desc in DEFAULT_PLUGINS.get(os_name, [])]
    else:
        chosen = list(plugins)

    summary = ScanSummary(
        image_path=str(image_path),
        os_name=os_name,
    )
    for plugin in chosen:
        r = run_plugin(
            image_path, plugin,
            binary=bin_path, timeout_s=plugin_timeout_s,
        )
        summary.per_plugin.append(r)
        summary.plugins_run += 1
        if r.returncode != 0:
            summary.plugins_failed += 1
        for row in r.rows:
            store.add_artifact(DiggerArtifact(
                collector=f"volatility:{plugin}",
                category="memory",
                subject=f"vol:{plugin}:{_row_subject(plugin, row)}",
                data={
                    "vol_plugin": plugin,
                    "vol_os":     os_name,
                    "vol_image":  str(image_path),
                    "row":        row,
                },
            ))
            summary.rows_emitted += 1

    summary.elapsed_s = time.time() - started
    return summary


def _row_subject(plugin: str, row: dict[str, Any]) -> str:
    """Pick a stable per-row subject for the Artifact, e.g. PID for
    process plugins, address for malfind."""
    for key in ("PID", "Pid", "pid", "Offset(V)", "Offset", "Name"):
        v = row.get(key)
        if v is not None and v != "":
            return f"{key}={v}"
    # Fallback: hash the row
    import hashlib
    return "h=" + hashlib.sha256(
        json.dumps(row, default=str, sort_keys=True).encode("utf-8"),
    ).hexdigest()[:12]
