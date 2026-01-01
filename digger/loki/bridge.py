"""Optional bridge to an installed LOKI / Loki-RS binary.

If the user has a working LOKI install (Python LOKI or Loki-RS) on the
host, we can invoke it directly on a target directory and ingest the
results as additional findings. Default-disabled because most users will
prefer digger's native LokiStyleDetector — the bridge is here for
parity with existing LOKI workflows.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class LokiResult:
    ok: bool
    binary: str
    stdout: str
    stderr: str
    return_code: int


def run_loki_binary(
    target: str | Path,
    binary: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
    timeout: float = 600.0,
) -> LokiResult:
    """Run LOKI/Loki-RS over `target`, return its raw output.

    Auto-detects `loki`, `loki.exe`, `loki-rs`, or `Loki.py` on PATH. Pass
    `binary` explicitly to override.
    """
    candidates = [binary] if binary else ["loki", "loki-rs", "Loki.py", "loki.exe"]
    found = None
    for c in candidates:
        if not c:
            continue
        if shutil.which(c):
            found = c
            break
    if not found:
        return LokiResult(False, binary or "(auto)", "", "no loki binary on PATH", -1)

    cmd = [found, "-p", str(target)]
    if extra_args:
        cmd += list(extra_args)
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
        return LokiResult(
            ok=(r.returncode in (0, 1)),  # LOKI returns 1 if findings present
            binary=found,
            stdout=r.stdout,
            stderr=r.stderr,
            return_code=r.returncode,
        )
    except subprocess.TimeoutExpired:
        return LokiResult(False, found, "", "timeout", -1)
    except OSError as exc:
        return LokiResult(False, found, "", str(exc), -1)
