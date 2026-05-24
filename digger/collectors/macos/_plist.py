"""macOS plist parsing helper.

Uses plistlib (stdlib) for XML/binary plists. Falls back to invoking
`plutil -convert json` when a plist can't be parsed natively (rare).
"""

from __future__ import annotations

import plistlib
import shutil
import subprocess
from pathlib import Path
from typing import Any


def read_plist(path: str | Path) -> dict[str, Any] | None:
    p = Path(path)
    if not p.exists():
        return None
    try:
        with open(p, "rb") as f:
            return plistlib.load(f)
    except Exception:
        pass
    if shutil.which("plutil"):
        try:
            out = subprocess.run(
                ["plutil", "-convert", "json", "-o", "-", str(p)],
                capture_output=True, text=True, timeout=10, check=False,
            ).stdout
            import json
            return json.loads(out) if out else None
        except Exception:
            return None
    return None
