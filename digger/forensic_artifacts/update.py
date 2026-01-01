"""Clone or fast-forward the ForensicArtifacts upstream repo."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from digger.forensic_artifacts.loader import cache_dir


_REPO = "https://github.com/ForensicArtifacts/artifacts.git"


def update_corpus(dest: Path | None = None) -> dict[str, Any]:
    """Clone or fast-forward into ``dest`` (default: ``cache_dir()``).

    Network-gated via ``digger.opsec.airgap.assert_network_allowed`` so
    air-gapped operators don't accidentally fetch."""
    from digger.opsec.airgap import assert_network_allowed
    assert_network_allowed("forensic-artifacts:upstream")

    dest = dest or cache_dir()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if (dest / ".git").is_dir():
        r = subprocess.run(
            ["git", "-C", str(dest), "pull", "--ff-only"],
            capture_output=True, text=True, timeout=120,
        )
    else:
        r = subprocess.run(
            ["git", "clone", "--depth", "1", _REPO, str(dest)],
            capture_output=True, text=True, timeout=300,
        )
    return {
        "dest": str(dest),
        "returncode": r.returncode,
        "stdout": (r.stdout or "")[-2000:],
        "stderr": (r.stderr or "")[-2000:],
    }
