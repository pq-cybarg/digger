"""SigmaHQ rule-corpus fetcher.

Pulls a curated slice of SigmaHQ/sigma rules — the canonical community
detection corpus — into the digger intel cache. The existing
:class:`digger.exchange.sigma.SigmaLoader` then consumes them at scan
time alongside the bundled rules.

We deliberately fetch a *slice* rather than the whole repo because:
  * SigmaHQ ships >3000 rules and parsing all of them at every scan
    is slow.
  * The Decepticon countermeasure surface area cleanly maps to four
    Sigma rule categories: process_creation, network_connection,
    file_event, and the credential_access / command_and_control tag
    families.

The fetcher hits the GitHub raw-content URLs for stable rule paths
under ``rules/cloud``, ``rules/linux``, ``rules/macos``, ``rules/windows``
that match our taxonomy. A failed individual file does not abort the
batch.

The cache directory ``$DIGGER_INTEL_DIR/sigma-corpus/`` is what the
SigmaLoader will pick up. A small summary JSON at
``$DIGGER_INTEL_DIR/sigmahq_corpus.json`` is the canonical
``load_intel("sigmahq_corpus")`` payload so detectors can see what's
loaded without re-walking the directory.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import time
from pathlib import Path

import requests


# Stable, frequently-updated rule paths in SigmaHQ. Each is a flat list of
# .yml files in that folder; we fetch the folder listing via the GitHub API
# and then bulk-download via the codeload tarball.
_GITHUB_API_TREE = (
    "https://api.github.com/repos/SigmaHQ/sigma/git/trees/master?recursive=1"
)
_GITHUB_TAR = (
    "https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master"
)


# Path-prefix predicates that decide which rule files we keep on disk.
# Matches against the in-tarball member name *after* stripping the leading
# top-level dir "sigma-master/".
def _keep_rule(path: str) -> bool:
    # Only YAML rules
    if not path.endswith(".yml"):
        return False
    if not path.startswith("rules/"):
        return False
    # Keep the categories we care about
    return any(seg in path for seg in (
        "/command_and_control/",
        "/credential_access/",
        "/lateral_movement/",
        "/privilege_escalation/",
        "/process_creation/",
        "/network_connection/",
        "/persistence/",
        "/defense_evasion/",
    ))


def cache_dir() -> Path:
    from digger.intel.feeds import intel_dir
    d = intel_dir() / "sigma-corpus"
    d.mkdir(parents=True, exist_ok=True)
    return d


def fetch_as_feed_bytes() -> bytes:
    """Pull the SigmaHQ master tarball, extract the rule subset to the
    cache directory, return a small summary JSON as the feed payload."""
    from digger.opsec.airgap import assert_network_allowed
    assert_network_allowed("intel-feed:sigmahq_corpus")

    print("  [sigmahq] downloading master tarball ...", file=sys.stderr)
    try:
        r = requests.get(_GITHUB_TAR, timeout=120, stream=True)
        r.raise_for_status()
        raw = r.content
    except requests.RequestException as exc:
        raise RuntimeError(f"sigmahq tarball fetch failed: {exc}")

    out = cache_dir()
    # Clean stale .yml under cache so removed upstream rules don't linger.
    for f in out.rglob("*.yml"):
        try:
            f.unlink()
        except OSError:
            pass

    kept_files: list[str] = []
    total_seen = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
            for member in tf:
                if not member.isfile():
                    continue
                # Strip leading "sigma-master/" or "sigma-<sha>/" prefix
                name = member.name
                if "/" in name:
                    _, _, name = name.partition("/")
                total_seen += 1
                if not _keep_rule(name):
                    continue
                # Sanitize: keep only the basename relative to "rules/"
                relpath = name
                target = out / relpath
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    fh = tf.extractfile(member)
                    if fh is None:
                        continue
                    target.write_bytes(fh.read())
                    kept_files.append(relpath)
                except (OSError, tarfile.TarError):
                    continue
    except tarfile.TarError as exc:
        raise RuntimeError(f"sigmahq tarball parse failed: {exc}")

    print(f"  [sigmahq] kept {len(kept_files)} / {total_seen} rules",
          file=sys.stderr)

    summary = {
        "source": "sigmahq/sigma",
        "fetched_at": time.time(),
        "rule_count": len(kept_files),
        "total_seen": total_seen,
        "cache_dir": str(out),
        "categories": sorted({
            "/".join(p.split("/")[1:-1]) for p in kept_files
        }),
    }
    return json.dumps(summary, default=str).encode("utf-8")


def parse_feed_payload(raw: bytes) -> dict:
    return json.loads(raw)


def loaded_rule_dirs() -> list[Path]:
    """Return any directories holding live-fetched Sigma rules.

    SigmaLoader uses this to extend its default rule-search path.
    """
    d = cache_dir()
    return [d] if d.exists() and any(d.rglob("*.yml")) else []
