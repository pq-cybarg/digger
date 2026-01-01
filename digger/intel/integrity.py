"""Post-quantum integrity for the threat-intel feed cache.

digger pulls IOCs from a dozen external feeds (CISA KEV, abuse.ch
URLhaus / ThreatFox / MalwareBazaar, Tor exit list, Spamhaus, OpenSSF
malicious-packages, the Shai-Hulud list, GitHub Advisory DB) into a
local cache at ``~/.cache/digger/intel/`` and detectors consume that
cache at scan time. The same supply-chain concern that applies to the
LOKI signature-base corpus applies here:

  * An attacker who can write to ``~/.cache/digger/intel/`` can poison
    the cache to make the C2 / supply-chain detectors *miss* what
    they care about (delete entries), or to make detectors *misfire*
    on benign infrastructure (insert entries).
  * An attacker who MITM's an HTTPS pull can drop a tampered cache file
    that looks legitimate on every subsequent verify.
  * Classical TLS protects the wire but not bytes already on disk.

Mitigation: same as the signature-base corpus. After
``digger intel update`` we can compute a dual SHA-256 + SHA3-256
tree-hash of the cache directory and PQC-sign it (ML-DSA-65 by
default). Subsequent uses verify the signature and refuse / warn on
mismatch.

Implementation lives in :mod:`digger.integrity`; this module re-exports
the same names with intel-specific defaults so callers in
``digger.intel.feeds`` and detectors that call ``load_intel()`` can
verify cheaply.
"""

from __future__ import annotations

from pathlib import Path

from digger.integrity import (
    SIG_FILENAME,
    TreeHash,
    IntegrityResult,
    compute_tree_hash,
    sign_snapshot as _sign_snapshot,
    verify_snapshot as _verify_snapshot,
    quick_status as _quick_status,
)


def _resolve_target(target: Path | str | None) -> Path:
    if target is None:
        from digger.intel.feeds import intel_dir
        return intel_dir()
    return Path(target).expanduser().resolve()


def sign_intel(
    target: Path | str | None,
    secret_key_path: Path | str,
    algorithm: str = "ML-DSA-65",
    note: str = "",
) -> Path:
    """PQC-sign the current intel cache. Returns the signature path."""
    root = _resolve_target(target)
    return _sign_snapshot(
        root, secret_key_path=secret_key_path,
        algorithm=algorithm,
        note=note or "digger intel-cache snapshot",
    )


def verify_intel(target: Path | str | None = None) -> IntegrityResult:
    """Verify the PQC signature against the current intel cache."""
    return _verify_snapshot(_resolve_target(target))


def intel_quick_status(target: Path | str | None = None) -> dict:
    """Cheap status — does a signature file exist and what does it claim?
    Use ``verify_intel`` for the cryptographic recheck."""
    return _quick_status(_resolve_target(target))


__all__ = [
    "SIG_FILENAME", "TreeHash", "IntegrityResult",
    "compute_tree_hash", "sign_intel", "verify_intel", "intel_quick_status",
]
