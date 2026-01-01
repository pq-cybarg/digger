"""Shared rule-loading helpers for detectors that consume bundled YAML.

Looks for live cached intel under ``digger.intel.intel_dir()`` first, then
falls back to the bundled snapshot under ``digger/rules/``.

PQC integrity check on intel cache
----------------------------------
Detectors load IOCs from ``~/.cache/digger/intel/``. An attacker who can
write to that directory can poison detections. Each process verifies the
ML-DSA-65 signature over the cache **once** on first ``load_intel()``
call. Behavior is controlled by:

  - ``DIGGER_INTEL_NO_VERIFY=1`` — skip verification entirely
  - ``DIGGER_INTEL_STRICT=1``    — refuse to return data on unsigned /
                                   tampered cache (return None instead)

Default (neither set): verify once, warn to stderr if unsigned or
tampered, still return the data (bundled fallback in rules/ is
authoritative).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

_BUNDLED = Path(__file__).parent.parent / "rules"


def load_yaml(rel_path: str) -> dict[str, Any]:
    """Load ``digger/rules/<rel_path>`` as YAML. Returns {} on failure."""
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        return {}
    full = _BUNDLED / rel_path
    if not full.exists():
        return {}
    try:
        with full.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


# Process-lifetime cache of the intel-verification verdict. None = not
# yet computed. Tuple is (ok_to_use, reason).
_INTEL_VERIFIED: tuple[bool, str] | None = None


def _intel_verdict() -> tuple[bool, str]:
    """Return (ok_to_use, reason). Memoized for the process.

    ok_to_use is False only when strict mode is set AND verification
    failed. Outside strict mode we always return True so detectors can
    still use the (possibly-poisoned) cache, but we emit a stderr warning
    so the user can see something is wrong.
    """
    global _INTEL_VERIFIED
    if _INTEL_VERIFIED is not None:
        return _INTEL_VERIFIED

    if os.environ.get("DIGGER_INTEL_NO_VERIFY"):
        _INTEL_VERIFIED = (True, "verification disabled via DIGGER_INTEL_NO_VERIFY")
        return _INTEL_VERIFIED

    strict = bool(os.environ.get("DIGGER_INTEL_STRICT"))
    try:
        from digger.intel.integrity import intel_quick_status, verify_intel
    except Exception as exc:
        _INTEL_VERIFIED = (True, f"intel integrity module unavailable: {exc}")
        return _INTEL_VERIFIED

    try:
        qs = intel_quick_status()
    except Exception as exc:
        _INTEL_VERIFIED = (True, f"intel quick-status failed: {exc}")
        return _INTEL_VERIFIED

    if not qs.get("signed"):
        msg = (
            "[digger] intel cache is unsigned — detectors will consume it but "
            "have no integrity guarantee. Run `digger intel sign --key <secret>` "
            "to bind a PQC signature, or set DIGGER_INTEL_NO_VERIFY=1 to silence."
        )
        print(msg, file=sys.stderr)
        _INTEL_VERIFIED = (not strict, "unsigned")
        return _INTEL_VERIFIED

    try:
        result = verify_intel()
    except Exception as exc:
        _INTEL_VERIFIED = (True, f"intel verify raised: {exc}")
        return _INTEL_VERIFIED

    if result.verified:
        _INTEL_VERIFIED = (True, f"verified ({result.algorithm})")
        return _INTEL_VERIFIED

    msg = (
        f"[digger] intel cache signature does NOT verify: {result.note}. "
        "Cache contents may have been tampered with. Detectors will "
        + ("REFUSE the cache (strict mode)." if strict
           else "still consume the cache; re-run `digger intel update --sign-key <secret>` to refresh.")
    )
    print(msg, file=sys.stderr)
    _INTEL_VERIFIED = (not strict, "tampered")
    return _INTEL_VERIFIED


def _reset_intel_verdict_for_tests() -> None:
    """Drop the cached verdict (test-only)."""
    global _INTEL_VERIFIED
    _INTEL_VERIFIED = None


def load_intel(feed_name: str) -> dict[str, Any] | None:
    """Load live cached intel feed, or None if not yet fetched / refused.

    Performs (once per process) a PQC signature verification of the intel
    cache. See module docstring for environment-variable controls.
    """
    ok, _reason = _intel_verdict()
    if not ok:
        return None
    try:
        from digger.intel import load_cached
        return load_cached(feed_name)
    except Exception:
        return None
