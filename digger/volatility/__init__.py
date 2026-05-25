"""Volatility 3 memory-image bridge.

Shells out to a user-installed ``vol3`` binary (or ``volatility3``)
and ingests selected plugin output into the EvidenceStore. Memory
forensics is the major DFIR capability digger doesn't natively
have — this bridge gives access to the Volatility 3 plugin ecosystem
without re-implementing it.

Architecture mirrors the ``digger.art`` and ``digger.forensic_artifacts``
modules: external binary + curated plugin selection + clean degradation
when the binary isn't installed.

Public API
----------
``discover_binary()``    find ``vol`` / ``vol3`` / ``volatility3`` in PATH
``image_info(path)``     run windows.info / linux.info / mac.info and
                          identify the image profile
``run_plugin(...)``      execute a single plugin, return parsed rows
``scan_image(...)``      run the curated relevance-list against an
                          image and emit Artifacts into a case
"""

from __future__ import annotations

from digger.volatility.runner import (
    DEFAULT_PLUGINS,
    VolatilityError,
    VolatilityResult,
    discover_binary,
    image_info,
    run_plugin,
    scan_image,
)

__all__ = [
    "DEFAULT_PLUGINS",
    "VolatilityError",
    "VolatilityResult",
    "discover_binary",
    "image_info",
    "run_plugin",
    "scan_image",
]
