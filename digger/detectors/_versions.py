"""Loose version parsing + range matching for service CVE detection.

Service banners vary wildly — OpenSSH says ``OpenSSH_9.3p1``, nginx says
``nginx/1.25.3``, Debian-built packages add ``-1ubuntu0.1``. We don't try
to be PEP-440 or semver-perfect; we tokenize into numeric segments and
compare lexicographically. The OSV-style ``introduced`` / ``fixed`` /
``last_affected`` range format is supported.
"""

from __future__ import annotations

import re
from typing import Iterable


_NUM_RE = re.compile(r"\d+")


def parse_version(s: str | None) -> tuple[int, ...]:
    """Extract numeric segments from a version string.

    >>> parse_version("OpenSSH_9.3p1")
    (9, 3, 1)
    >>> parse_version("nginx/1.25.3")
    (1, 25, 3)
    >>> parse_version("1.2.3-1ubuntu0.1")
    (1, 2, 3, 1, 0, 1)
    >>> parse_version(None)
    ()
    """
    if not s:
        return ()
    return tuple(int(m) for m in _NUM_RE.findall(s))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Compare zero-padded version tuples. Shorter wins on ties (1.2 < 1.2.1)."""
    n = max(len(a), len(b))
    pa = a + (0,) * (n - len(a))
    pb = b + (0,) * (n - len(b))
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def version_lt(a: str | None, b: str | None) -> bool:
    return _cmp(parse_version(a), parse_version(b)) < 0


def version_lte(a: str | None, b: str | None) -> bool:
    return _cmp(parse_version(a), parse_version(b)) <= 0


def version_gte(a: str | None, b: str | None) -> bool:
    return _cmp(parse_version(a), parse_version(b)) >= 0


def in_range(version: str | None, ranges: Iterable[dict]) -> bool:
    """Return True if ``version`` falls inside any range in ``ranges``.

    Range dict supports OSV-style keys:
      - ``introduced`` (inclusive lower bound; default 0.0.0)
      - ``fixed``      (exclusive upper bound)
      - ``last_affected`` (inclusive upper bound; mutually exclusive with ``fixed``)

    A range with neither ``fixed`` nor ``last_affected`` means "everything
    at and above ``introduced``" (open-ended upper).
    """
    if not version:
        return False
    for r in ranges or []:
        introduced = r.get("introduced", "0")
        fixed = r.get("fixed")
        last_affected = r.get("last_affected")
        if not version_gte(version, introduced):
            continue
        if fixed and not version_lt(version, fixed):
            continue
        if last_affected and not version_lte(version, last_affected):
            continue
        return True
    return False
