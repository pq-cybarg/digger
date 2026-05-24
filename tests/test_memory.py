"""Memory-region model, anomaly detector, collector smoke."""

from __future__ import annotations

import os
from pathlib import Path

from digger.core import Artifact, EvidenceStore
from digger.memory import MemoryAnomalyDetector
from digger.memory.maps import (
    MemoryRegion, list_regions_for_pid, list_regions_for_all_pids,
)


def _r(**kw) -> MemoryRegion:
    base = dict(pid=1, start=0x1000, end=0x2000, perms="r-xp",
                offset=0, backing="/usr/bin/cat", private=True)
    base.update(kw)
    return MemoryRegion(**base)


def test_region_classifies_rwx():
    r = _r(perms="rwxp", backing="[anon]")
    assert r.is_rwx
    assert r.is_anonymous_exec
    assert not r.is_backing_in_drop


def test_region_classifies_anonymous_exec():
    r = _r(perms="r-xp", backing="[anon]")
    assert r.is_anonymous_exec
    assert not r.is_rwx


def test_region_classifies_drop_backing():
    r = _r(backing="/tmp/.X11-unix/.libtelemetry.so")
    assert r.is_backing_in_drop
    assert not r.is_anonymous_exec


def test_region_clean_legit():
    r = _r(backing="/usr/bin/cat", perms="r-xp")
    assert not r.is_anonymous_exec
    assert not r.is_rwx
    assert not r.is_backing_in_drop


def test_region_size():
    r = _r(start=0x1000, end=0x5000)
    assert r.size == 0x4000


def test_detector_emits_findings(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(
        collector="memory_regions", category="memory",
        subject="pid=1234 evil",
        data={
            "pid": 1234, "name": "evil", "exe": "/usr/local/bin/evil",
            "counts": {"total": 50, "rwx": 1, "anonymous_exec": 1,
                       "backing_in_drop": 1, "executable": 10, "private": 50},
            "suspect_regions": [
                {"pid": 1234, "perms": "rwxp", "start": "0x10000", "end": "0x11000",
                 "size": 4096, "backing": "[anon]",
                 "is_rwx": True, "is_anonymous_exec": True, "is_backing_in_drop": False},
                {"pid": 1234, "perms": "r-xp", "start": "0x20000", "end": "0x21000",
                 "size": 4096, "backing": "[anon]",
                 "is_rwx": False, "is_anonymous_exec": True, "is_backing_in_drop": False},
                {"pid": 1234, "perms": "r--p", "start": "0x30000", "end": "0x31000",
                 "size": 4096, "backing": "/tmp/.so",
                 "is_rwx": False, "is_anonymous_exec": False, "is_backing_in_drop": True},
            ],
            "suspect_count": 3,
        },
    ))
    n = MemoryAnomalyDetector().run(store)
    # 3 finding kinds: RWX, anon-exec (non-rwx), drop-backed
    assert n == 3
    findings = list(store.iter_findings())
    titles = " ".join(f["title"].lower() for f in findings)
    assert "rwx" in titles
    assert "anonymous executable" in titles
    assert "drop location" in titles
    store.close()


def test_list_regions_does_not_crash_on_real_process():
    """At minimum, our own process should yield SOME regions on Linux/macOS.
    On unsupported platforms or weird sandboxes this can be empty; we
    just want a non-crashing call."""
    regions = list_regions_for_pid(os.getpid())
    assert isinstance(regions, list)


def test_list_regions_for_all_pids_returns_dict():
    out = list_regions_for_all_pids(limit=3)
    assert isinstance(out, dict)
