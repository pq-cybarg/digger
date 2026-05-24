"""supply_chain detector: openssf live feed authoritative, bundled fallback."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.supply_chain import SupplyChainDetector
from digger.intel import feeds as feeds_mod


def _point_intel_dir(monkeypatch, root):
    monkeypatch.setattr(feeds_mod, "intel_dir", lambda: root)
    monkeypatch.setenv("DIGGER_INTEL_NO_VERIFY", "1")
    from digger.detectors import _rules_io
    _rules_io._reset_intel_verdict_for_tests()


def _npm_project(store, project, locked):
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject=f"npm:{project}",
        data={"project": project, "locked_packages": locked},
    ))


def _pypi_env(store, interpreter, entries):
    store.add_artifact(Artifact(
        collector="python_packages", category="inventory",
        subject=f"pip:{interpreter}",
        data={"interpreter": interpreter, "entries": entries},
    ))


# ---- live feed wins over bundled ---- #


def test_live_openssf_entry_flagged(tmp_path, monkeypatch):
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    _point_intel_dir(monkeypatch, intel_dir)

    # Plant a live openssf feed with a synthetic package the bundled YAML
    # does NOT carry — proves the live feed alone fired the finding.
    payload = {
        "source": "openssf",
        "raw": {
            "entries": [
                {
                    "id": "MAL-9999-TEST",
                    "affected": [{
                        "package": {"ecosystem": "npm",
                                     "name": "synthetic-live-malware"},
                        "versions": ["1.0.0"],
                    }],
                },
            ],
        },
    }
    (intel_dir / "openssf_malicious_packages.json").write_text(json.dumps(payload))

    store = EvidenceStore(tmp_path / "evidence.db")
    _npm_project(store, "my-app", {"synthetic-live-malware": "1.0.0"})

    findings = list(SupplyChainDetector().detect(store))
    syn = [f for f in findings if "synthetic-live-malware" in f.title]
    assert syn, [f.title for f in findings]
    assert syn[0].severity == "critical"
    assert syn[0].mitre == "T1195.001"
    store.close()


# ---- bundled fallback when no live feed ---- #


def test_bundled_fallback_when_live_feed_missing(tmp_path, monkeypatch):
    empty = tmp_path / "empty_intel"
    empty.mkdir()
    _point_intel_dir(monkeypatch, empty)

    store = EvidenceStore(tmp_path / "evidence.db")
    # event-stream@3.3.6 is in the bundled seed (Copay incident).
    _npm_project(store, "legacy", {"event-stream": "3.3.6"})

    findings = list(SupplyChainDetector().detect(store))
    es = [f for f in findings if "event-stream" in f.title]
    assert es, [f.title for f in findings]
    store.close()


# ---- live feed empty entries list = treat as missing, fall back ---- #


def test_live_feed_empty_list_falls_back_to_bundled(tmp_path, monkeypatch):
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    _point_intel_dir(monkeypatch, intel_dir)

    payload = {"source": "openssf", "raw": {"entries": []}}
    (intel_dir / "openssf_malicious_packages.json").write_text(json.dumps(payload))

    store = EvidenceStore(tmp_path / "evidence.db")
    _npm_project(store, "legacy", {"event-stream": "3.3.6"})

    findings = list(SupplyChainDetector().detect(store))
    es = [f for f in findings if "event-stream" in f.title]
    assert es, "empty live feed should trigger bundled-fallback"
    store.close()


# ---- both live + bundled present: live used, bundled not merged ---- #


def test_live_feed_present_bundled_not_merged(tmp_path, monkeypatch):
    """When the live feed has entries, the bundled file is NOT additively
    merged — the live feed is treated as authoritative."""
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    _point_intel_dir(monkeypatch, intel_dir)

    payload = {
        "source": "openssf",
        "raw": {"entries": [{
            "id": "MAL-1",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "synthetic-other"},
                "versions": ["1.0.0"],
            }],
        }]},
    }
    (intel_dir / "openssf_malicious_packages.json").write_text(json.dumps(payload))

    store = EvidenceStore(tmp_path / "evidence.db")
    # event-stream IS in bundled, but bundled should NOT be consulted when
    # live feed is present.
    _npm_project(store, "legacy", {"event-stream": "3.3.6"})

    findings = list(SupplyChainDetector().detect(store))
    es = [f for f in findings if "event-stream" in f.title]
    assert es == [], (
        "live feed present should be authoritative; bundled must not "
        "additively contribute"
    )
    store.close()
