"""ServiceCVEDetector — version-range matching, live-first, bundled fallback."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors._versions import in_range, parse_version, version_lt
from digger.detectors.service_cve import ServiceCVEDetector


# ---- version parsing ---- #


def test_parse_version_basic():
    assert parse_version("1.25.3") == (1, 25, 3)
    assert parse_version("OpenSSH_9.3p1") == (9, 3, 1)
    assert parse_version("nginx/1.25.3") == (1, 25, 3)
    assert parse_version("1.2.3-1ubuntu0.1") == (1, 2, 3, 1, 0, 1)
    assert parse_version(None) == ()
    assert parse_version("") == ()


def test_version_lt_padding():
    # 1.2 < 1.2.1 because pad with zero: (1,2,0) < (1,2,1)
    assert version_lt("1.2", "1.2.1") is True
    assert version_lt("1.2.0", "1.2") is False  # equal after padding


def test_in_range_open_ended():
    ranges = [{"introduced": "1.0"}]
    assert in_range("1.5", ranges) is True
    assert in_range("0.9", ranges) is False


def test_in_range_fixed():
    ranges = [{"introduced": "1.0", "fixed": "2.0"}]
    assert in_range("1.5", ranges) is True
    assert in_range("2.0", ranges) is False  # fixed is exclusive
    assert in_range("2.0.1", ranges) is False


def test_in_range_last_affected():
    ranges = [{"introduced": "1.0", "last_affected": "1.9"}]
    assert in_range("1.5", ranges) is True
    assert in_range("1.9", ranges) is True  # last_affected is inclusive
    assert in_range("1.9.1", ranges) is False


def test_in_range_multiple_branches():
    ranges = [
        {"introduced": "8.5", "fixed": "9.8"},   # regreSSHion range
        {"introduced": "4.0", "fixed": "4.4"},   # ancient branch
    ]
    assert in_range("9.6", ranges) is True
    assert in_range("9.8", ranges) is False
    assert in_range("4.2", ranges) is True
    assert in_range("5.0", ranges) is False


# ---- detector wiring ---- #


def _store_with_service(tmp_path, service: str, version: str) -> EvidenceStore:
    store = EvidenceStore(tmp_path / "evidence.db")
    store.add_artifact(Artifact(
        collector="service_versions",
        category="service",
        subject=f"{service} {version}",
        data={"service": service, "version": version, "binary": service},
    ))
    return store


def test_detector_emits_nothing_without_live_cache(tmp_path, monkeypatch, capsys):
    """No live cache → detector logs once and emits nothing.

    There is no hand-typed bundled fallback (would go stale).
    """
    monkeypatch.setenv("DIGGER_INTEL_DIR", str(tmp_path / "intel_empty"))
    monkeypatch.setenv("DIGGER_INTEL_NO_VERIFY", "1")
    from digger.detectors import _rules_io, service_cve
    _rules_io._reset_intel_verdict_for_tests()
    service_cve._WARNED_NO_CORPUS = False  # reset module-level once-warn

    store = _store_with_service(tmp_path, "nginx", "1.20.0")
    findings = list(ServiceCVEDetector().detect(store))
    assert findings == []
    err = capsys.readouterr().err
    assert "digger intel update" in err


def test_detector_prefers_live_cache_over_bundled(tmp_path, monkeypatch):
    """When live cache exists, it wins over bundled snapshot."""
    intel_dir = tmp_path / "intel_live"
    intel_dir.mkdir()
    # Plant a live cache with a synthetic CVE the bundled file can't have.
    payload = {
        "source": "nvd",
        "generated_at": 0,
        "service_count": 1,
        "cve_count": 1,
        "services": {
            "nginx": [{
                "id": "CVE-9999-TEST-LIVE-FEED",
                "severity": "high",
                "summary": "synthetic CVE proving live-cache path was used",
                "affected": [{"introduced": "0", "fixed": "999.0"}],
                "references": ["https://example.invalid/synthetic"],
            }],
        },
    }
    (intel_dir / "nvd_service_cves.json").write_text(json.dumps(payload))

    monkeypatch.setenv("DIGGER_INTEL_DIR", str(intel_dir))
    monkeypatch.setenv("DIGGER_INTEL_NO_VERIFY", "1")
    from digger.detectors import _rules_io
    _rules_io._reset_intel_verdict_for_tests()

    store = _store_with_service(tmp_path, "nginx", "1.20.0")
    findings = list(ServiceCVEDetector().detect(store))
    synthetic = [f for f in findings if "CVE-9999-TEST-LIVE-FEED" in f.title]
    assert synthetic, (
        "live cache should be consumed in preference to bundled snapshot, "
        f"got findings: {[f.title for f in findings]}"
    )
    assert synthetic[0].severity == "high"
    assert synthetic[0].mitre == "T1190"
