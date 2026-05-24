"""BrowserDetector — service-worker findings for unpatched chromium bug
https://issues.chromium.org/issues/40062121."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.browser import BrowserDetector


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _sw(store, profile, origins, script_count=0, storage_bytes=0):
    store.add_artifact(Artifact(
        collector="browsers",
        category="browser",
        subject=f"chrome.service_workers:Chrome/{profile}",
        data={
            "profile": f"/path/to/Chrome/{profile}",
            "origins": origins,
            "origin_count": len(origins),
            "script_count": script_count,
            "storage_bytes": storage_bytes,
        },
    ))


def test_baseline_info_finding_always_emitted(tmp_path):
    store = _store(tmp_path)
    _sw(store, "Default", ["https://mail.google.com"], script_count=10,
        storage_bytes=10_000_000)
    findings = list(BrowserDetector().detect(store))
    info = [f for f in findings if f.evidence.get("kind") == "service_worker_baseline"]
    assert info, [f.title for f in findings]
    assert info[0].severity == "info"
    # Friendly origin is correctly classified
    assert "mail.google.com" in info[0].evidence["origins_friendly"]
    assert info[0].evidence["origins_unfamiliar"] == []
    store.close()


def test_unfamiliar_origins_flagged(tmp_path):
    store = _store(tmp_path)
    origins = [
        "https://mail.google.com",
        "https://virushunterx.xyz",
        "https://random-startup.example",
        "https://capriole.com",
        "https://cellframe.net",
        "https://mexc.co",
        "https://flova.ai",
    ]
    _sw(store, "Profile 3", origins, script_count=50, storage_bytes=50_000_000)
    findings = list(BrowserDetector().detect(store))
    unfam = [f for f in findings
             if f.evidence.get("kind") == "service_worker_unfamiliar_origins"]
    assert unfam, [f.title for f in findings]
    assert unfam[0].severity == "medium"
    assert len(unfam[0].evidence["unfamiliar_origins"]) >= 5
    assert "mail.google.com" not in unfam[0].evidence["unfamiliar_origins"]
    store.close()


def test_storage_bloat_high_when_above_2gb(tmp_path):
    store = _store(tmp_path)
    _sw(store, "Profile 4", ["https://mail.google.com"],
        script_count=200, storage_bytes=3 * 1024 * 1024 * 1024)
    findings = list(BrowserDetector().detect(store))
    bloat = [f for f in findings if f.evidence.get("kind") == "service_worker_storage_bloat"]
    assert bloat
    assert bloat[0].severity == "high"
    store.close()


def test_storage_bloat_medium_when_between_500mb_and_2gb(tmp_path):
    store = _store(tmp_path)
    _sw(store, "Default", ["https://mail.google.com"],
        storage_bytes=800 * 1024 * 1024)
    findings = list(BrowserDetector().detect(store))
    bloat = [f for f in findings if f.evidence.get("kind") == "service_worker_storage_bloat"]
    assert bloat
    assert bloat[0].severity == "medium"
    store.close()


def test_high_origin_count_low_severity(tmp_path):
    store = _store(tmp_path)
    origins = [f"https://site{i}.example" for i in range(80)]
    _sw(store, "Default", origins, script_count=400, storage_bytes=10_000_000)
    findings = list(BrowserDetector().detect(store))
    high = [f for f in findings
            if f.evidence.get("kind") == "service_worker_high_origin_count"]
    assert high
    assert high[0].severity == "low"
    assert high[0].evidence["origin_count"] == 80
    store.close()


def test_chromium_bug_url_present_in_baseline_evidence(tmp_path):
    store = _store(tmp_path)
    _sw(store, "Default", ["https://mail.google.com"], script_count=1,
        storage_bytes=1_000)
    findings = list(BrowserDetector().detect(store))
    info = next(f for f in findings
                if f.evidence.get("kind") == "service_worker_baseline")
    # The detector must surface the bug URL so reviewers can pivot.
    assert info.evidence["chromium_bug"].endswith("/40062121")


def test_subdomain_matches_friendly_set(tmp_path):
    """docs.google.com should be recognized via the strip-subdomain pass."""
    store = _store(tmp_path)
    _sw(store, "Default", ["https://docs.google.com",
                            "https://photos.google.com"],
        script_count=2, storage_bytes=1_000)
    findings = list(BrowserDetector().detect(store))
    info = next(f for f in findings
                if f.evidence.get("kind") == "service_worker_baseline")
    assert "docs.google.com" in info.evidence["origins_friendly"]
    assert "photos.google.com" in info.evidence["origins_friendly"]
    assert info.evidence["origins_unfamiliar"] == []
