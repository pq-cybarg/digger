"""Unpatched-Chromium-bug-class corpus: drives BrowserDetector
findings without code changes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors._rules_io import load_yaml
from digger.detectors.browser import BrowserDetector
from digger.intel import feeds as feeds_mod


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _sw_art(store, profile, origins):
    store.add_artifact(Artifact(
        collector="browsers", category="browser",
        subject=f"chrome.service_workers:Chrome/{profile}",
        data={"profile": f"/path/Chrome/{profile}",
              "origins": origins, "origin_count": len(origins),
              "script_count": len(origins), "storage_bytes": 1000},
    ))


# ---- corpus shape ---- #


def test_corpus_loads_with_required_fields():
    corpus = load_yaml("browsers/chromium_unpatched.yaml")
    assert corpus, "corpus failed to load"
    issues = corpus.get("issues")
    assert isinstance(issues, list) and len(issues) >= 1
    for entry in issues:
        for k in ("id", "short_id", "title", "url", "vendor_status",
                  "affected_versions", "impact", "detection_signal",
                  "workaround", "references"):
            assert k in entry, f"entry {entry.get('id')} missing field {k}"
        sig = entry["detection_signal"]
        assert "kind" in sig and "threshold" in sig


def test_crbug_40062121_present():
    corpus = load_yaml("browsers/chromium_unpatched.yaml")
    ids = {e.get("short_id") for e in corpus["issues"]}
    assert "40062121" in ids


# ---- detector drives off corpus ---- #


def test_unpatched_bug_finding_fires_when_sw_present(tmp_path):
    store = _store(tmp_path)
    _sw_art(store, "Default", ["https://example.com"])
    findings = list(BrowserDetector().detect(store))
    unpatched = [f for f in findings
                 if f.evidence.get("kind") == "unpatched_chromium_bug"]
    assert unpatched, [f.title for f in findings]
    assert unpatched[0].evidence["short_id"] == "40062121"
    # Workaround surfaced
    assert any("serviceworker-internals" in w
               for w in unpatched[0].evidence.get("workaround") or [])
    store.close()


def test_unpatched_bug_finding_skipped_when_no_sw(tmp_path):
    """Without SW artifacts, the bug doesn't apply on this profile."""
    store = _store(tmp_path)
    # No SW artifact added
    findings = list(BrowserDetector().detect(store))
    unpatched = [f for f in findings
                 if f.evidence.get("kind") == "unpatched_chromium_bug"]
    assert unpatched == []
    store.close()


def test_finding_carries_upstream_tracker_url(tmp_path):
    store = _store(tmp_path)
    _sw_art(store, "Default", ["https://gmail.com"])
    findings = list(BrowserDetector().detect(store))
    u = next(f for f in findings
             if f.evidence.get("kind") == "unpatched_chromium_bug")
    assert "issues.chromium.org" in u.evidence["url"]
    assert "40062121" in u.evidence["url"]
    store.close()


# ---- corpus extensibility: synthetic new entry fires without code change ----


def test_new_corpus_entry_fires_without_code_changes(tmp_path, monkeypatch):
    """Add a synthetic entry to the corpus at runtime and prove it fires."""
    import digger.detectors._rules_io as rio
    original = rio.load_yaml

    def patched(rel: str):
        if rel == "browsers/chromium_unpatched.yaml":
            return {
                "issues": [{
                    "id": "crbug-9999999",
                    "short_id": "9999999",
                    "title": "Synthetic test bug",
                    "url": "https://issues.chromium.org/issues/9999999",
                    "vendor_status": "private",
                    "affected_versions": "all",
                    "impact": "critical",
                    "detection_signal": {"kind": "service_worker_presence",
                                          "threshold": "any"},
                    "workaround": ["test workaround"],
                    "references": ["https://example.com"],
                }],
            }
        return original(rel)

    monkeypatch.setattr(
        "digger.detectors.browser.load_yaml", patched)

    store = _store(tmp_path)
    _sw_art(store, "Default", ["https://example.com"])
    findings = list(BrowserDetector().detect(store))
    syn = [f for f in findings
           if f.evidence.get("short_id") == "9999999"]
    assert syn, [f.title for f in findings]
    assert syn[0].severity == "critical"
    assert "Synthetic test bug" in syn[0].title
    store.close()


def test_integer_threshold_supported(tmp_path, monkeypatch):
    """detection_signal.threshold can be an integer; entry only fires
    when origin_count >= threshold."""
    import digger.detectors._rules_io as rio
    original = rio.load_yaml

    def patched(rel: str):
        if rel == "browsers/chromium_unpatched.yaml":
            return {"issues": [{
                "id": "test-int", "short_id": "int", "title": "int-thresh",
                "url": "x", "vendor_status": "private",
                "affected_versions": "all", "impact": "low",
                "detection_signal": {"kind": "service_worker_presence",
                                      "threshold": 5},
                "workaround": [], "references": [],
            }]}
        return original(rel)

    monkeypatch.setattr("digger.detectors.browser.load_yaml", patched)

    # 3 origins — below threshold of 5
    store = _store(tmp_path)
    _sw_art(store, "Default",
            ["https://a.example", "https://b.example", "https://c.example"])
    findings = list(BrowserDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("short_id") == "int"] == []
    store.close()

    # 6 origins — above threshold of 5
    store2 = _store(tmp_path / "v2")
    _sw_art(store2, "Default",
            [f"https://s{i}.example" for i in range(6)])
    findings2 = list(BrowserDetector().detect(store2))
    fired = [f for f in findings2
             if f.evidence.get("short_id") == "int"]
    assert fired
    store2.close()
