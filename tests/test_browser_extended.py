"""Comprehensive browser scanner — cookies, IndexedDB, Local Storage,
PWAs, passwords-count, profile defaults, bad-host cross-reference."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.browser import BrowserDetector
from digger.intel import feeds as feeds_mod


def _point_intel_dir(monkeypatch, root):
    monkeypatch.setattr(feeds_mod, "intel_dir", lambda: root)
    monkeypatch.setenv("DIGGER_INTEL_NO_VERIFY", "1")
    from digger.detectors import _rules_io
    _rules_io._reset_intel_verdict_for_tests()


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _art(store, subj, data):
    store.add_artifact(Artifact(
        collector="browsers", category="browser",
        subject=subj, data=data,
    ))


# ---- Cookies ---- #


def test_cookie_high_domain_count_low_severity(tmp_path):
    store = _store(tmp_path)
    _art(store, "chrome.cookies:Chrome/Default", {
        "profile": "/p/Default",
        "domain_count": 600,
        "total_cookie_count": 2000,
        "total_value_bytes": 1_000_000,
        "domains": [{"host": f"d{i}.example", "count": 3,
                     "value_bytes": 50} for i in range(600)],
    })
    findings = list(BrowserDetector().detect(store))
    hi = [f for f in findings if "Cookie store holds" in f.title]
    assert hi
    assert hi[0].severity == "low"
    assert hi[0].mitre == "T1539"
    store.close()


def test_cookies_for_bad_host_flagged(tmp_path, monkeypatch):
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    _point_intel_dir(monkeypatch, intel_dir)
    (intel_dir / "urlhaus_recent.json").write_text(json.dumps({
        "entries": [{"url": "https://evil.example/payload"}],
    }))

    store = _store(tmp_path)
    _art(store, "chrome.cookies:Chrome/Default", {
        "profile": "/p/Default",
        "domain_count": 1,
        "total_cookie_count": 5,
        "total_value_bytes": 1000,
        "domains": [{"host": ".evil.example", "count": 5,
                     "value_bytes": 1000}],
    })
    findings = list(BrowserDetector().detect(store))
    bad = [f for f in findings if f.evidence.get("kind") == "cookies_for_bad_host"]
    assert bad, [f.title for f in findings]
    assert bad[0].severity == "high"
    store.close()


# ---- Saved passwords ---- #


def test_high_password_count_info(tmp_path):
    store = _store(tmp_path)
    _art(store, "chrome.passwords_summary:Chrome/Default", {
        "profile": "/p/Default",
        "saved_count": 250,
        "distinct_realm_count": 220,
    })
    findings = list(BrowserDetector().detect(store))
    f = [x for x in findings if x.evidence.get("kind") == "password_store_size"]
    assert f
    assert f[0].severity == "info"
    assert f[0].mitre == "T1555.003"
    store.close()


def test_small_password_count_no_finding(tmp_path):
    store = _store(tmp_path)
    _art(store, "chrome.passwords_summary:Chrome/Default", {
        "profile": "/p/Default", "saved_count": 12, "distinct_realm_count": 10,
    })
    findings = list(BrowserDetector().detect(store))
    assert [f for f in findings if "password" in f.title.lower()] == []
    store.close()


# ---- IndexedDB ---- #


def test_indexeddb_bloat_flagged(tmp_path):
    store = _store(tmp_path)
    _art(store, "chrome.indexeddb:Chrome/Default", {
        "profile": "/p/Default", "origin_count": 1,
        "total_bytes": 500 * 1024 * 1024,
        "origins": [{"origin": "https://heavy.example",
                     "bytes": 500 * 1024 * 1024}],
    })
    findings = list(BrowserDetector().detect(store))
    bl = [f for f in findings if f.evidence.get("kind") == "indexeddb_bloat"]
    assert bl
    assert bl[0].severity == "low"
    store.close()


def test_indexeddb_bad_origin_critical(tmp_path, monkeypatch):
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    _point_intel_dir(monkeypatch, intel_dir)
    (intel_dir / "threatfox_recent.json").write_text(json.dumps({
        "entries": [{"ioc": "evil.example", "ioc_type": "domain"}],
    }))

    store = _store(tmp_path)
    _art(store, "chrome.indexeddb:Chrome/Default", {
        "profile": "/p/Default", "origin_count": 1,
        "total_bytes": 1000,
        "origins": [{"origin": "https://evil.example", "bytes": 1000}],
    })
    findings = list(BrowserDetector().detect(store))
    bad = [f for f in findings if f.evidence.get("kind") == "indexeddb_bad_origin"]
    assert bad, [f.title for f in findings]
    assert bad[0].severity == "critical"
    store.close()


# ---- Local Storage ---- #


def test_local_storage_bad_origin_critical(tmp_path, monkeypatch):
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    _point_intel_dir(monkeypatch, intel_dir)
    (intel_dir / "urlhaus_recent.json").write_text(json.dumps({
        "entries": [{"url": "https://badsite.example/foo"}],
    }))

    store = _store(tmp_path)
    _art(store, "chrome.local_storage:Chrome/Default", {
        "profile": "/p/Default", "origin_count": 2, "total_bytes": 5000,
        "origins": ["https://google.com", "https://badsite.example"],
    })
    findings = list(BrowserDetector().detect(store))
    bad = [f for f in findings
           if f.evidence.get("kind") == "local_storage_bad_origin"]
    assert bad
    assert bad[0].severity == "critical"
    store.close()


# ---- Profile defaults: search hijack ---- #


def test_non_mainstream_search_engine_flagged(tmp_path):
    store = _store(tmp_path)
    _art(store, "chrome.profile_defaults:Chrome/Default", {
        "profile": "/p/Default",
        "default_search_engine": {
            "short_name": "WeirdSearch",
            "keyword": "weird",
            "url": "https://weirdsearch.invalid/q={searchTerms}",
        },
        "homepage": "https://example.com",
    })
    findings = list(BrowserDetector().detect(store))
    h = [f for f in findings if f.evidence.get("kind") == "default_search_hijack"]
    assert h
    assert h[0].severity == "medium"
    store.close()


def test_mainstream_search_engine_not_flagged(tmp_path):
    store = _store(tmp_path)
    _art(store, "chrome.profile_defaults:Chrome/Default", {
        "profile": "/p/Default",
        "default_search_engine": {
            "short_name": "Google", "keyword": "google",
            "url": "https://google.com/search?q={searchTerms}",
        },
    })
    findings = list(BrowserDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "default_search_hijack"] == []
    store.close()


def test_startup_url_bad_host_critical(tmp_path, monkeypatch):
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    _point_intel_dir(monkeypatch, intel_dir)
    (intel_dir / "urlhaus_recent.json").write_text(json.dumps({
        "entries": [{"url": "https://evilstart.example"}],
    }))

    store = _store(tmp_path)
    _art(store, "chrome.profile_defaults:Chrome/Default", {
        "profile": "/p/Default",
        "default_search_engine": {"url": "https://google.com/?q={searchTerms}"},
        "startup_urls": ["https://evilstart.example"],
    })
    findings = list(BrowserDetector().detect(store))
    s = [f for f in findings
         if f.evidence.get("kind") == "startup_url_bad_origin"]
    assert s
    assert s[0].severity == "critical"
    store.close()


# ---- PWAs ---- #


def test_pwa_inventory_emitted(tmp_path):
    store = _store(tmp_path)
    _art(store, "chrome.pwas:Chrome/Default", {
        "profile": "/p/Default", "count": 2,
        "entries": [
            {"id": "abc", "name": "My App", "start_url": "https://app.example"},
            {"id": "def", "name": "Other", "start_url": "https://other.example"},
        ],
    })
    findings = list(BrowserDetector().detect(store))
    inv = [f for f in findings if f.evidence.get("kind") == "pwa_inventory"]
    assert inv
    assert inv[0].severity == "info"
    store.close()


def test_pwa_start_url_bad_host_critical(tmp_path, monkeypatch):
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    _point_intel_dir(monkeypatch, intel_dir)
    (intel_dir / "urlhaus_recent.json").write_text(json.dumps({
        "entries": [{"url": "https://maliciouspwa.example/start"}],
    }))

    store = _store(tmp_path)
    _art(store, "chrome.pwas:Chrome/Default", {
        "profile": "/p/Default", "count": 1,
        "entries": [{"id": "x", "name": "Bad",
                     "start_url": "https://maliciouspwa.example"}],
    })
    findings = list(BrowserDetector().detect(store))
    bad = [f for f in findings if f.evidence.get("kind") == "pwa_bad_start_url"]
    assert bad
    assert bad[0].severity == "critical"
    store.close()


# ---- SW + bad-host cross-reference ---- #


def test_sw_origin_in_bad_feed_critical(tmp_path, monkeypatch):
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    _point_intel_dir(monkeypatch, intel_dir)
    (intel_dir / "threatfox_recent.json").write_text(json.dumps({
        "entries": [{"ioc": "swbad.example", "ioc_type": "domain"}],
    }))

    store = _store(tmp_path)
    _art(store, "chrome.service_workers:Chrome/Default", {
        "profile": "/p/Default",
        "origins": ["https://swbad.example"],
        "origin_count": 1, "script_count": 1, "storage_bytes": 1000,
    })
    findings = list(BrowserDetector().detect(store))
    bad = [f for f in findings
           if f.evidence.get("kind") == "service_worker_bad_origin"]
    assert bad
    assert bad[0].severity == "critical"
    store.close()
