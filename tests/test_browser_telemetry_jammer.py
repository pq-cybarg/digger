"""BrowserTelemetryJammerDetector — cross-platform browser sovereignty."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.browser_telemetry_jammer import (
    BrowserTelemetryJammerDetector,
)


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, exe):
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}",
        data={"pid": pid, "ppid": 1, "name": name, "exe": exe,
              "cmdline": [exe], "username": "user",
              "connections": [], "open_files": []},
    ))


# ---- B1 browser process detection + per-browser remediation ---- #


@pytest.mark.parametrize("name,exe,browser_key,wantsin", [
    ("chrome", "/usr/bin/google-chrome", "chrome", "MetricsReportingEnabled"),
    ("chromium", "/usr/bin/chromium", "chromium", "MetricsReportingEnabled"),
    ("msedge", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
     "msedge", "PersonalizationReportingEnabled"),
    ("brave", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
     "brave", "p3a"),
    ("firefox", "/usr/lib/firefox/firefox", "firefox", "toolkit.telemetry.enabled"),
    ("opera", "/usr/lib/opera/opera", "opera", "opera://settings"),
    ("vivaldi", "/usr/bin/vivaldi", "vivaldi", "vivaldi://settings"),
    ("librewolf", "/usr/bin/librewolf", "librewolf", "toolkit.telemetry.enabled"),
])
def test_browser_process_emits_per_browser_remediation(
    tmp_path, name, exe, browser_key, wantsin,
):
    store = _store(tmp_path)
    _proc(store, 100, name, exe)
    findings = list(BrowserTelemetryJammerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "browser_process"
            and f.evidence.get("browser") == browser_key]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "info"
    mit = hits[0].evidence.get("remediation_commands") or ""
    assert wantsin in mit
    store.close()


def test_non_browser_process_not_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 200, "nginx", "/usr/sbin/nginx")
    findings = list(BrowserTelemetryJammerDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "browser_process"]
    store.close()


def test_chrome_runs_only_once_per_case(tmp_path):
    """If three chrome PIDs are visible (parent + render + utility), we
    still emit one process-level finding for chrome."""
    store = _store(tmp_path)
    _proc(store, 300, "chrome", "/usr/bin/google-chrome")
    _proc(store, 301, "chrome", "/usr/bin/google-chrome --type=renderer")
    _proc(store, 302, "chrome", "/usr/bin/google-chrome --type=utility")
    findings = [f for f in BrowserTelemetryJammerDetector().detect(store)
                if f.evidence.get("kind") == "browser_process"]
    assert len(findings) == 1
    store.close()


# ---- B2 telemetry hosts in DNS ---- #


@pytest.mark.parametrize("host", [
    "clients4.google.com", "edge.microsoft.com",
    "p3a.brave.com", "incoming.telemetry.mozilla.org",
    "sync.opera.com", "update.vivaldi.com",
])
def test_browser_telemetry_dns_flagged(tmp_path, host):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="dns", category="network",
        subject="dns:cache",
        data={"host": host, "entries": []},
    ))
    findings = [f for f in BrowserTelemetryJammerDetector().detect(store)
                if f.evidence.get("kind") == "browser_telemetry_dns"]
    assert findings, host
    assert findings[0].evidence.get("host") == host
    mit = findings[0].evidence.get("remediation_commands") or ""
    assert host in mit
    store.close()


# ---- B3 browser profile artifact ---- #


def test_browser_profile_artifact_emits_finding(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="browsers", category="browser",
        subject="browser:Chrome:default-profile",
        data={"browser": "Chrome", "profile": "default"},
    ))
    findings = [f for f in BrowserTelemetryJammerDetector().detect(store)
                if f.evidence.get("kind") == "browser_profile"]
    assert findings, [f.title for f in findings]
    assert findings[0].evidence.get("browser") == "chrome"
    store.close()


# ---- per-OS Chrome remediation has all three blocks --------------- #


def test_chrome_remediation_lacks_per_os_chunks(tmp_path):
    """Chrome remediation deliberately ships a single concatenated
    cross-OS block so the user picks the relevant section."""
    store = _store(tmp_path)
    _proc(store, 500, "chrome", "/usr/bin/google-chrome")
    f = next(iter(BrowserTelemetryJammerDetector().detect(store)))
    mit = f.evidence.get("remediation_commands") or ""
    # All three platform blocks should be concatenated
    assert "LINUX" in mit
    assert "MACOS" in mit
    assert "WINDOWS" in mit
    store.close()


# ---- Sigma + registration ---- #


def test_sigma_template_present():
    tpl = BrowserTelemetryJammerDetector().to_sigma_template()
    assert tpl is not None
    assert "selection_browser_proc" in tpl["detection"]
    images = tpl["detection"]["selection_browser_proc"]["Image|endswith"]
    assert "/chrome" in images
    assert "/firefox" in images
    assert "/brave" in images


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "browser_telemetry_jammer" in [d.name for d in all_detectors()]
