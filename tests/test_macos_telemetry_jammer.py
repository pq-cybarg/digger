"""MacOSTelemetryJammerDetector — owner-sovereignty Apple-telemetry disabler."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.macos_telemetry_jammer import MacOSTelemetryJammerDetector


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


# ---- M1 launchd labels ------------------------------------------------ #


@pytest.mark.parametrize("label", [
    "com.apple.appleseed.fbahelperd",
    "com.apple.osanalytics.osanalyticshelper",
    "com.apple.SiriAnalytics.siri-analyticsd",
    "com.apple.symptomsd-diag",
    "com.apple.suggestd",
    "com.apple.coreduetd",
    "com.apple.searchpartyd",
    "com.apple.parsecd",
    "com.apple.bird",
])
def test_apple_telemetry_launchd_flagged(tmp_path, label):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="macos.launchd", category="persistence",
        subject=f"launchd:{label}",
        data={"label": label,
              "path": f"/System/Library/LaunchDaemons/{label}.plist",
              "program": f"/usr/libexec/{label.split('.')[-1]}",
              "run_at_load": True},
    ))
    findings = list(MacOSTelemetryJammerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "apple_telemetry_launchd"
            and f.evidence.get("label") == label]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "low"
    mit = hits[0].evidence.get("remediation_commands") or ""
    assert "launchctl disable" in mit
    assert "launchctl bootout" in mit
    assert label in mit
    assert hits[0].evidence.get("reversible") is True
    store.close()


def test_unrelated_launchd_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="macos.launchd", category="persistence",
        subject="launchd:org.mycompany.daemon",
        data={"label": "org.mycompany.daemon",
              "path": "/Library/LaunchDaemons/org.mycompany.daemon.plist"},
    ))
    findings = list(MacOSTelemetryJammerDetector().detect(store))
    assert not [f for f in findings
                if f.evidence.get("kind") == "apple_telemetry_launchd"]
    store.close()


# ---- M2 telemetry processes ------------------------------------------ #


@pytest.mark.parametrize("name,exe_path", [
    ("osanalyticshelper",
     "/System/Library/PrivateFrameworks/OSAnalytics.framework/Resources/osanalyticshelper"),
    ("photoanalysisd",
     "/System/Library/PrivateFrameworks/PhotoAnalysis.framework/photoanalysisd"),
    ("knowledge-agent",
     "/System/Library/PrivateFrameworks/CoreDuet.framework/knowledge-agent"),
    ("cloudd", "/System/Library/PrivateFrameworks/CloudKitDaemon.framework/cloudd"),
    ("bird", "/System/Library/PrivateFrameworks/CloudDocs.framework/bird"),
])
def test_apple_telemetry_process_flagged(tmp_path, name, exe_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid=900 {name}",
        data={"pid": 900, "ppid": 1, "name": name, "exe": exe_path,
              "cmdline": [exe_path], "username": "user",
              "connections": [], "open_files": []},
    ))
    findings = list(MacOSTelemetryJammerDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "apple_telemetry_process"]
    assert hits, [f.title for f in findings]
    assert hits[0].evidence.get("component") == name
    assert hits[0].severity == "info"
    store.close()


def test_unrelated_process_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=901 finder",
        data={"pid": 901, "ppid": 1, "name": "Finder",
              "exe": "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
              "cmdline": ["Finder"], "username": "user",
              "connections": [], "open_files": []},
    ))
    findings = list(MacOSTelemetryJammerDetector().detect(store))
    assert not [f for f in findings
                if f.evidence.get("kind") == "apple_telemetry_process"]
    store.close()


# ---- M3 diagnostic AutoSubmit ---------------------------------------- #


def test_autosubmit_true_emits_diag_finding(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="macos.profiles", category="config",
        subject="profile:DiagnosticMessagesHistory",
        data={"AutoSubmit": True, "AutoSubmitVersion": 4,
              "ThirdPartyDataSubmit": True},
    ))
    findings = list(MacOSTelemetryJammerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "apple_diag_autosubmit"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "low"
    mit = hits[0].evidence.get("remediation_commands") or ""
    assert "AutoSubmit" in mit
    assert "Siri Data Sharing" in mit
    store.close()


def test_autosubmit_false_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="macos.profiles", category="config",
        subject="profile:DiagnosticMessagesHistory",
        data={"AutoSubmit": False, "AutoSubmitVersion": 4},
    ))
    findings = list(MacOSTelemetryJammerDetector().detect(store))
    assert not [f for f in findings
                if f.evidence.get("kind") == "apple_diag_autosubmit"]
    store.close()


# ---- M4 Apple-telemetry DNS resolution ------------------------------- #


@pytest.mark.parametrize("host", [
    "gs-loc.apple.com", "metrics.icloud.com",
    "configuration.apple.com", "guzzoni.apple.com",
    "smoot.apple.com",
])
def test_apple_telemetry_dns_flagged(tmp_path, host):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="dns", category="network",
        subject="dns:cache",
        data={"host": host, "entries": []},
    ))
    findings = list(MacOSTelemetryJammerDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "apple_telemetry_dns"
            and f.evidence.get("host") == host]
    assert hits, [f.title for f in findings]
    mit = hits[0].evidence.get("remediation_commands") or ""
    assert "/etc/hosts" in mit
    assert host in mit
    store.close()


# ---- M5 TCC AppleSeed grants ----------------------------------------- #


def test_tcc_appleseed_grant_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="macos.tcc", category="privacy",
        subject="tcc:user",
        data={"entries": [
            {"service": "kTCCServiceMicrophone",
             "client": "com.apple.appleseed.FeedbackAssistant",
             "auth_value": 2},
        ]},
    ))
    findings = list(MacOSTelemetryJammerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "tcc_appleseed_grant"]
    assert hits
    mit = hits[0].evidence.get("remediation_commands") or ""
    assert "tccutil reset" in mit
    assert "FeedbackAssistant" in mit
    store.close()


# ---- Spotlight Suggestions advisory always emits ---------------------- #


def test_spotlight_suggestions_advisory_emitted(tmp_path):
    store = _store(tmp_path)
    # Need at least one launchd artifact to trigger the advisory
    store.add_artifact(Artifact(
        collector="macos.launchd", category="persistence",
        subject="launchd:placeholder",
        data={"label": "org.placeholder", "path": "/tmp/x.plist"},
    ))
    findings = list(MacOSTelemetryJammerDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "spotlight_suggestions_advisory"]
    assert hits
    mit = hits[0].evidence.get("remediation_commands") or ""
    assert "LookupSuggestionsDisabled" in mit
    assert "killall -HUP suggestd" in mit
    store.close()


# ---- Sigma + registration ------------------------------------------- #


def test_sigma_template_present():
    tpl = MacOSTelemetryJammerDetector().to_sigma_template()
    assert tpl is not None
    assert tpl["logsource"]["product"] == "macos"
    assert "selection_apple_telemetry_proc" in tpl["detection"]


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "macos_telemetry_jammer" in [d.name for d in all_detectors()]
