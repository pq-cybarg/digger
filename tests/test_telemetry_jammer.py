"""TelemetryJammerDetector — owner-sovereignty Windows-telemetry disabler."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.telemetry_jammer import TelemetryJammerDetector


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


# ---- T1/T2/T4 services ------------------------------------------------ #


@pytest.mark.parametrize("svc_name", [
    "DiagTrack", "dmwappushservice", "WerSvc", "PcaSvc",
])
def test_telemetry_service_active_emits_finding(tmp_path, svc_name):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="services", category="persistence",
        subject=f"svc:{svc_name}",
        data={"Name": svc_name, "StartType": "Automatic",
              "Status": "Running"},
    ))
    findings = list(TelemetryJammerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "telemetry_service"
            and f.evidence.get("service") == svc_name]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "low"
    mit = hits[0].evidence.get("remediation_commands") or ""
    assert "Stop-Service" in mit
    assert "Set-Service" in mit
    assert svc_name in mit
    assert hits[0].evidence.get("reversible") is True
    store.close()


def test_disabled_service_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="services", category="persistence",
        subject="svc:DiagTrack",
        data={"Name": "DiagTrack", "StartType": "Disabled",
              "Status": "Stopped"},
    ))
    findings = list(TelemetryJammerDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "telemetry_service"]
    store.close()


def test_unrelated_service_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="services", category="persistence",
        subject="svc:Spooler",
        data={"Name": "Spooler", "StartType": "Automatic"},
    ))
    findings = list(TelemetryJammerDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "telemetry_service"]
    store.close()


# ---- T3 telemetry processes ------------------------------------------ #


def test_compattelrunner_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=1234 CompatTelRunner",
        data={"pid": 1234, "ppid": 1, "name": "CompatTelRunner.exe",
              "exe": "C:\\Windows\\System32\\CompatTelRunner.exe",
              "cmdline": ["CompatTelRunner.exe", "-m:appraiser.dll"],
              "username": "SYSTEM", "connections": [], "open_files": []},
    ))
    findings = list(TelemetryJammerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "telemetry_process"]
    assert hits, [f.title for f in findings]
    assert "Compatibility" in hits[0].evidence.get("label", "")
    assert "Disable-ScheduledTask" in (hits[0].evidence.get("remediation_commands") or "")
    store.close()


def test_devicecensus_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=1235 DeviceCensus",
        data={"pid": 1235, "ppid": 1, "name": "DeviceCensus.exe",
              "exe": "C:\\Windows\\System32\\DeviceCensus.exe",
              "cmdline": ["DeviceCensus.exe"], "username": "SYSTEM",
              "connections": [], "open_files": []},
    ))
    findings = list(TelemetryJammerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "telemetry_process"]
    assert hits
    store.close()


# ---- T5 scheduled tasks ---------------------------------------------- #


def test_compatibility_appraiser_task_enabled(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="scheduled_tasks", category="persistence",
        subject="task:Compatibility Appraiser",
        data={"entries": [
            {"TaskPath": "\\Microsoft\\Windows\\Application Experience",
             "TaskName": "Microsoft Compatibility Appraiser",
             "State": "Ready"},
        ]},
    ))
    findings = list(TelemetryJammerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "telemetry_task"]
    assert hits, [f.title for f in findings]
    assert "Microsoft Compatibility Appraiser" in hits[0].evidence.get("task_name", "")
    assert "Disable-ScheduledTask" in (hits[0].evidence.get("remediation_commands") or "")
    store.close()


def test_disabled_task_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="scheduled_tasks", category="persistence",
        subject="task:Consolidator",
        data={"entries": [
            {"TaskPath": "\\Microsoft\\Windows\\Customer Experience Improvement Program",
             "TaskName": "Consolidator", "State": "Disabled"},
        ]},
    ))
    findings = list(TelemetryJammerDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "telemetry_task"]
    store.close()


# ---- T6 registry AllowTelemetry ------------------------------------- #


def test_allowtelemetry_above_zero_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="registry_persistence", category="persistence",
        subject="reg:AllowTelemetry",
        data={
            "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
            "name": "AllowTelemetry", "value": 3,
        },
    ))
    findings = list(TelemetryJammerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "telemetry_registry"]
    assert hits, [f.title for f in findings]
    assert hits[0].evidence.get("value") == 3
    mit = hits[0].evidence.get("remediation_commands") or ""
    assert "AllowTelemetry" in mit
    assert "DataCollection" in mit
    store.close()


def test_allowtelemetry_zero_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="registry_persistence", category="persistence",
        subject="reg:AllowTelemetry",
        data={
            "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
            "name": "AllowTelemetry", "value": 0,
        },
    ))
    findings = list(TelemetryJammerDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "telemetry_registry"]
    store.close()


# ---- T7 telemetry DNS history --------------------------------------- #


def test_telemetry_host_in_dns_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="dns", category="network",
        subject="dns:cache",
        data={"host": "vortex-win.data.microsoft.com", "entries": []},
    ))
    findings = list(TelemetryJammerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "telemetry_dns"]
    assert hits, [f.title for f in findings]
    assert "vortex-win.data.microsoft.com" == hits[0].evidence.get("host")
    mit = hits[0].evidence.get("remediation_commands") or ""
    assert "hosts" in mit  # hosts-file block command
    assert "0.0.0.0" in mit
    store.close()


# ---- Sigma template ------------------------------------------------- #


def test_sigma_template_present():
    tpl = TelemetryJammerDetector().to_sigma_template()
    assert tpl is not None
    assert "selection_telemetry_proc" in tpl["detection"]
    assert "selection_telemetry_service_host" in tpl["detection"]


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "telemetry_jammer" in [d.name for d in all_detectors()]
