"""WarbirdBlockerDetector — owner-sovereignty Warbird-component disabler."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.warbird_blocker import WarbirdBlockerDetector


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


# ---- W1 sppsvc process ----------------------------------------------- #


def test_sppsvc_process_flagged_with_activation_warning(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=900 sppsvc",
        data={"pid": 900, "ppid": 1, "name": "sppsvc.exe",
              "exe": "C:\\Windows\\System32\\sppsvc.exe",
              "cmdline": ["sppsvc.exe"], "username": "NT SERVICE",
              "connections": [], "open_files": []},
    ))
    findings = list(WarbirdBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "warbird_process"
            and f.evidence.get("component") == "sppsvc.exe"]
    assert hits, [f.title for f in findings]
    # Warning text must mention Activation breakage
    assert "Activation" in hits[0].evidence.get("warning", "")
    # Remediation must include the Stop-Service + Set-Service combo
    mit = hits[0].evidence.get("remediation_commands") or ""
    assert "Stop-Service" in mit
    assert "sppsvc" in mit
    assert "StartupType Disabled" in mit
    assert hits[0].evidence.get("reversible") is True
    store.close()


def test_unrelated_process_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=901 notepad",
        data={"pid": 901, "ppid": 1, "name": "notepad.exe",
              "exe": "C:\\Windows\\System32\\notepad.exe",
              "cmdline": ["notepad.exe"], "username": "user",
              "connections": [], "open_files": []},
    ))
    findings = list(WarbirdBlockerDetector().detect(store))
    assert not findings
    store.close()


# ---- W2 Warbird services -------------------------------------------- #


def test_sppsvc_service_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="services", category="persistence",
        subject="svc:sppsvc",
        data={"Name": "sppsvc", "StartType": "Automatic",
              "Status": "Running"},
    ))
    findings = list(WarbirdBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "warbird_service"
            and f.evidence.get("component") == "sppsvc"]
    assert hits
    assert "Activation" in hits[0].evidence.get("warning", "")
    store.close()


def test_clipsvc_service_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="services", category="persistence",
        subject="svc:ClipSVC",
        data={"Name": "ClipSVC", "StartType": "Manual"},
    ))
    findings = list(WarbirdBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "warbird_service"
            and f.evidence.get("component") == "ClipSVC"]
    assert hits
    assert "Microsoft Store" in hits[0].evidence.get("warning", "")
    store.close()


def test_wdnissvc_flagged_with_edr_warning(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="services", category="persistence",
        subject="svc:WdNisSvc",
        data={"Name": "WdNisSvc", "StartType": "Automatic"},
    ))
    findings = list(WarbirdBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "warbird_service"
            and f.evidence.get("component") == "WdNisSvc"]
    assert hits
    assert "EDR" in hits[0].evidence.get("warning", "")
    store.close()


def test_disabled_warbird_service_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="services", category="persistence",
        subject="svc:sppsvc",
        data={"Name": "sppsvc", "StartType": "Disabled"},
    ))
    findings = list(WarbirdBlockerDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "warbird_service"]
    store.close()


# ---- W3/W4/W5 Warbird drivers / DLLs in process ---------------------- #


def test_clipsp_driver_in_process_modules_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=1000 mfpmp",
        data={"pid": 1000, "ppid": 1, "name": "mfpmp.exe",
              "exe": "C:\\Windows\\System32\\mfpmp.exe",
              "cmdline": ["mfpmp.exe"], "username": "user",
              "connections": [], "open_files": [],
              "modules": [{"path": "C:\\Windows\\System32\\drivers\\ClipSp.sys"}]},
    ))
    findings = list(WarbirdBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "warbird_driver"
            and f.evidence.get("component") == "ClipSp.sys"]
    assert hits, [f.title for f in findings]
    assert "DRM" in hits[0].evidence.get("warning", "")
    assert "sc.exe config ClipSp" in (hits[0].evidence.get("remediation_commands") or "")
    store.close()


def test_ngc_dll_in_loaded_modules_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=1001 lsass",
        data={"pid": 1001, "ppid": 1, "name": "lsass.exe",
              "exe": "C:\\Windows\\System32\\lsass.exe",
              "cmdline": ["lsass.exe"], "username": "SYSTEM",
              "connections": [], "open_files": [],
              "modules": [{"path": "C:\\Windows\\System32\\ngc.dll"}]},
    ))
    findings = list(WarbirdBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "warbird_driver"
            and f.evidence.get("component") == "ngc.dll"]
    assert hits
    assert "Hello" in hits[0].evidence.get("warning", "")
    assert "PassportForWork" in (hits[0].evidence.get("remediation_commands") or "")
    store.close()


def test_ksecdd_is_info_severity_and_no_remediation(tmp_path):
    """ksecdd.sys is essential for boot — surface as info-only, no
    remediation command."""
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=1002 svchost",
        data={"pid": 1002, "ppid": 1, "name": "svchost.exe",
              "exe": "C:\\Windows\\System32\\svchost.exe",
              "cmdline": ["svchost.exe"], "username": "SYSTEM",
              "connections": [], "open_files": [],
              "modules": [{"path": "C:\\Windows\\System32\\drivers\\ksecdd.sys"}]},
    ))
    findings = list(WarbirdBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "warbird_driver"
            and f.evidence.get("component") == "ksecdd.sys"]
    assert hits
    assert hits[0].severity == "info"
    # Critical safety: no remediation command shipped for ksecdd
    assert (hits[0].evidence.get("remediation_commands") or "").strip() == ""
    assert hits[0].evidence.get("essential_for_boot") is True
    assert hits[0].evidence.get("reversible") is False
    store.close()


# ---- Sigma template / registry --------------------------------------- #


def test_sigma_template_present():
    tpl = WarbirdBlockerDetector().to_sigma_template()
    assert tpl is not None
    assert "selection_warbird_proc" in tpl["detection"]
    # sppsvc.exe is a Warbird-protected component — must be in the
    # selection list
    assert "sppsvc.exe" in tpl["detection"]["selection_warbird_proc"]["Image|endswith"]


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "warbird_blocker" in [d.name for d in all_detectors()]
