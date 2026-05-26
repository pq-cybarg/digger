"""LateralMovementDetector — outbound-to-internal, credential dumpers,
Impacket toolkit, ProxyJump, pass-the-hash."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.lateral import LateralMovementDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, exe=None, cmdline=None, connections=None,
          username="user"):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    store.add_artifact(Artifact(
        collector="processes",
        category="process",
        subject=f"pid={pid} {name}",
        data={
            "pid": pid, "ppid": 1, "name": name,
            "exe": exe or f"/usr/bin/{name}",
            "cmdline": cm,
            "username": username,
            "connections": connections or [],
        },
    ))


def _evt(store, raw):
    store.add_artifact(Artifact(
        collector="windows.event_logs",
        category="logs",
        subject="security",
        data={"raw": raw},
    ))


# ---- L1 lateral outbound ---- #


def test_outbound_smb_to_rfc1918_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "python3.11", exe="/usr/bin/python3",
          connections=[{"raddr": ["10.0.0.50", 445], "status": "ESTABLISHED"}])
    findings = list(LateralMovementDetector().detect(store))
    smb = [f for f in findings if "smb" in f.title]
    assert smb, [f.title for f in findings]
    assert smb[0].severity == "high"
    assert smb[0].mitre == "T1021.002"
    store.close()


def test_outbound_to_internet_not_flagged(tmp_path):
    """8.8.8.8 is not RFC1918 — should not flag."""
    store = _store(tmp_path)
    _proc(store, 100, "python3.11", exe="/usr/bin/python3",
          connections=[{"raddr": ["8.8.8.8", 22], "status": "ESTABLISHED"}])
    findings = list(LateralMovementDetector().detect(store))
    assert [f for f in findings if "lateral" in f.title.lower()] == []
    store.close()


def test_outbound_winrm_to_rfc1918_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 200, "pwsh", exe="C:\\Program Files\\PowerShell\\pwsh.exe",
          connections=[{"raddr": ["172.16.5.10", 5985], "status": "ESTABLISHED"}])
    findings = list(LateralMovementDetector().detect(store))
    wr = [f for f in findings if "winrm" in f.title]
    assert wr
    assert wr[0].mitre == "T1021.006"
    store.close()


def test_admin_tool_ssh_not_flagged(tmp_path):
    """ssh from /usr/bin/ssh is excluded — admin baseline."""
    store = _store(tmp_path)
    _proc(store, 100, "ssh", exe="/usr/bin/ssh",
          connections=[{"raddr": ["192.168.1.10", 22], "status": "ESTABLISHED"}])
    findings = list(LateralMovementDetector().detect(store))
    assert [f for f in findings if "Lateral" in f.title] == []
    store.close()


# ---- L2 credential dumpers ---- #


def test_mimikatz_in_cmdline_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "pwsh", cmdline=["pwsh", "-c",
                                         "Invoke-Mimikatz -DumpCreds"])
    findings = list(LateralMovementDetector().detect(store))
    mk = [f for f in findings if "mimikatz" in f.title.lower()]
    assert mk, [f.title for f in findings]
    assert mk[0].severity == "critical"
    assert mk[0].mitre == "T1003"
    store.close()


def test_secretsdump_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "python3", exe="/opt/impacket/secretsdump.py",
          cmdline=["secretsdump.py", "domain/user:pass@10.0.0.1"])
    findings = list(LateralMovementDetector().detect(store))
    sd = [f for f in findings if "secretsdump" in f.title.lower() or
          "credential-dumping" in f.title.lower()]
    assert sd
    store.close()


# ---- L3 Impacket / lateral toolkits ---- #


def test_evil_winrm_process_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "evil-winrm", exe="/usr/local/bin/evil-winrm",
          cmdline=["evil-winrm", "-i", "10.0.0.5"])
    findings = list(LateralMovementDetector().detect(store))
    ew = [f for f in findings if "evil-winrm" in f.title]
    assert ew
    assert ew[0].mitre == "T1570"
    store.close()


def test_responder_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "responder", exe="/usr/local/bin/responder")
    findings = list(LateralMovementDetector().detect(store))
    rp = [f for f in findings if "responder" in f.title.lower()]
    assert rp
    store.close()


# ---- L4 SSH ProxyJump ---- #


def test_ssh_proxyjump_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "ssh",
          cmdline=["ssh", "-J", "bastion@10.0.0.1,bastion2@10.0.0.2",
                   "target@10.1.1.1"])
    findings = list(LateralMovementDetector().detect(store))
    pj = [f for f in findings if "ProxyJump" in f.title]
    assert pj
    assert pj[0].mitre == "T1021.004"
    store.close()


# ---- L5 pass-the-hash ---- #


def test_pth_event_4624_flagged(tmp_path):
    store = _store(tmp_path)
    evt = (
        "2026-05-22 An account was successfully logged on. EventID: 4624 "
        "SubjectUserName: SYSTEM LogonType: 3 AuthenticationPackageName: NTLM "
        "WorkstationName: - LmPackageName: NTLM V2"
    )
    _evt(store, evt)
    findings = list(LateralMovementDetector().detect(store))
    pth = [f for f in findings if "pass-the-hash" in f.title.lower()]
    assert pth, [f.title for f in findings]
    assert pth[0].severity == "critical"
    assert pth[0].mitre == "T1550.002"
    store.close()


# ---- Sigma generation ---- #


def test_lateral_sigma_for_smb(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "python3.11", exe="/usr/bin/python3",
          connections=[{"raddr": ["10.0.0.50", 445], "status": "ESTABLISHED"}])
    f = next(LateralMovementDetector().detect(store))
    fdict = {
        "detector": f.detector, "title": f.title, "summary": f.summary,
        "severity": f.severity, "evidence": f.evidence,
        "finding_uuid": "lm-1",
    }
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert rule["logsource"]["category"] == "network_connection"
    assert "attack.lateral_movement" in rule["tags"]
    store.close()


def test_lateral_sigma_for_pth(tmp_path):
    store = _store(tmp_path)
    evt = (
        "EventID: 4624 LogonType: 3 AuthenticationPackageName: NTLM "
        "WorkstationName: ANONYMOUS"
    )
    _evt(store, evt)
    f = next(LateralMovementDetector().detect(store))
    fdict = {
        "detector": f.detector, "title": f.title, "summary": f.summary,
        "severity": f.severity, "evidence": f.evidence,
        "finding_uuid": "lm-2",
    }
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert rule["logsource"]["service"] == "security"
    assert "attack.t1550.002" in rule["tags"]
    store.close()


# ---- L6 taint shared content (T1080) ---- #


def _recent_file(store, path, *, size=1024):
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject=f"recent:{path}",
        data={"location": "/tmp", "entries": [
            {"path": path, "size": size},
        ]},
    ))


@pytest.mark.parametrize("path", [
    "/Volumes/SharedDrive/installer.exe",
    "/mnt/team-share/launcher.bat",
    "/media/nfs-home/.bashrc",
    "/net/share/Start Menu/Programs/Startup/run.ps1",
    "\\\\fileserver\\share\\Users\\Default\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\login.bat",
])
def test_l6_taint_shared_content_flagged(tmp_path, path):
    store = _store(tmp_path)
    _recent_file(store, path)
    findings = list(LateralMovementDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "taint_shared_content"]
    assert hits, [f.title for f in findings]
    assert hits[0].mitre == "T1080"
    assert hits[0].severity == "high"
    store.close()


def test_l6_user_local_executable_not_flagged(tmp_path):
    """Non-shared path → no taint finding (this is just routine
    desktop activity)."""
    store = _store(tmp_path)
    _recent_file(store, "/Users/alice/Downloads/installer.exe")
    findings = list(LateralMovementDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "taint_shared_content"] == []
    store.close()


def test_l6_shared_path_but_not_exec_not_flagged(tmp_path):
    """File on shared mount but not exec/script/startup → no finding
    (a Word doc on a shared drive is not lateral movement)."""
    store = _store(tmp_path)
    _recent_file(store, "/Volumes/SharedDrive/notes.docx")
    findings = list(LateralMovementDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "taint_shared_content"] == []
    store.close()


# ---- L7 SSH ControlMaster hijack (T1563.001) ---- #


def test_l7_ssh_controlmaster_hijack_critical(tmp_path):
    """alice attaching to a ControlMaster socket NOT under her own
    home — classic ride-an-existing-authenticated-session pattern."""
    store = _store(tmp_path)
    _proc(store, 100, "ssh",
          cmdline=["ssh", "-S", "/tmp/bob-master-22", "user@victim"],
          username="alice")
    findings = list(LateralMovementDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "ssh_hijack"]
    assert hits, [f.title for f in findings]
    assert hits[0].mitre == "T1563.001"
    assert hits[0].severity == "critical"
    assert "/tmp/bob-master-22" in hits[0].evidence.get("control_socket", "")
    store.close()


def test_l7_ssh_controlmaster_own_socket_not_flagged(tmp_path):
    """alice attaching to her OWN ControlMaster socket is normal."""
    store = _store(tmp_path)
    _proc(store, 100, "ssh",
          cmdline=["ssh", "-S", "/Users/alice/.ssh/master-22", "user@bastion"],
          username="alice")
    findings = list(LateralMovementDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "ssh_hijack"] == []
    store.close()


def test_l7_ssh_with_no_socket_arg_not_flagged(tmp_path):
    """Plain `ssh user@host` shouldn't fire SSH hijacking."""
    store = _store(tmp_path)
    _proc(store, 100, "ssh", cmdline=["ssh", "user@bastion"],
          username="alice")
    findings = list(LateralMovementDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "ssh_hijack"] == []
    store.close()


def test_l7_ssh_controlmaster_controlpath_form(tmp_path):
    """`ControlPath=...` form also flagged."""
    store = _store(tmp_path)
    _proc(store, 100, "ssh",
          cmdline=["ssh", "-o",
                   "ControlPath=/tmp/admin-cm", "user@victim"],
          username="alice")
    findings = list(LateralMovementDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "ssh_hijack"]
    assert hits
    store.close()


# ---- L8 RDP hijacking via tscon (T1563.002) ---- #


def test_l8_tscon_with_dest_flag_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "tscon.exe",
          exe="C:\\Windows\\System32\\tscon.exe",
          cmdline=["tscon.exe", "2", "/dest:rdp-tcp#3"],
          username="SYSTEM")
    findings = list(LateralMovementDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "rdp_hijack"]
    assert hits, [f.title for f in findings]
    assert hits[0].mitre == "T1563.002"
    assert hits[0].severity == "critical"
    store.close()


def test_l8_tscon_no_dest_not_flagged(tmp_path):
    """Plain `tscon /v` or interactive use without /dest: doesn't
    fire — that's session-listing not hijacking."""
    store = _store(tmp_path)
    _proc(store, 100, "tscon.exe",
          exe="C:\\Windows\\System32\\tscon.exe",
          cmdline=["tscon.exe", "/?"],
          username="SYSTEM")
    findings = list(LateralMovementDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "rdp_hijack"] == []
    store.close()


# ---- coverage check ---- #


def test_lateral_tactic_expanded_to_at_least_6():
    """The heatmap should now show ≥6 lateral-movement techniques
    (was 3 before this extension)."""
    from digger.genrule.heatmap import build_coverage
    cov = build_coverage()
    lateral_tids = cov["tactics"]["lateral-movement"]["technique_ids"]
    assert len(lateral_tids) >= 6
    assert "T1080" in lateral_tids
    assert "T1563.001" in lateral_tids
    assert "T1563.002" in lateral_tids
