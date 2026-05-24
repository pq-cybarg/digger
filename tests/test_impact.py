"""ImpactDetector — 12th Decepticon countermeasure.

Covers ransomware encrypt-shapes (I1), ransom-note filenames (I2),
shadow-copy / system-restore deletion (I3), security-service stop /
EDR-tamper (I4), disk wipe (I5), system shutdown (I6), cloud-resource
destruction (I7), and mass-extension change footprint (I8)."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.impact import ImpactDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, cmdline, exe=None, username="user"):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}",
        data={"pid": pid, "ppid": 1, "name": name,
              "exe": exe or f"/usr/bin/{name}",
              "cmdline": cm, "username": username,
              "connections": [], "open_files": []},
    ))


# ---- I1 ransomware encrypt shape -------------------------------------- #


def test_find_exec_openssl_enc_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 1, "bash",
          ["bash", "-c", "find /home -type f -exec openssl enc -aes-256-cbc -k pw {} \\;"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if "find" in (f.evidence.get("pattern") or "")
            and "openssl" in (f.evidence.get("pattern") or "")]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1486"
    store.close()


def test_gpg_batch_encrypt_recursive_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 2, "gpg",
          ["gpg", "--batch", "--passphrase", "x", "--encrypt", "--recursive", "/home"])
    findings = list(ImpactDetector().detect(store))
    assert any("gpg" in (f.evidence.get("pattern") or "")
               for f in findings if f.evidence.get("kind") == "impact_cmdline")
    store.close()


def test_7zip_password_recursive_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 3, "7za",
          ["7za", "a", "-pmysecret", "-mhe=on", "-r", "/tmp/out.7z", "/home/user"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if "7z" in (f.evidence.get("pattern") or "")]
    assert hits
    assert hits[0].severity == "high"
    store.close()


# ---- I2 ransom-note filenames ----------------------------------------- #


@pytest.mark.parametrize("name", [
    "HOW_TO_DECRYPT.txt", "READ_ME_FOR_DECRYPT.txt",
    "DECRYPT_INSTRUCTIONS.txt", "YOUR_FILES_ARE_ENCRYPTED.txt",
    "_readme.txt", "info.hta", "lockbit-decryptor.txt",
    "akira_readme.txt", "ryukreadme.txt",
])
def test_ransom_note_filename_critical(tmp_path, name):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home",
        data={"location": "/home",
              "entries": [{"path": f"/home/user/{name}", "size": 1024}]},
    ))
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "ransom_note_file"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1486"
    store.close()


def test_clean_filename_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home",
        data={"location": "/home",
              "entries": [{"path": "/home/user/README.md", "size": 1024}]},
    ))
    findings = list(ImpactDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "ransom_note_file"]
    store.close()


# ---- I3 inhibit system recovery --------------------------------------- #


@pytest.mark.parametrize("cmd,mitre", [
    (["vssadmin", "delete", "shadows", "/all", "/quiet"], "T1490"),
    (["wmic", "shadowcopy", "delete"], "T1490"),
    (["bcdedit", "/set", "{default}", "recoveryenabled", "No"], "T1490"),
    (["wbadmin", "delete", "catalog", "-quiet"], "T1490"),
])
def test_inhibit_recovery_critical(tmp_path, cmd, mitre):
    store = _store(tmp_path)
    _proc(store, 10, cmd[0], cmd)
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "impact_cmdline"]
    assert hits, [f.title for f in findings]
    assert hits[0].mitre == mitre
    assert hits[0].severity in ("critical", "high")
    store.close()


def test_bcdedit_bootstatuspolicy_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 11, "bcdedit.exe",
          ["bcdedit.exe", "/set", "{default}", "bootstatuspolicy",
           "ignoreallfailures"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if "bootstatuspolicy" in (f.evidence.get("pattern") or "")]
    assert hits
    assert hits[0].severity == "high"
    store.close()


# ---- I4 security-service stop / EDR tamper ---------------------------- #


def test_systemctl_stop_falcon_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 20, "systemctl",
          ["systemctl", "stop", "falcon-sensor"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "impact_cmdline"]
    assert hits
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1489"
    store.close()


def test_net_stop_windefend_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 21, "net.exe", ["net.exe", "stop", "WinDefend"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "impact_cmdline"]
    assert hits
    assert hits[0].severity == "critical"
    store.close()


def test_set_mppreference_disablertm_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 22, "powershell.exe",
          ["powershell.exe", "-c",
           "Set-MpPreference -DisableRealtimeMonitoring $true"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if "DisableRealtimeMonitoring" in (f.evidence.get("pattern") or "")]
    assert hits
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1562.001"
    store.close()


def test_add_mppreference_exclusion_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 23, "powershell.exe",
          ["powershell.exe", "-c",
           "Add-MpPreference -ExclusionPath 'C:\\Users\\Public'"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if "ExclusionPath" in (f.evidence.get("pattern") or "")]
    assert hits
    assert hits[0].severity == "high"
    store.close()


# ---- I5 disk wipe ----------------------------------------------------- #


def test_dd_zero_to_disk_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 30, "dd",
          ["dd", "if=/dev/zero", "of=/dev/sda", "bs=1M"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "impact_cmdline"]
    assert hits
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1561"
    store.close()


def test_shred_device_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 31, "shred", ["shred", "-vfz", "-n", "3", "/dev/nvme0n1"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "impact_cmdline"]
    assert hits
    assert hits[0].mitre == "T1561"
    store.close()


def test_wipefs_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 32, "wipefs", ["wipefs", "-af", "/dev/sda"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "impact_cmdline"]
    assert hits
    assert hits[0].mitre == "T1561"
    store.close()


def test_diskpart_clean_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 33, "diskpart.exe",
          ["diskpart.exe", "/s", "C:\\Windows\\Temp\\wipe.txt", "clean"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if "diskpart" in (f.evidence.get("pattern") or "")]
    assert hits
    store.close()


# ---- I6 shutdown / reboot --------------------------------------------- #


def test_shutdown_now_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 40, "bash", ["bash", "-c", "shutdown -h now"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "impact_cmdline"
            and "shutdown" in (f.evidence.get("pattern") or "")]
    assert hits
    assert hits[0].mitre == "T1529"
    store.close()


def test_powershell_stop_computer_force_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 41, "powershell.exe",
          ["powershell.exe", "-c", "Stop-Computer -Force"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if "Stop-Computer" in (f.evidence.get("pattern") or "")]
    assert hits
    assert hits[0].severity == "high"
    store.close()


# ---- I7 cloud resource destruction ------------------------------------ #


def test_aws_ec2_terminate_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 50, "aws",
          ["aws", "ec2", "terminate-instances", "--instance-ids", "i-123"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "impact_cmdline"]
    assert hits
    assert hits[0].severity == "high"
    assert hits[0].mitre == "T1485"
    store.close()


def test_aws_s3_rb_force_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 51, "aws",
          ["aws", "s3", "rb", "s3://my-bucket", "--force"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "impact_cmdline"]
    assert hits
    assert hits[0].severity == "critical"
    store.close()


def test_aws_rds_delete_skip_snapshot_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 52, "aws",
          ["aws", "rds", "delete-db-instance",
           "--db-instance-identifier", "prod",
           "--skip-final-snapshot"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "impact_cmdline"]
    assert hits
    assert hits[0].severity == "critical"
    store.close()


def test_aws_cloudtrail_disable_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 53, "aws",
          ["aws", "cloudtrail", "stop-logging", "--name", "main"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if "cloudtrail" in (f.evidence.get("pattern") or "").lower()]
    assert hits
    assert hits[0].mitre == "T1562.008"
    store.close()


def test_terraform_destroy_auto_approve_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 54, "terraform",
          ["terraform", "destroy", "-auto-approve"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if "terraform" in (f.evidence.get("pattern") or "").lower()]
    assert hits
    assert hits[0].severity == "high"
    store.close()


def test_kubectl_delete_all_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 55, "kubectl",
          ["kubectl", "delete", "--all", "deployments", "-n", "prod"])
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if "kubectl" in (f.evidence.get("pattern") or "").lower()]
    assert hits
    store.close()


# ---- I8 mass-extension rename footprint ------------------------------- #


def test_mass_rename_to_encrypted_extension_critical(tmp_path):
    store = _store(tmp_path)
    entries = [{"path": f"/home/user/docs/file_{i}.encrypted", "size": 100}
               for i in range(60)]
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home/user/docs",
        data={"location": "/home/user/docs", "entries": entries},
    ))
    findings = list(ImpactDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "mass_rename"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].evidence.get("extension") == ".encrypted"
    assert hits[0].evidence.get("count") >= 60
    store.close()


def test_below_threshold_not_flagged(tmp_path):
    """49 files with the suspect extension is below the 50-file threshold."""
    store = _store(tmp_path)
    entries = [{"path": f"/home/x_{i}.locked", "size": 100} for i in range(49)]
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home",
        data={"location": "/home", "entries": entries},
    ))
    findings = list(ImpactDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "mass_rename"]
    store.close()


# ---- Sigma ---- #


def test_sigma_for_vssadmin(tmp_path):
    store = _store(tmp_path)
    _proc(store, 60, "vssadmin.exe", ["vssadmin.exe", "delete", "shadows", "/all"])
    f = next(iter(ImpactDetector().detect(store)))
    rule = finding_to_sigma({
        "detector": f.detector, "title": f.title, "summary": f.summary,
        "severity": f.severity, "evidence": f.evidence,
        "finding_uuid": "imp-1", "mitre": f.mitre,
    }, case_id="t")
    assert rule is not None
    assert rule["logsource"]["category"] == "process_creation"
    assert "attack.impact" in rule["tags"]


def test_sigma_for_ransom_note_file(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home",
        data={"location": "/home",
              "entries": [{"path": "/home/user/HOW_TO_DECRYPT.txt", "size": 4096}]},
    ))
    f = next(iter(ImpactDetector().detect(store)))
    rule = finding_to_sigma({
        "detector": f.detector, "title": f.title, "summary": f.summary,
        "severity": f.severity, "evidence": f.evidence,
        "finding_uuid": "imp-2", "mitre": f.mitre,
    }, case_id="t")
    assert rule is not None
    assert rule["logsource"]["category"] == "file_event"
    assert "how_to_decrypt.txt" in str(rule["detection"]["selection"]["TargetFilename|endswith"])


def test_sigma_template_present():
    tpl = ImpactDetector().to_sigma_template()
    assert tpl is not None
    assert tpl["level"] == "critical"
    for tag in ("attack.t1485", "attack.t1486", "attack.t1489",
                "attack.t1490", "attack.t1529", "attack.t1561"):
        assert tag in tpl["tags"]
    sels = [k for k in tpl["detection"] if k.startswith("selection_")]
    assert len(sels) >= 6


# ---- Registry hookup -------------------------------------------------- #


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "impact" in [d.name for d in all_detectors()]
