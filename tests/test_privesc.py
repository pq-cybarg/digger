"""PrivescDetector — setuid, capabilities, sudoers, kernel-taint."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.privesc import PrivescDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _suid(store, path, *, world_writable=False, owner_uid=0,
          in_system_dir=True, mode="04755"):
    store.add_artifact(Artifact(
        collector="linux.privesc",
        category="privesc_surface",
        subject=f"suid:{path}",
        data={"path": path, "mode": mode, "is_setuid": True, "is_setgid": False,
              "world_writable": world_writable, "owner_uid": owner_uid,
              "owner_gid": 0, "size": 12345, "mtime": 0,
              "in_system_dir": in_system_dir},
    ))


def _sudoers(store, name, contents):
    store.add_artifact(Artifact(
        collector="linux.sudoers",
        category="identity",
        subject=name,
        data={"path": f"/etc/sudoers.d/{name}", "contents": contents},
    ))


def _getcap(store, raw):
    store.add_artifact(Artifact(
        collector="linux.privesc",
        category="privesc_surface",
        subject="getcap:/usr/bin",
        data={"root": "/usr/bin", "raw": raw},
    ))


def _taint(store, value):
    store.add_artifact(Artifact(
        collector="linux.privesc",
        category="privesc_surface",
        subject="kernel-tainted",
        data={"value": str(value)},
    ))


# ---- P1 world-writable + setuid ---- #


def test_world_writable_setuid_is_critical(tmp_path):
    store = _store(tmp_path)
    _suid(store, "/usr/bin/somebin", world_writable=True, mode="04777")
    findings = list(PrivescDetector().detect(store))
    crit = [f for f in findings if "World-writable" in f.title]
    assert crit, [f.title for f in findings]
    assert crit[0].severity == "critical"
    assert crit[0].mitre == "T1548.001"
    store.close()


# ---- P1b setuid in scratch dir ---- #


def test_setuid_in_tmp_is_critical(tmp_path):
    store = _store(tmp_path)
    _suid(store, "/tmp/rootme", in_system_dir=False, mode="04755")
    findings = list(PrivescDetector().detect(store))
    crit = [f for f in findings if "scratch/user dir" in f.title]
    assert crit
    assert crit[0].severity == "critical"
    store.close()


def test_setuid_in_user_home_is_critical(tmp_path):
    store = _store(tmp_path)
    _suid(store, "/home/alice/poc", in_system_dir=False, mode="04755")
    findings = list(PrivescDetector().detect(store))
    crit = [f for f in findings if "scratch/user dir" in f.title]
    assert crit
    store.close()


# ---- P2 GTFOBins commodity binary ---- #


def test_setuid_on_perl_is_critical(tmp_path):
    store = _store(tmp_path)
    _suid(store, "/usr/bin/perl", owner_uid=0, mode="04755", in_system_dir=True)
    findings = list(PrivescDetector().detect(store))
    crit = [f for f in findings if "commodity binary" in f.title]
    assert crit
    assert "perl" in crit[0].title
    store.close()


def test_legitimate_setuid_is_not_flagged_critical(tmp_path):
    """sudo itself is setuid root; we don't flag it."""
    store = _store(tmp_path)
    _suid(store, "/usr/bin/sudo", owner_uid=0, in_system_dir=True, mode="04755")
    findings = list(PrivescDetector().detect(store))
    crit = [f for f in findings if f.severity in ("high", "critical")]
    assert crit == [], [f.title for f in crit]
    store.close()


# ---- P3 sudoers NOPASSWD ---- #


def test_sudoers_nopasswd_all_flagged(tmp_path):
    store = _store(tmp_path)
    _sudoers(store, "ci", "ci ALL=(ALL:ALL) NOPASSWD: ALL\n")
    findings = list(PrivescDetector().detect(store))
    np = [f for f in findings if "NOPASSWD" in f.title]
    assert np, [f.title for f in findings]
    assert np[0].severity == "high"
    assert np[0].mitre == "T1548.003"
    store.close()


def test_sudoers_comment_is_not_flagged(tmp_path):
    store = _store(tmp_path)
    _sudoers(store, "doc",
             "# Example: ci ALL=(ALL) NOPASSWD: ALL  <- do not enable this\n")
    findings = list(PrivescDetector().detect(store))
    assert [f for f in findings if "NOPASSWD" in f.title] == []
    store.close()


# ---- P4 file capabilities ---- #


def test_dangerous_capability_on_python_is_critical(tmp_path):
    store = _store(tmp_path)
    _getcap(store, "/usr/bin/python3 cap_setuid,cap_net_raw=ep\n")
    findings = list(PrivescDetector().detect(store))
    cap = [f for f in findings if "file capability" in f.title]
    assert cap
    assert cap[0].severity == "critical"
    assert "cap_setuid" in str(cap[0].evidence["dangerous"])
    store.close()


def test_capability_on_admin_tool_is_high(tmp_path):
    store = _store(tmp_path)
    _getcap(store, "/usr/sbin/some-admin-tool cap_net_admin=ep\n")
    findings = list(PrivescDetector().detect(store))
    cap = [f for f in findings if "file capability" in f.title]
    assert cap
    assert cap[0].severity == "high"  # not a shell, but still dangerous cap
    store.close()


# ---- P5 kernel taint ---- #


def test_kernel_taint_unsigned_module_is_high(tmp_path):
    store = _store(tmp_path)
    _taint(store, 1 << 11)  # bit 11 = unsigned module
    findings = list(PrivescDetector().detect(store))
    t = [f for f in findings if "Kernel taint" in f.title]
    assert t
    assert t[0].severity == "high"
    assert any(b["bit"] == 11 for b in t[0].evidence["bits_set"])
    store.close()


def test_kernel_taint_zero_no_finding(tmp_path):
    store = _store(tmp_path)
    _taint(store, 0)
    findings = list(PrivescDetector().detect(store))
    assert [f for f in findings if "Kernel taint" in f.title] == []
    store.close()


# ---- Sigma generation ---- #


def test_privesc_sigma_for_setuid(tmp_path):
    store = _store(tmp_path)
    _suid(store, "/tmp/rootme", in_system_dir=False)
    f = next(PrivescDetector().detect(store))
    fdict = {
        "detector": f.detector,
        "title": f.title,
        "summary": f.summary,
        "severity": f.severity,
        "evidence": f.evidence,
        "finding_uuid": "pe-1",
    }
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert rule["logsource"]["category"] == "file_event"
    assert "attack.t1548.001" in rule["tags"]
    store.close()


def test_privesc_sigma_for_kernel_taint(tmp_path):
    store = _store(tmp_path)
    _taint(store, 1 << 11)
    f = next(PrivescDetector().detect(store))
    fdict = {
        "detector": f.detector,
        "title": f.title,
        "summary": f.summary,
        "severity": f.severity,
        "evidence": f.evidence,
        "finding_uuid": "pe-2",
    }
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert "attack.t1547.006" in rule["tags"]
    store.close()
