"""LinuxTelemetryJammerDetector — distro / desktop telemetry disabler."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.linux_telemetry_jammer import LinuxTelemetryJammerDetector


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


# ---- L1 systemd telemetry units --------------------------------------- #


def test_whoopsie_unit_active_flagged(tmp_path):
    store = _store(tmp_path)
    raw = (
        "UNIT FILE                                    STATE     VENDOR PRESET\n"
        "whoopsie.service                             enabled   enabled\n"
        "apport.service                               enabled   enabled\n"
        "ssh.service                                  enabled   enabled\n"
    )
    store.add_artifact(Artifact(
        collector="linux.systemd", category="persistence",
        subject="list-unit-files",
        data={"raw": raw},
    ))
    findings = list(LinuxTelemetryJammerDetector().detect(store))
    units = {f.evidence.get("unit") for f in findings
             if f.evidence.get("kind") == "linux_telemetry_unit"}
    assert "whoopsie.service" in units
    assert "apport.service" in units
    # ssh.service is NOT in our telemetry set
    assert "ssh.service" not in units
    store.close()


def test_whoopsie_remediation_contains_apt_purge(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="linux.systemd", category="persistence",
        subject="list-unit-files",
        data={"raw": "whoopsie.service                  enabled   enabled\n"},
    ))
    findings = [f for f in LinuxTelemetryJammerDetector().detect(store)
                if f.evidence.get("unit") == "whoopsie.service"]
    assert findings
    mit = findings[0].evidence.get("remediation_commands") or ""
    # whoopsie maps to the apt-purge remediation (cleaner than mere
    # systemctl disable)
    assert "apt purge" in mit
    assert "whoopsie apport" in mit
    store.close()


def test_disabled_unit_not_flagged(tmp_path):
    store = _store(tmp_path)
    raw = (
        "UNIT FILE                                    STATE     VENDOR PRESET\n"
        "whoopsie.service                             disabled  enabled\n"
    )
    store.add_artifact(Artifact(
        collector="linux.systemd", category="persistence",
        subject="list-unit-files",
        data={"raw": raw},
    ))
    findings = [f for f in LinuxTelemetryJammerDetector().detect(store)
                if f.evidence.get("unit") == "whoopsie.service"]
    assert not findings
    store.close()


def test_masked_unit_not_flagged(tmp_path):
    store = _store(tmp_path)
    raw = "ubuntu-report.service                        masked    enabled\n"
    store.add_artifact(Artifact(
        collector="linux.systemd", category="persistence",
        subject="list-unit-files",
        data={"raw": raw},
    ))
    findings = [f for f in LinuxTelemetryJammerDetector().detect(store)
                if f.evidence.get("unit") == "ubuntu-report.service"]
    assert not findings
    store.close()


@pytest.mark.parametrize("unit", [
    "snapd.service", "snapd.refresh.timer", "abrtd.service",
    "tracker-miner-fs-3.service", "goa-daemon.service",
    "fwupd-refresh.timer", "popularity-contest.timer",
    "canonical-livepatch.service",
])
def test_known_telemetry_units_flagged(tmp_path, unit):
    store = _store(tmp_path)
    raw = f"{unit:<60} enabled   enabled\n"
    store.add_artifact(Artifact(
        collector="linux.systemd", category="persistence",
        subject="list-unit-files",
        data={"raw": raw},
    ))
    findings = [f for f in LinuxTelemetryJammerDetector().detect(store)
                if f.evidence.get("unit") == unit]
    assert findings, f"unit {unit} should be flagged"
    assert findings[0].severity == "low"
    store.close()


# ---- L2 telemetry processes ------------------------------------------ #


@pytest.mark.parametrize("name,exe", [
    ("whoopsie", "/usr/bin/whoopsie"),
    ("apport", "/usr/share/apport/apport"),
    ("tracker-miner-fs-3", "/usr/libexec/tracker-miner-fs-3"),
    ("abrtd", "/usr/sbin/abrtd"),
    ("baloo_file", "/usr/bin/baloo_file"),
    ("packagekitd", "/usr/libexec/packagekitd"),
])
def test_telemetry_process_flagged(tmp_path, name, exe):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid=100 {name}",
        data={"pid": 100, "ppid": 1, "name": name, "exe": exe,
              "cmdline": [exe], "username": "root",
              "connections": [], "open_files": []},
    ))
    findings = [f for f in LinuxTelemetryJammerDetector().detect(store)
                if f.evidence.get("kind") == "linux_telemetry_process"]
    assert findings, [f.title for f in findings]
    assert findings[0].evidence.get("component") == name
    store.close()


def test_unrelated_process_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=101 nginx",
        data={"pid": 101, "ppid": 1, "name": "nginx", "exe": "/usr/sbin/nginx",
              "cmdline": ["nginx"], "username": "www-data",
              "connections": [], "open_files": []},
    ))
    findings = list(LinuxTelemetryJammerDetector().detect(store))
    assert not findings
    store.close()


# ---- L3 popcon participate ------------------------------------------- #


def test_popcon_participate_yes_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="services", category="config",
        subject="/etc/popularity-contest.conf",
        data={"path": "/etc/popularity-contest.conf",
              "content": 'PARTICIPATE="yes"'},
    ))
    findings = [f for f in LinuxTelemetryJammerDetector().detect(store)
                if f.evidence.get("kind") == "popcon_participate"]
    assert findings
    mit = findings[0].evidence.get("remediation_commands") or ""
    assert "apt purge" in mit
    store.close()


def test_popcon_participate_no_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="services", category="config",
        subject="/etc/popularity-contest.conf",
        data={"path": "/etc/popularity-contest.conf",
              "content": 'PARTICIPATE="no"'},
    ))
    findings = [f for f in LinuxTelemetryJammerDetector().detect(store)
                if f.evidence.get("kind") == "popcon_participate"]
    assert not findings
    store.close()


# ---- L4 telemetry DNS ----------------------------------------------- #


@pytest.mark.parametrize("host", [
    "daisy.ubuntu.com", "popcon.ubuntu.com",
    "incoming.telemetry.mozilla.org", "self-repair.mozilla.org",
    "api.snapcraft.io", "vortex.data.microsoft.com",
])
def test_telemetry_host_dns_flagged(tmp_path, host):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="dns", category="network",
        subject="dns:cache",
        data={"host": host, "entries": []},
    ))
    findings = [f for f in LinuxTelemetryJammerDetector().detect(store)
                if f.evidence.get("kind") == "linux_telemetry_dns"]
    assert findings
    mit = findings[0].evidence.get("remediation_commands") or ""
    assert "/etc/hosts" in mit
    assert host in mit
    store.close()


# ---- L5 Firefox profile advisory ------------------------------------- #


def test_firefox_profile_path_emits_advisory(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home",
        data={
            "location": "/home/user",
            "entries": [
                {"path": "/home/user/.mozilla/firefox/abc123.default-release/prefs.js",
                 "size": 4096},
            ],
        },
    ))
    findings = [f for f in LinuxTelemetryJammerDetector().detect(store)
                if f.evidence.get("kind") == "firefox_telemetry_advisory"]
    assert findings
    mit = findings[0].evidence.get("remediation_commands") or ""
    assert "toolkit.telemetry.enabled" in mit
    assert "user.js" in mit
    store.close()


# ---- Sigma + registration ------------------------------------------- #


def test_sigma_template_present():
    tpl = LinuxTelemetryJammerDetector().to_sigma_template()
    assert tpl is not None
    assert tpl["logsource"]["product"] == "linux"
    assert "selection_telemetry_proc" in tpl["detection"]


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "linux_telemetry_jammer" in [d.name for d in all_detectors()]
