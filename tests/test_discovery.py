"""DiscoveryDetector — living-off-the-land enumeration on the host."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.discovery import (
    CLUSTER_MIN_DISTINCT,
    CLUSTER_WINDOW_S,
    DiscoveryDetector,
)


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, cmdline, *, username="user", ts=None):
    if isinstance(cmdline, str):
        cm = cmdline.split()
    else:
        cm = list(cmdline)
    data = {
        "pid": pid, "ppid": 1, "name": name,
        "exe": f"/usr/bin/{name}",
        "cmdline": cm,
        "username": username,
        "connections": [], "open_files": [],
    }
    if ts is not None:
        data["create_time"] = ts
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}", data=data,
    ))


# ---- D1 high-signal single-hit patterns ---- #


@pytest.mark.parametrize("cmd,want_mitre,want_kind", [
    ("whoami /all",                  "T1033",     "owner_priv_dump"),
    ("whoami /priv",                 "T1033",     "owner_priv_dump"),
    ("whoami /groups",               "T1033",     "owner_priv_dump"),
    ("net user /domain",             "T1087.002", "ad_account_enum"),
    ("net user",                     "T1087.001", "local_account_enum"),
    ("net localgroup",               "T1069.001", "local_group_enum"),
    ('net group "Domain Admins" /domain',
     "T1069.002", "domain_admin_enum"),
    ("nltest /dclist:corp.local",    "T1018",     "dc_discovery"),
    ("nltest /domain_trusts",        "T1482",     "trust_discovery"),
    ("net view /domain",             "T1018",     "remote_system_discovery"),
    ("ldapsearch -x -b dc=corp",     "T1087.002", "ldap_enum"),
    ("dsquery user -name *",         "T1087.002", "ad_query"),
    ("Get-ADUser -Filter *",         "T1087.002", "ad_powershell"),
    ("Get-LocalGroupMember -Group Administrators",
     "T1069.001", "local_group_enum"),
    ("getent passwd",                "T1087.001", "getent_enum"),
    ("getent shadow",                "T1087.001", "getent_enum"),
    ("dscl . list /Users",           "T1087.001", "macos_account_enum"),
    ("find / -perm -4000 -type f",   "T1083",     "suid_hunt"),
    ('find / -name "*.kdbx"',        "T1083",     "credential_file_hunt"),
    ("find / -name id_rsa",          "T1083",     "credential_file_hunt"),
    ('find / -name "*.pem"',         "T1083",     "credential_file_hunt"),
    ("grep -r password /etc",        "T1552.001", "credential_string_hunt"),
    ("grep -r api_key /home",        "T1552.001", "credential_string_hunt"),
    ("nmap -sS 10.0.0.0/24",         "T1046",     "port_scanner"),
    ("masscan -p1-65535 1.1.1.1",    "T1046",     "port_scanner"),
    ("rustscan -a 10.0.0.5",         "T1046",     "port_scanner"),
    ("naabu -host target.local",     "T1046",     "port_scanner"),
    ("net view \\\\fileserver",      "T1135",     "share_enum"),
    ("smbclient -L //fileserver",    "T1135",     "share_enum"),
    ("enum4linux 192.168.1.5",       "T1135",     "share_enum"),
])
def test_d1_high_signal_single_hits(tmp_path, cmd, want_mitre, want_kind):
    store = _store(tmp_path)
    _proc(store, 100, "bash", ["bash", "-c", cmd])
    findings = list(DiscoveryDetector().detect(store))
    matching = [f for f in findings if f.evidence.get("kind") == want_kind]
    assert matching, (
        f"expected kind={want_kind} for cmd={cmd!r}; got "
        f"{[(f.evidence.get('kind'), f.mitre) for f in findings]}"
    )
    assert matching[0].mitre == want_mitre
    store.close()


def test_d1_severity_downgraded_for_admin_user(tmp_path):
    """whoami /all by root should not be a 'high' finding — it's
    almost always a sysadmin or shell prompt setup. Downgraded to
    low; we still record it for audit but don't flood the report."""
    store = _store(tmp_path)
    _proc(store, 100, "bash", ["bash", "-c", "whoami /all"],
          username="root")
    findings = list(DiscoveryDetector().detect(store))
    f = next(f for f in findings
             if f.evidence.get("kind") == "owner_priv_dump")
    assert f.severity == "low"
    store.close()


def test_d1_severity_kept_for_non_admin_user(tmp_path):
    """whoami /all by a normal user is the signal we care about."""
    store = _store(tmp_path)
    _proc(store, 100, "bash", ["bash", "-c", "whoami /all"],
          username="alice")
    findings = list(DiscoveryDetector().detect(store))
    f = next(f for f in findings
             if f.evidence.get("kind") == "owner_priv_dump")
    assert f.severity == "high"
    store.close()


def test_d1_one_finding_per_process(tmp_path):
    """Even if a process matches multiple D1 patterns, only emit one
    D1 finding per (pid, kind) tuple."""
    store = _store(tmp_path)
    # whoami /all + whoami /priv on the same line — both match
    # owner_priv_dump kind; we should dedupe
    _proc(store, 100, "bash",
          ["bash", "-c", "whoami /all && whoami /priv"],
          username="alice")
    findings = list(DiscoveryDetector().detect(store))
    priv_dump = [f for f in findings
                 if f.evidence.get("kind") == "owner_priv_dump"]
    assert len(priv_dump) == 1
    store.close()


def test_d1_credential_hunt_is_critical(tmp_path):
    """Credential-file hunts (find *.kdbx, id_rsa, *.pem) are
    critical-severity; they're never routine."""
    store = _store(tmp_path)
    _proc(store, 100, "bash",
          ["bash", "-c", 'find / -name "*.kdbx" 2>/dev/null'],
          username="alice")
    findings = list(DiscoveryDetector().detect(store))
    hunt = [f for f in findings
            if f.evidence.get("kind") == "credential_file_hunt"]
    assert len(hunt) == 1
    assert hunt[0].severity == "critical"
    store.close()


def test_domain_admin_enum_is_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "cmd.exe",
          ["cmd.exe", "/c", 'net group "Domain Admins" /domain'],
          username="alice")
    findings = list(DiscoveryDetector().detect(store))
    f = next(f for f in findings
             if f.evidence.get("kind") == "domain_admin_enum")
    assert f.severity == "critical"
    assert f.mitre == "T1069.002"
    store.close()


# ---- D3 security-software discovery ---- #


@pytest.mark.parametrize("cmd", [
    "tasklist /svc | findstr CSFalconSvc",
    "Get-Service WinDefend",
    "Get-Service SentinelAgent",
    "ps -ef | grep crowdstrike",
    "ps -ef | grep falcon",
    "systemctl status falcon-sensor",
    "systemctl is-active crowdstrike",
    "Get-MpComputerStatus",
    "Get-MpPreference",
    "launchctl list | grep CrowdStrike",
])
def test_d3_security_software_discovery(tmp_path, cmd):
    store = _store(tmp_path)
    _proc(store, 100, "bash", ["bash", "-c", cmd], username="alice")
    findings = list(DiscoveryDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "security_software_discovery"]
    assert hits, (
        f"expected security_software_discovery for cmd={cmd!r}; "
        f"got {[(f.evidence.get('kind'), f.mitre) for f in findings]}"
    )
    assert hits[0].mitre == "T1518.001"
    assert hits[0].severity == "high"
    store.close()


# ---- D4 cluster heuristic ---- #


def test_d4_cluster_fires_on_3_distinct_recon_commands(tmp_path):
    """≥3 distinct standard recon commands within 60s → cluster
    finding."""
    store = _store(tmp_path)
    base_ts = 1_700_000_000
    _proc(store, 100, "bash", ["bash", "-c", "whoami"],
          username="alice", ts=base_ts)
    _proc(store, 101, "bash", ["bash", "-c", "uname -a"],
          username="alice", ts=base_ts + 5)
    _proc(store, 102, "bash", ["bash", "-c", "ifconfig"],
          username="alice", ts=base_ts + 10)
    _proc(store, 103, "bash", ["bash", "-c", "netstat -an"],
          username="alice", ts=base_ts + 20)
    findings = list(DiscoveryDetector().detect(store))
    cluster = [f for f in findings
               if f.evidence.get("kind") == "discovery_cluster"]
    assert len(cluster) == 1
    assert cluster[0].severity == "medium"
    distinct = cluster[0].evidence.get("distinct_labels") or []
    # 4 distinct labels: owner_id, sysinfo, network_config, network_conn
    assert len(distinct) >= 3
    assert "owner_id" in distinct
    store.close()


def test_d4_cluster_below_threshold_does_not_fire(tmp_path):
    """2 distinct recon commands < CLUSTER_MIN_DISTINCT (3) → no
    cluster finding."""
    assert CLUSTER_MIN_DISTINCT == 3
    store = _store(tmp_path)
    base_ts = 1_700_000_000
    _proc(store, 100, "bash", ["bash", "-c", "whoami"],
          username="alice", ts=base_ts)
    _proc(store, 101, "bash", ["bash", "-c", "uname -a"],
          username="alice", ts=base_ts + 5)
    findings = list(DiscoveryDetector().detect(store))
    cluster = [f for f in findings
               if f.evidence.get("kind") == "discovery_cluster"]
    assert cluster == []
    store.close()


def test_d4_cluster_same_command_repeated_does_not_count(tmp_path):
    """3 invocations of `whoami` is not a cluster — it's the same
    distinct label repeated. Cluster requires DISTINCT labels."""
    store = _store(tmp_path)
    base_ts = 1_700_000_000
    for i in range(3):
        _proc(store, 100 + i, "bash", ["bash", "-c", "whoami"],
              username="alice", ts=base_ts + i)
    findings = list(DiscoveryDetector().detect(store))
    cluster = [f for f in findings
               if f.evidence.get("kind") == "discovery_cluster"]
    assert cluster == []
    store.close()


def test_d4_cluster_different_users_dont_merge(tmp_path):
    """alice's whoami + bob's uname + carol's ifconfig shouldn't
    cluster — different users.

    Use commands that don't trigger D1 single-hit findings (whoami
    plain, uname -a, ifconfig) so we're testing cluster-only
    behavior."""
    store = _store(tmp_path)
    base_ts = 1_700_000_000
    _proc(store, 100, "bash", ["bash", "-c", "whoami"],
          username="alice", ts=base_ts)
    _proc(store, 101, "bash", ["bash", "-c", "uname -a"],
          username="bob", ts=base_ts + 5)
    _proc(store, 102, "bash", ["bash", "-c", "ifconfig"],
          username="carol", ts=base_ts + 10)
    findings = list(DiscoveryDetector().detect(store))
    cluster = [f for f in findings
               if f.evidence.get("kind") == "discovery_cluster"]
    assert cluster == []
    store.close()


def test_d4_cluster_outside_window_does_not_merge(tmp_path):
    """3 distinct commands but spread across two 60s buckets shouldn't
    cluster (each bucket only sees a subset). The window logic uses
    bucket-aligned starts."""
    assert CLUSTER_WINDOW_S == 60
    store = _store(tmp_path)
    base_ts = 1_700_000_000
    _proc(store, 100, "bash", ["bash", "-c", "whoami"],
          username="alice", ts=base_ts)
    # ~60s later → next bucket
    _proc(store, 101, "bash", ["bash", "-c", "uname -a"],
          username="alice", ts=base_ts + CLUSTER_WINDOW_S * 5)
    _proc(store, 102, "bash", ["bash", "-c", "ifconfig"],
          username="alice", ts=base_ts + CLUSTER_WINDOW_S * 10)
    findings = list(DiscoveryDetector().detect(store))
    cluster = [f for f in findings
               if f.evidence.get("kind") == "discovery_cluster"]
    assert cluster == []
    store.close()


def test_d4_cluster_admin_severity_is_low(tmp_path):
    """Admin clusters are sysadmin debugging — soft severity."""
    store = _store(tmp_path)
    base_ts = 1_700_000_000
    _proc(store, 100, "bash", ["bash", "-c", "whoami"],
          username="root", ts=base_ts)
    _proc(store, 101, "bash", ["bash", "-c", "uname -a"],
          username="root", ts=base_ts + 5)
    _proc(store, 102, "bash", ["bash", "-c", "ifconfig"],
          username="root", ts=base_ts + 10)
    findings = list(DiscoveryDetector().detect(store))
    cluster = [f for f in findings
               if f.evidence.get("kind") == "discovery_cluster"]
    assert len(cluster) == 1
    assert cluster[0].severity == "low"
    store.close()


# ---- clean negatives ---- #


def test_no_findings_when_only_unrelated_processes(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "vim", ["vim", "/etc/hosts"], username="alice")
    _proc(store, 101, "git", ["git", "log"], username="alice")
    _proc(store, 102, "node", ["node", "/srv/app.js"], username="alice")
    findings = list(DiscoveryDetector().detect(store))
    assert findings == []
    store.close()


# ---- registration + sigma ---- #


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "discovery" in [d.name for d in all_detectors()]


def test_sigma_template_present():
    tpl = DiscoveryDetector().to_sigma_template()
    assert tpl is not None
    assert tpl["level"] == "high"
    for tag in (
        "attack.t1007", "attack.t1018", "attack.t1046",
        "attack.t1069", "attack.t1083", "attack.t1087",
        "attack.t1518.001", "attack.discovery",
    ):
        assert tag in tpl["tags"]


def test_sigma_template_covers_both_selections():
    tpl = DiscoveryDetector().to_sigma_template()
    sels = [k for k in tpl["detection"] if k.startswith("selection_")]
    assert "selection_high_signal_lotl" in sels
    assert "selection_security_software" in sels


def test_heatmap_discovery_tactic_expanded():
    """End-to-end: the heatmap should now show Discovery at >> 1
    technique."""
    from digger.genrule.heatmap import build_coverage
    cov = build_coverage()
    discovery = cov["tactics"]["discovery"]
    assert len(discovery["technique_ids"]) >= 12
    # And the discovery detector must be the source for most of them
    covering = set()
    for tid in discovery["technique_ids"]:
        covering.update(cov["techniques"][tid]["detectors"])
    assert "discovery" in covering
