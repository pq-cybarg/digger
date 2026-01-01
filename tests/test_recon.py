"""ReconDetector — port-scan + SSH-recon detection from collected artifacts."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.recon import ReconDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _conn(store, raddr_ip, laddr_port, status="SYN_RECV"):
    store.add_artifact(Artifact(
        collector="network",
        category="network",
        subject=f"{status} ('0.0.0.0', {laddr_port})->('{raddr_ip}', 12345)",
        data={
            "laddr": ["0.0.0.0", laddr_port],
            "raddr": [raddr_ip, 12345],
            "status": status,
            "family": "AF_INET",
        },
    ))


def _auth_log(store, raw):
    store.add_artifact(Artifact(
        collector="linux.auth_logs",
        category="logs",
        subject="log:/var/log/auth.log",
        data={"path": "/var/log/auth.log", "tail": raw, "raw": raw},
    ))


# ---- R1 portscan ---- #


def test_detects_multi_source_portscan(tmp_path):
    store = _store(tmp_path)
    # 4 scanner IPs, each hitting 5 ports
    for src_octet in range(1, 5):
        for port in (22, 80, 443, 3306, 5432):
            _conn(store, f"10.0.0.{src_octet}", port, "SYN_RECV")
    findings = list(ReconDetector().detect(store))
    multi = [f for f in findings if "Port-scan footprint" in f.title]
    assert multi, [f.title for f in findings]
    assert multi[0].severity == "high"
    assert multi[0].mitre == "T1595.001"
    assert multi[0].evidence["scanner_count"] == 4
    store.close()


def test_detects_single_source_portprobe(tmp_path):
    store = _store(tmp_path)
    for port in (22, 80, 443, 3306, 5432, 6379):
        _conn(store, "8.8.4.4", port, "SYN_RECV")
    findings = list(ReconDetector().detect(store))
    single = [f for f in findings if "8.8.4.4" in f.title]
    assert single, [f.title for f in findings]
    assert single[0].severity == "medium"
    store.close()


def test_no_finding_when_normal_traffic(tmp_path):
    store = _store(tmp_path)
    # All ESTABLISHED — not scan signal
    for port in (22, 80, 443):
        _conn(store, "10.0.0.1", port, "ESTABLISHED")
    findings = list(ReconDetector().detect(store))
    assert [f for f in findings if "Port-scan" in f.title or "port-probe" in f.title] == []
    store.close()


# ---- R2 SSH recon ---- #


def test_detects_ssh_brute_force(tmp_path):
    store = _store(tmp_path)
    lines = "\n".join(
        f"May 22 10:00:0{i % 10} host sshd[123]: "
        f"Failed password for invalid user admin{i} from 198.51.100.7 port 4{i}{i} ssh2"
        for i in range(25)
    )
    _auth_log(store, lines)
    findings = list(ReconDetector().detect(store))
    bf = [f for f in findings if "brute-force" in f.title.lower()]
    assert bf, [f.title for f in findings]
    assert bf[0].evidence["remote_ip"] == "198.51.100.7"
    assert bf[0].evidence["failed_attempts"] >= 20
    store.close()


def test_detects_ssh_banner_grab(tmp_path):
    store = _store(tmp_path)
    lines = "\n".join(
        f"May 22 10:01:0{i % 10} host sshd[123]: "
        f"Did not receive identification string from 203.0.113.9 port 4{i}{i}"
        for i in range(8)
    )
    _auth_log(store, lines)
    findings = list(ReconDetector().detect(store))
    bg = [f for f in findings if "banner-grab" in f.title.lower()]
    assert bg, [f.title for f in findings]
    assert bg[0].evidence["remote_ip"] == "203.0.113.9"
    store.close()


def test_detects_ssh_user_enum(tmp_path):
    store = _store(tmp_path)
    users = ["admin", "root", "test", "git", "ubuntu", "ec2-user",
             "oracle", "postgres", "redis", "alice", "bob", "carol"]
    lines = "\n".join(
        f"May 22 10:02:0{i % 10} host sshd[123]: "
        f"Invalid user {u} from 192.0.2.5 port 4{i}{i}"
        for i, u in enumerate(users)
    )
    _auth_log(store, lines)
    findings = list(ReconDetector().detect(store))
    enum_ = [f for f in findings if "enumeration" in f.title.lower()]
    assert enum_, [f.title for f in findings]
    assert enum_[0].mitre == "T1589.002"
    store.close()


# ---- Sigma generation ---- #


def test_recon_brute_force_generates_sigma(tmp_path):
    store = _store(tmp_path)
    lines = "\n".join(
        f"May 22 10:00:0{i % 10} host sshd[123]: "
        f"Failed password for invalid user u{i} from 198.51.100.7 port 1{i}{i}"
        for i in range(25)
    )
    _auth_log(store, lines)
    findings = list(ReconDetector().detect(store))
    bf = next(f for f in findings if "brute-force" in f.title.lower())
    # Marshal to dict the way Sigma generator expects
    finding_dict = {
        "detector": bf.detector,
        "title": bf.title,
        "summary": bf.summary,
        "severity": bf.severity,
        "evidence": bf.evidence,
        "finding_uuid": "test-uuid-1234",
    }
    rule = finding_to_sigma(finding_dict, case_id="test")
    assert rule is not None
    assert rule["logsource"]["service"] == "auth"
    assert "attack.t1110.001" in rule["tags"]
    assert "198.51.100.7" in rule["title"]
    store.close()


def test_recon_portscan_generates_sigma(tmp_path):
    store = _store(tmp_path)
    for src_octet in range(1, 5):
        for port in (22, 80, 443, 3306, 5432):
            _conn(store, f"10.0.0.{src_octet}", port, "SYN_RECV")
    findings = list(ReconDetector().detect(store))
    multi = next(f for f in findings if "Port-scan" in f.title)
    finding_dict = {
        "detector": multi.detector,
        "title": multi.title,
        "summary": multi.summary,
        "severity": multi.severity,
        "evidence": multi.evidence,
        "finding_uuid": "test-uuid-2345",
    }
    rule = finding_to_sigma(finding_dict, case_id="test")
    assert rule is not None
    assert rule["logsource"]["category"] == "network_connection"
    assert "attack.t1595.001" in rule["tags"]
    store.close()
