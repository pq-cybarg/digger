"""VECT 2.0 ransomware-by-design / wiper-by-accident detector tests."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.vect import VectDetector


_SHA256_LINUX = "e1fc59c7ece6e9a7fb262fc8529e3c4905503a1ca44630f9724b2ccc518d0c06"
_SHA256_WIN   = "8ee4ec425bc0d8db050d13bbff98f483fff020050d49f40c5055ca2b9f6b1c4d"
_SHA256_ESXI  = "a7eadcf81dd6fda0dd6affefaffcb33b1d8f64ddec6e5a1772d028ef2a7da0f2"


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, *, exe=None, sha256=None, cmdline=None):
    cm = cmdline if isinstance(cmdline, list) else \
        ([cmdline] if cmdline else [name])
    data = {
        "pid": pid, "ppid": 1, "name": name,
        "exe": exe or f"/usr/local/bin/{name}",
        "cmdline": cm, "username": "u",
        "connections": [], "open_files": [],
    }
    if sha256:
        data["exe_sha256"] = sha256
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}", data=data,
    ))


# ---- V1 hash IOCs ---- #


@pytest.mark.parametrize("sha,platform", [
    (_SHA256_LINUX, "linux"),
    (_SHA256_WIN, "windows"),
    (_SHA256_ESXI, "esxi"),
])
def test_v1_process_exe_sha256_match_critical(tmp_path, sha, platform):
    store = _store(tmp_path)
    _proc(store, 100, "encryptor", sha256=sha)
    findings = list(VectDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "binary_hash"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].evidence.get("platform") == platform
    assert "DO NOT PAY" in hits[0].evidence.get("destructive_warning", "")
    store.close()


def test_v1_unrelated_hash_not_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "notepad", sha256="0" * 64)
    findings = list(VectDetector().detect(store))
    assert [f for f in findings if f.evidence.get("kind") == "binary_hash"] == []
    store.close()


def test_v1_file_on_disk_sha256_match(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/tmp",
        data={"location": "/tmp", "entries": [
            {"path": "/tmp/.staged/encryptor", "size": 1024000,
             "sha256": _SHA256_WIN},
        ]},
    ))
    findings = list(VectDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "binary_hash"]
    assert hits
    assert hits[0].evidence.get("platform") == "windows"
    store.close()


# ---- V2 ransom-note filename ---- #


def test_v2_ransom_note_filename_critical(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home/dev",
        data={"location": "/home/dev", "entries": [
            {"path": "/home/dev/Documents/!!!READ_ME!!!.txt", "size": 4096},
        ]},
    ))
    findings = list(VectDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "ransom_note_file"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1486"
    store.close()


# ---- V3 .vect extension ---- #


def test_v3_vect_extension_single_hit_critical(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/srv",
        data={"location": "/srv", "entries": [
            {"path": "/srv/db/prod.dump.vect", "size": 1024 * 1024 * 1024},
        ]},
    ))
    findings = list(VectDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "vect_extension"]
    assert hits
    assert hits[0].severity == "critical"
    assert "/srv/db/prod.dump.vect" in hits[0].evidence.get("path", "")
    store.close()


def test_v3_unrelated_extension_not_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/srv",
        data={"location": "/srv", "entries": [
            {"path": "/srv/x.txt", "size": 10},
        ]},
    ))
    findings = list(VectDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "vect_extension"] == []
    store.close()


# ---- V4 ESXi/Linux drop paths ---- #


@pytest.mark.parametrize("path", [
    "/etc/motd",
    "/etc/issue",
    "/etc/issue.net",
    "/etc/profile.d/vector_notice.sh",
])
def test_v4_esxi_linux_drop_path_flagged(tmp_path, path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/etc",
        data={"location": "/etc", "entries": [
            {"path": path, "size": 512},
        ]},
    ))
    findings = list(VectDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "drop_path"]
    assert hits, [f.title for f in findings]
    assert hits[0].evidence.get("path") == path
    store.close()


# ---- V5 distinctive cmdline flags ---- #


@pytest.mark.parametrize("flag", [
    "--force-safemode",
    "--no-stealth",
    "--no-kill-vms",
])
def test_v5_distinctive_flag_critical(tmp_path, flag):
    store = _store(tmp_path)
    _proc(store, 100, "encryptor",
          cmdline=["encryptor", "--path", "/srv", flag])
    findings = list(VectDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "cmdline_flag"]
    assert hits
    assert hits[0].severity == "critical"
    assert hits[0].evidence.get("flag") == flag
    store.close()


# ---- V6 C2 ---- #


def test_v6_tor_onion_in_cmdline_critical(tmp_path):
    store = _store(tmp_path)
    onion = ("vectordntlcrlmfkcm4alni734tbcrnd5lk44v6sp4lqal6noqrgnbyd"
             ".onion/chat/abc")
    _proc(store, 100, "curl",
          cmdline=["curl", f"https://{onion}"])
    findings = list(VectDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "c2_cmdline"]
    assert hits
    store.close()


def test_v6_tor_onion_in_dns_critical(tmp_path):
    store = _store(tmp_path)
    onion = ("vectordntlcrlmfkcm4alni734tbcrnd5lk44v6sp4lqal6noqrgnbyd"
             ".onion")
    store.add_artifact(Artifact(
        collector="dns", category="network",
        subject="dns:cache",
        data={"host": onion, "entries": []},
    ))
    findings = list(VectDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "c2_dns"]
    assert hits
    store.close()


# ---- destructive_warning + mitigation routing ---- #


def test_every_finding_carries_destructive_warning(tmp_path):
    """V1-V6 findings all must ship destructive_warning + mitigation."""
    store = _store(tmp_path)
    _proc(store, 100, "encryptor", sha256=_SHA256_WIN)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/x",
        data={"location": "/x", "entries": [
            {"path": "/home/u/!!!READ_ME!!!.txt", "size": 1024},
            {"path": "/srv/file.vect", "size": 999999},
            {"path": "/etc/motd", "size": 256},
        ]},
    ))
    findings = list(VectDetector().detect(store))
    assert len(findings) >= 4
    for f in findings:
        warn = f.evidence.get("destructive_warning") or ""
        mit = f.evidence.get("mitigation_commands") or ""
        assert "DO NOT PAY" in warn
        assert "128 KB" in warn or "128KB" in warn or "131072" in warn
        assert "isolate" in mit.lower() or "memory image" in mit.lower()
    store.close()


# ---- registration + sigma ---- #


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "vect" in [d.name for d in all_detectors()]


def test_sigma_template_present():
    tpl = VectDetector().to_sigma_template()
    assert tpl is not None
    assert tpl["level"] == "critical"
    for tag in ("attack.t1486", "attack.t1485", "attack.t1489",
                "attack.impact"):
        assert tag in tpl["tags"]
    sels = [k for k in tpl["detection"] if k.startswith("selection_")]
    assert len(sels) >= 4
