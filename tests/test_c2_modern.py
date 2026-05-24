"""Extended C2 detector — modern frameworks, named pipes, injection landing pads."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.c2 import C2Detector


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, cmdline=None, open_files=None, connections=None):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    store.add_artifact(Artifact(
        collector="processes",
        category="process",
        subject=f"pid={pid} {name}",
        data={
            "pid": pid, "ppid": 1, "name": name,
            "exe": f"/usr/bin/{name}",
            "cmdline": cm,
            "open_files": open_files or [],
            "connections": connections or [],
        },
    ))


# ---- Modern framework signatures ---- #


def test_sliver_implant_binary_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "sliver-darwin", cmdline=["/tmp/sliver-darwin.bin"])
    findings = list(C2Detector().detect(store))
    s = [f for f in findings if f.evidence.get("framework") == "Sliver"]
    assert s, [f.title for f in findings]
    store.close()


def test_havoc_demon_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "demon", cmdline=["/opt/havoc/demon.bin", "--connect", "10.0.0.5"])
    findings = list(C2Detector().detect(store))
    h = [f for f in findings if f.evidence.get("framework") == "Havoc"]
    assert h
    store.close()


def test_brute_ratel_badger_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "badger.exe", cmdline=["badger.exe"])
    findings = list(C2Detector().detect(store))
    b = [f for f in findings if f.evidence.get("framework") == "Brute Ratel C4"]
    assert b
    store.close()


def test_merlin_agent_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "merlinagent", cmdline=["./merlinagent", "-url", "https://c2.example"])
    findings = list(C2Detector().detect(store))
    m = [f for f in findings if f.evidence.get("framework") == "Merlin"]
    assert m
    store.close()


def test_nighthawk_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "nh_beacon", cmdline=["nh_beacon.exe"])
    findings = list(C2Detector().detect(store))
    n = [f for f in findings if f.evidence.get("framework") == "Nighthawk (MDSec)"]
    assert n
    store.close()


# ---- Named-pipe patterns ---- #


def test_cobalt_strike_msse_pipe_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "rundll32.exe",
          open_files=[r"\\.\pipe\MSSE-1234-server"])
    findings = list(C2Detector().detect(store))
    cs = [f for f in findings if f.evidence.get("framework") == "Cobalt Strike"
          and f.evidence.get("kind") == "pipe_pattern"]
    assert cs, [f.title for f in findings]
    store.close()


def test_sliver_named_pipe_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "svchost.exe",
          open_files=[r"\\.\pipe\sliver_session_abc"])
    findings = list(C2Detector().detect(store))
    s = [f for f in findings if f.evidence.get("framework") == "Sliver"
         and f.evidence.get("kind") == "pipe_pattern"]
    assert s
    store.close()


def test_havoc_demon_pipe_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "wininit.exe",
          open_files=[r"\\.\pipe\demon_a1b2c3d4"])
    findings = list(C2Detector().detect(store))
    h = [f for f in findings if f.evidence.get("framework") == "Havoc"
         and f.evidence.get("kind") == "pipe_pattern"]
    assert h
    store.close()


# ---- Process-injection landing-pad heuristic ---- #


def test_svchost_to_random_ip_flagged_as_injection_target(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "svchost.exe",
          connections=[{"raddr": ["8.8.4.4", 443], "status": "ESTABLISHED"}])
    findings = list(C2Detector().detect(store))
    inj = [f for f in findings if f.evidence.get("kind") == "injection_landing_pad"]
    assert inj, [f.title for f in findings]
    assert inj[0].mitre == "T1055"
    store.close()


def test_svchost_to_microsoft_range_not_flagged(tmp_path):
    """13.107.x.x is in the Microsoft Azure hint set — should be ignored."""
    store = _store(tmp_path)
    _proc(store, 100, "svchost.exe",
          connections=[{"raddr": ["13.107.4.50", 443], "status": "ESTABLISHED"}])
    findings = list(C2Detector().detect(store))
    inj = [f for f in findings if f.evidence.get("kind") == "injection_landing_pad"]
    assert inj == []
    store.close()


def test_explorer_with_outbound_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "explorer.exe",
          connections=[{"raddr": ["192.168.55.5", 443], "status": "ESTABLISHED"}])
    findings = list(C2Detector().detect(store))
    inj = [f for f in findings if f.evidence.get("kind") == "injection_landing_pad"]
    assert inj
    store.close()
