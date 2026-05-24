"""CounterREDetector — debugger attached to digger / EDR processes."""

from __future__ import annotations

import os

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.counter_re import CounterREDetector, _extract_target_pids
from digger.opsec.watchers import _extract_target_pids as watcher_extract


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, cmdline, exe=None):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}",
        data={"pid": pid, "ppid": 1, "name": name,
              "exe": exe or f"/usr/bin/{name}",
              "cmdline": cm, "username": "user",
              "connections": [], "open_files": []},
    ))


# ---- target-pid extraction ---- #


def test_extract_pid_dash_p():
    assert 1234 in _extract_target_pids("gdb -p 1234")


def test_extract_pid_long_pid_flag():
    assert 4567 in _extract_target_pids("lldb --pid 4567")


def test_extract_pid_attach_keyword():
    assert 8900 in _extract_target_pids("gdb (no executable) attach 8900")


def test_extract_pid_x64dbg_form():
    assert 2222 in _extract_target_pids("x64dbg.exe -pid2222")


def test_extract_pid_ida_form():
    assert 3333 in _extract_target_pids("ida64 -P3333 somefile")


def test_extract_no_pid_in_normal_cmdline():
    assert _extract_target_pids("gdb /usr/bin/ls") == set()


# ---- detector: collected-artifact path ---- #


def test_debugger_against_digger_self_flagged(tmp_path):
    store = _store(tmp_path)
    # Add a digger-looking process that the debugger is targeting
    _proc(store, 9999, "python3",
          cmdline=["python3", "-m", "digger.cli", "collect"])
    # Debugger attached to that pid
    _proc(store, 1000, "lldb", cmdline=["lldb", "--pid", "9999"])
    findings = list(CounterREDetector().detect(store))
    self_hit = [f for f in findings
                if f.evidence.get("kind") == "stored_debugger_attach"
                and f.evidence.get("self_attribution")]
    assert self_hit, [f.title for f in findings]
    assert self_hit[0].severity == "high"
    assert self_hit[0].mitre == "T1622"
    assert "digger" in self_hit[0].title
    store.close()


def test_debugger_against_edr_flagged_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 8888, "falcon-sensor", cmdline=["falcon-sensor"])
    _proc(store, 2000, "gdb", cmdline=["gdb", "-p", "8888"])
    findings = list(CounterREDetector().detect(store))
    edr = [f for f in findings
           if f.evidence.get("kind") == "stored_debugger_attach"
           and f.evidence.get("target", {}).get("is_edr")]
    assert edr
    assert edr[0].severity == "critical"
    store.close()


def test_debugger_against_random_target_not_flagged(tmp_path):
    """Debugger attached to a non-defender PID is irrelevant to this detector."""
    store = _store(tmp_path)
    _proc(store, 7777, "myapp", cmdline=["myapp"])
    _proc(store, 3000, "gdb", cmdline=["gdb", "-p", "7777"])
    findings = list(CounterREDetector().detect(store))
    stored = [f for f in findings if f.evidence.get("kind") == "stored_debugger_attach"]
    assert stored == []
    store.close()


def test_non_debugger_process_not_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 9999, "python3",
          cmdline=["python3", "-m", "digger.cli"])
    # Innocent process that mentions -p 9999 (not a debugger)
    _proc(store, 4000, "myapp", cmdline=["myapp", "-p", "9999"])
    findings = list(CounterREDetector().detect(store))
    stored = [f for f in findings if f.evidence.get("kind") == "stored_debugger_attach"]
    assert stored == []
    store.close()


def test_watcher_extract_target_pids_handles_multiple():
    assert watcher_extract("lldb -p 100 --pid 200") == {100, 200}


def test_sigma_emitted_for_counter_re(tmp_path):
    from digger.genrule.sigma import finding_to_sigma
    store = _store(tmp_path)
    _proc(store, 9999, "python3",
          cmdline=["python3", "-m", "digger.cli", "scan"])
    _proc(store, 1000, "lldb", cmdline=["lldb", "--pid", "9999"])
    f = next(CounterREDetector().detect(store))
    fdict = {"detector": f.detector, "title": f.title, "summary": f.summary,
             "severity": f.severity, "evidence": f.evidence,
             "finding_uuid": "cre-1"}
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert "attack.t1622" in rule["tags"]
    assert rule["logsource"]["category"] == "process_creation"
    store.close()
