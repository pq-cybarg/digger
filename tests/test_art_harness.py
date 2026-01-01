"""Atomic Red Team validation harness — loader + coverage + sandbox + runner."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

from digger.art.harness import (
    AtomicTest,
    build_coverage_matrix,
    coverage_report_json,
    coverage_report_text,
    load_atomics,
    run_test,
    sandbox_check,
    verify_detection,
    SANDBOX_ENV,
)


# ---- AtomicTest.is_destructive ---------------------------------------- #


@pytest.mark.parametrize("cmd", [
    "rm -rf /home/user",
    "vssadmin delete shadows /all",
    "bcdedit /set {default} recoveryenabled No",
    "wevtutil cl Security",
    "Stop-Service WinDefend",
    "Set-MpPreference -DisableRealtimeMonitoring $true",
    "format C: /q",
    "shred -u /etc/shadow",
])
def test_is_destructive_true_for_known_destructive_primitives(cmd):
    t = AtomicTest(
        technique_id="T9999", index=0, name="test", description="",
        supported_platforms=["linux"], executor_name="bash", command=cmd,
    )
    assert t.is_destructive, f"should be destructive: {cmd}"


@pytest.mark.parametrize("cmd", [
    "echo hello",
    "whoami /priv",
    "ls -la /etc/passwd",
    "cat /proc/version",
    "Get-Process",
])
def test_is_destructive_false_for_benign_commands(cmd):
    t = AtomicTest(
        technique_id="T9999", index=0, name="test", description="",
        supported_platforms=["linux"], executor_name="bash", command=cmd,
    )
    assert not t.is_destructive


def test_display_id_format():
    t = AtomicTest(technique_id="T1059.001", index=3, name="x",
                   description="", supported_platforms=[], executor_name="",
                   command="")
    assert t.display_id == "T1059.001#3"


# ---- load_atomics: missing cache returns [] -------------------------- #


def test_load_atomics_missing_dir_returns_empty(tmp_path):
    out = load_atomics(root=tmp_path / "does-not-exist")
    assert out == []


def test_load_atomics_parses_yaml(tmp_path):
    """Build a minimal ART-shaped fixture and verify the loader."""
    yaml = pytest.importorskip("yaml")
    root = tmp_path / "atomics"
    tdir = root / "T1059"
    tdir.mkdir(parents=True)
    (tdir / "T1059.yaml").write_text(yaml.safe_dump({
        "attack_technique": "T1059",
        "atomic_tests": [
            {"name": "bash one-liner",
             "description": "Run a one-liner via bash.",
             "supported_platforms": ["linux", "macos"],
             "executor": {"name": "bash",
                          "command": "echo {{message}}"},
             "input_arguments": {
                 "message": {"description": "what to say",
                             "type": "string", "default": "hello"},
             },
             "auto_generated_guid": "0000-1111"},
            {"name": "powershell var",
             "description": "Set a PS var.",
             "supported_platforms": ["windows"],
             "executor": {"name": "powershell",
                          "command": "$x = 1"},
             "auto_generated_guid": "0000-2222"},
        ],
    }))
    out = load_atomics(root=root)
    assert len(out) == 2
    assert out[0].technique_id == "T1059"
    assert out[0].index == 0
    assert out[0].name == "bash one-liner"
    assert "linux" in out[0].supported_platforms
    assert out[0].executor_name == "bash"
    assert out[0].input_arguments["message"]["default"] == "hello"
    assert out[1].executor_name == "powershell"
    assert out[1].display_id == "T1059#1"


# ---- build_coverage_matrix ------------------------------------------- #


def _fake_digger_coverage():
    """Minimal stand-in for digger.genrule.heatmap.build_coverage()."""
    return {
        "techniques": {
            "T1059": {
                "tactics": ["execution"],
                "detectors": ["lolbins", "suspicious_processes"],
            },
            "T1059.001": {
                "tactics": ["execution"],
                "detectors": ["suspicious_processes"],
            },
            "T1486": {
                "tactics": ["impact"],
                "detectors": ["impact"],
            },
        },
        "tactics": {},
        "detectors": {},
        "summary": {},
    }


def _atom(tid, idx=0, *, destructive_cmd=False):
    cmd = "rm -rf ~/" if destructive_cmd else "echo hi"
    return AtomicTest(
        technique_id=tid, index=idx, name=f"test-{tid}-{idx}",
        description="", supported_platforms=["linux"],
        executor_name="bash", command=cmd,
    )


def test_coverage_matrix_basic():
    atomics = [_atom("T1059"), _atom("T1486"), _atom("T1190")]
    m = build_coverage_matrix(
        atomics=atomics, digger_coverage=_fake_digger_coverage(),
    )
    assert m["summary"]["art_techniques_total"] == 3
    assert m["summary"]["art_techniques_covered"] == 2  # T1059 + T1486
    assert m["summary"]["art_techniques_uncovered"] == 1  # T1190
    assert m["summary"]["art_tests_total"] == 3
    assert "T1190" in m["art_only"]
    # T1059 is covered by both lolbins + suspicious_processes
    assert "lolbins" in m["per_technique"]["T1059"]["covered_by_detectors"]
    assert "suspicious_processes" in m["per_technique"]["T1059"]["covered_by_detectors"]


def test_coverage_matrix_subtechnique_falls_back_to_parent():
    """ART tests for T1059.003 should still count as covered if the
    parent technique T1059 has a detector."""
    atomics = [_atom("T1059.003")]
    m = build_coverage_matrix(
        atomics=atomics, digger_coverage=_fake_digger_coverage(),
    )
    assert m["per_technique"]["T1059.003"]["covered"]
    # Detector list comes from the parent's entry
    assert "lolbins" in m["per_technique"]["T1059.003"]["covered_by_detectors"]


def test_destructive_count_tallied():
    atomics = [
        _atom("T1059", 0),
        _atom("T1059", 1, destructive_cmd=True),
        _atom("T1486", 0, destructive_cmd=True),
    ]
    m = build_coverage_matrix(
        atomics=atomics, digger_coverage=_fake_digger_coverage(),
    )
    assert m["summary"]["art_tests_destructive"] == 2
    assert m["per_technique"]["T1059"]["destructive_count"] == 1
    assert m["per_technique"]["T1486"]["destructive_count"] == 1


def test_digger_only_techniques_listed():
    """Techniques digger covers but ART doesn't test should appear in
    `digger_only`."""
    atomics = [_atom("T1059")]
    m = build_coverage_matrix(
        atomics=atomics, digger_coverage=_fake_digger_coverage(),
    )
    # T1486 is in digger but not in ART atomics → digger_only
    assert "T1486" in m["digger_only"]


# ---- renderers ------------------------------------------------------- #


def test_render_text_empty_corpus_returns_instructions():
    m = build_coverage_matrix(atomics=[], digger_coverage=_fake_digger_coverage())
    out = coverage_report_text(m)
    assert "no atomic tests loaded" in out
    assert "digger art update" in out


def test_render_text_lists_top_techniques():
    atomics = [_atom("T1059", i) for i in range(5)]
    atomics += [_atom("T1486", i) for i in range(3)]
    atomics += [_atom("T1190", 0)]  # uncovered
    m = build_coverage_matrix(
        atomics=atomics, digger_coverage=_fake_digger_coverage(),
    )
    out = coverage_report_text(m)
    assert "Atomic Red Team coverage" in out
    assert "T1059" in out
    assert "T1190" in out
    # UNCOVERED gap section
    assert "ART-only" in out


def test_render_json_roundtrip():
    m = build_coverage_matrix(
        atomics=[_atom("T1059")], digger_coverage=_fake_digger_coverage(),
    )
    out = coverage_report_json(m)
    re_parsed = json.loads(out)
    assert re_parsed["summary"] == m["summary"]


# ---- sandbox_check --------------------------------------------------- #


def test_sandbox_check_refuses_without_env_var(monkeypatch):
    monkeypatch.delenv(SANDBOX_ENV, raising=False)
    ok, reason = sandbox_check()
    assert not ok
    assert SANDBOX_ENV in reason


def test_sandbox_check_refuses_without_marker_file(monkeypatch, tmp_path):
    monkeypatch.setenv(SANDBOX_ENV, "1")
    # Repoint marker to a non-existent path
    monkeypatch.setattr("digger.art.harness.SANDBOX_MARKER",
                        tmp_path / "no-marker")
    ok, reason = sandbox_check()
    assert not ok
    assert "marker" in reason.lower()


def test_sandbox_check_ok_with_both(monkeypatch, tmp_path):
    monkeypatch.setenv(SANDBOX_ENV, "1")
    marker = tmp_path / "sandbox.ok"
    marker.touch()
    monkeypatch.setattr("digger.art.harness.SANDBOX_MARKER", marker)
    ok, reason = sandbox_check()
    assert ok, reason


def test_sandbox_check_refuses_marker_owned_by_other_user(
    monkeypatch, tmp_path,
):
    """The marker must be owned by the current user."""
    monkeypatch.setenv(SANDBOX_ENV, "1")
    marker = tmp_path / "sandbox.ok"
    marker.touch()
    monkeypatch.setattr("digger.art.harness.SANDBOX_MARKER", marker)
    # Force the uid check to fail by pretending we're a different uid
    monkeypatch.setattr(os, "getuid", lambda: 99999, raising=False)
    ok, reason = sandbox_check()
    assert not ok
    assert "owned" in reason.lower()


# ---- run_test gating ------------------------------------------------- #


def test_run_test_refuses_without_sandbox(monkeypatch):
    monkeypatch.delenv(SANDBOX_ENV, raising=False)
    t = _atom("T1059")
    r = run_test(t)
    assert r["executed"] is False
    assert SANDBOX_ENV in r["refusal_reason"]


def test_run_test_refuses_destructive_without_override(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv(SANDBOX_ENV, "1")
    marker = tmp_path / "sandbox.ok"
    marker.touch()
    monkeypatch.setattr("digger.art.harness.SANDBOX_MARKER", marker)
    monkeypatch.delenv("DIGGER_ART_ALLOW_DESTRUCTIVE", raising=False)
    t = _atom("T1486", destructive_cmd=True)
    r = run_test(t)
    assert r["executed"] is False
    assert "destructive" in r["refusal_reason"]


def test_run_test_executes_benign_in_sandbox(monkeypatch, tmp_path):
    monkeypatch.setenv(SANDBOX_ENV, "1")
    marker = tmp_path / "sandbox.ok"
    marker.touch()
    monkeypatch.setattr("digger.art.harness.SANDBOX_MARKER", marker)
    t = AtomicTest(
        technique_id="T0000", index=0, name="echo-marker",
        description="", supported_platforms=["linux"],
        executor_name="bash",
        command="echo digger-art-test-marker",
    )
    r = run_test(t, timeout_s=5)
    assert r["executed"] is True
    assert r["returncode"] == 0
    assert "digger-art-test-marker" in (r["stdout"] or "")


# ---- verify_detection ------------------------------------------------ #


def test_verify_detection_finds_matching_finding(tmp_path):
    from digger.core.evidence import EvidenceStore, Finding
    store = EvidenceStore(tmp_path / "ev.db")
    after = time.time()
    time.sleep(0.01)
    store.add_finding(Finding(
        detector="lolbins", severity="high",
        title="LOLBin abuse", summary="",
        artifact_refs=[], evidence={}, mitre="T1059",
    ))
    r = verify_detection(store, "T1059", after_ts=after, window_s=60)
    assert r["detected"] is True
    assert len(r["matching_findings"]) == 1
    assert r["matching_findings"][0]["detector"] == "lolbins"
    store.close()


def test_verify_detection_subtechnique_matches_parent(tmp_path):
    """A finding tagged T1059 should satisfy verification for T1059.003."""
    from digger.core.evidence import EvidenceStore, Finding
    store = EvidenceStore(tmp_path / "ev.db")
    after = time.time()
    store.add_finding(Finding(
        detector="lolbins", severity="high", title="x", summary="",
        artifact_refs=[], evidence={}, mitre="T1059",
    ))
    r = verify_detection(store, "T1059.003", after_ts=after, window_s=60)
    assert r["detected"] is True
    store.close()


def test_verify_detection_misses_outside_window(tmp_path):
    from digger.core.evidence import EvidenceStore, Finding
    store = EvidenceStore(tmp_path / "ev.db")
    store.add_finding(Finding(
        detector="lolbins", severity="high", title="x", summary="",
        artifact_refs=[], evidence={}, mitre="T1059",
    ))
    future = time.time() + 1000
    r = verify_detection(store, "T1059", after_ts=future, window_s=10)
    assert r["detected"] is False
    store.close()


# ---- CLI smoke ------------------------------------------------------- #


def test_cli_art_coverage_text_runs():
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "art", "coverage", "--format", "text"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    # With or without ART corpus installed, the command must succeed
    assert ("Atomic Red Team coverage" in r.stdout
            or "no atomic tests loaded" in r.stdout)


def test_cli_art_coverage_json_parses():
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "art", "coverage", "--format", "json"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    parsed = json.loads(r.stdout)
    assert "summary" in parsed
    assert "per_technique" in parsed
