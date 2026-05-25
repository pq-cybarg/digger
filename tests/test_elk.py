"""ELK / OpenSearch _bulk NDJSON exporter."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import time

import pytest

from digger.exchange.elk import (
    ElkBulkSink,
    ElkExporter,
    artifact_to_ecs,
    bulk_lines,
    finding_to_ecs,
)


def _f(**kw):
    base = {
        "finding_uuid": "F-1",
        "detector": "trapdoor",
        "severity": "critical",
        "title": "Compromised npm package",
        "summary": "x",
        "mitre": "T1195.001",
        "evidence": {"package": "eth-wallet-sentinel@1.0.0",
                     "campaign": "TrapDoor"},
        "artifact_refs": ["A-1"],
        "ts": time.time(),
    }
    base.update(kw)
    return base


# ---- finding_to_ecs ---- #


def test_finding_to_ecs_has_required_ecs_fields():
    doc = finding_to_ecs(_f(), case_id="c1", host_name="myhost")
    assert "@timestamp" in doc
    assert doc["event.kind"] == "alert"
    assert doc["event.module"] == "digger"
    assert doc["event.dataset"] == "digger.findings"
    assert doc["host.name"] == "myhost"
    assert doc["rule.name"] == "trapdoor"
    assert doc["rule.uuid"] == "F-1"
    assert doc["message"] == "Compromised npm package"
    assert doc["digger.case_id"] == "c1"


@pytest.mark.parametrize("sev,expected", [
    ("info", 10), ("low", 25), ("medium", 50),
    ("high", 75), ("critical", 100),
])
def test_ecs_severity_scale(sev, expected):
    doc = finding_to_ecs(_f(severity=sev))
    assert doc["event.severity"] == expected


def test_ecs_threat_fields_from_mitre():
    doc = finding_to_ecs(_f(mitre="T1486"))
    assert doc["threat.framework"] == "MITRE ATT&CK"
    assert doc["threat.technique.id"] == "T1486"


def test_ecs_skips_threat_fields_when_no_mitre():
    doc = finding_to_ecs(_f(mitre=""))
    assert "threat.framework" not in doc
    assert "threat.technique.id" not in doc


def test_ecs_evidence_remote_ip_promoted():
    doc = finding_to_ecs(_f(evidence={
        "remote_ip": "192.0.2.1", "domain": "evil.example",
        "pid": 1234, "name": "node",
    }))
    assert doc["destination.ip"] == "192.0.2.1"
    assert doc["destination.domain"] == "evil.example"
    assert doc["process.pid"] == 1234
    assert doc["process.name"] == "node"


def test_ecs_evidence_file_hash_promoted():
    doc = finding_to_ecs(_f(evidence={
        "sha256": "a" * 64, "path": "/tmp/x",
    }))
    assert doc["file.hash.sha256"] == "a" * 64
    assert doc["file.path"] == "/tmp/x"


def test_ecs_campaign_promoted_to_threat_group():
    doc = finding_to_ecs(_f(evidence={"campaign": "Mini Shai-Hulud"}))
    assert doc["threat.group.name"] == "Mini Shai-Hulud"
    assert doc["digger.campaign"] == "Mini Shai-Hulud"


def test_ecs_empty_evidence_doesnt_crash():
    doc = finding_to_ecs(_f(evidence={}))
    assert "destination.ip" not in doc
    assert "file.path" not in doc


# ---- artifact_to_ecs ---- #


def test_artifact_to_ecs_basic():
    art = {
        "artifact_uuid": "A-7",
        "collector": "processes",
        "category": "process",
        "subject": "pid=1234 node",
        "data_sha256": "deadbeef",
        "data": {"pid": 1234, "name": "node"},
        "ts": time.time(),
    }
    doc = artifact_to_ecs(art, case_id="c1", host_name="h")
    assert doc["event.kind"] == "state"
    assert doc["event.dataset"] == "digger.artifacts"
    assert doc["digger.collector"] == "processes"
    assert doc["digger.artifact_uuid"] == "A-7"
    assert doc["digger.artifact_data"]["pid"] == 1234


# ---- bulk_lines ---- #


def test_bulk_lines_index_with_id():
    docs = [({"a": 1}, "doc-1")]
    lines = list(bulk_lines(docs, index="my-index", op="index"))
    assert len(lines) == 2
    action = json.loads(lines[0])
    body = json.loads(lines[1])
    assert action == {"index": {"_index": "my-index", "_id": "doc-1"}}
    assert body == {"a": 1}


def test_bulk_lines_index_without_id():
    lines = list(bulk_lines([({"a": 1}, None)], index="x"))
    action = json.loads(lines[0])
    assert action == {"index": {"_index": "x"}}


def test_bulk_lines_update_op_wraps_body():
    """update op requires {"doc": payload} body."""
    lines = list(bulk_lines(
        [({"a": 1}, "doc-1")], index="x", op="update",
    ))
    body = json.loads(lines[1])
    assert body == {"doc": {"a": 1}}


def test_bulk_lines_create_op_doesnt_wrap():
    lines = list(bulk_lines(
        [({"a": 1}, "doc-1")], index="x", op="create",
    ))
    body = json.loads(lines[1])
    assert body == {"a": 1}


# ---- ElkExporter.write_file ---- #


def test_exporter_writes_two_lines_per_finding(tmp_path):
    from digger.core.evidence import EvidenceStore, Finding

    store = EvidenceStore(tmp_path)
    store.add_finding(Finding(
        detector="trapdoor", severity="critical",
        title="x", summary="y", artifact_refs=[],
        evidence={"campaign": "TrapDoor"}, mitre="T1195.001",
    ))
    store.add_finding(Finding(
        detector="mini_shai_hulud", severity="critical",
        title="z", summary="w", artifact_refs=[],
        evidence={"host": "git-tanstack.com"}, mitre="T1071",
    ))

    out = tmp_path / "elk.ndjson"
    n = ElkExporter().write_file(
        store, out, case_id="c1", host_name="myhost",
        include_artifacts=False,
    )
    assert n == 4  # 2 findings × 2 lines each
    lines = out.read_text().splitlines()
    assert len(lines) == 4
    # Every line is valid JSON
    for ln in lines:
        json.loads(ln)
    # Index name + ECS shape
    action0 = json.loads(lines[0])
    body0 = json.loads(lines[1])
    assert action0["index"]["_index"] == "digger-findings"
    assert body0["@timestamp"]
    assert body0["host.name"] == "myhost"
    assert body0["digger.case_id"] == "c1"
    store.close()


def test_exporter_includes_artifacts_by_default(tmp_path):
    from digger.core.evidence import Artifact, EvidenceStore, Finding
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=1 init",
        data={"pid": 1, "name": "init"},
    ))
    store.add_finding(Finding(
        detector="x", severity="info", title="t", summary="",
        artifact_refs=[], evidence={}, mitre="",
    ))
    out = tmp_path / "elk.ndjson"
    n = ElkExporter().write_file(store, out, include_artifacts=True)
    assert n == 4  # 1 finding + 1 artifact, each two lines
    store.close()


def test_exporter_no_artifacts_flag(tmp_path):
    from digger.core.evidence import Artifact, EvidenceStore, Finding
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=1", data={"pid": 1},
    ))
    store.add_finding(Finding(
        detector="x", severity="info", title="t", summary="",
        artifact_refs=[], evidence={}, mitre="",
    ))
    out = tmp_path / "elk.ndjson"
    n = ElkExporter().write_file(store, out, include_artifacts=False)
    assert n == 2  # only the finding's two lines
    store.close()


def test_exporter_uses_custom_index_names(tmp_path):
    from digger.core.evidence import EvidenceStore, Finding
    store = EvidenceStore(tmp_path)
    store.add_finding(Finding(
        detector="x", severity="low", title="t", summary="",
        artifact_refs=[], evidence={}, mitre="",
    ))
    out = tmp_path / "elk.ndjson"
    ElkExporter(findings_index="custom-findings").write_file(
        store, out, include_artifacts=False,
    )
    line0 = out.read_text().splitlines()[0]
    assert json.loads(line0)["index"]["_index"] == "custom-findings"
    store.close()


# ---- ElkBulkSink (watch-daemon sink) ---- #


def test_bulk_sink_skips_on_empty(monkeypatch):
    posts = []
    monkeypatch.setattr("requests.post",
                        lambda *a, **kw: posts.append((a, kw)))
    ElkBulkSink(url="http://es:9200").emit([], tick=1)
    assert posts == []


def test_bulk_sink_posts_to_bulk_endpoint(monkeypatch):
    posts = []
    class _Resp:
        status_code = 200
        text = "ok"
    def _post(url, **kw):
        posts.append({"url": url, **kw})
        return _Resp()
    monkeypatch.setattr("requests.post", _post)
    sink = ElkBulkSink(url="http://es:9200/", case_id="c1",
                       host_name="h", findings_index="my-findings")
    sink.emit([_f()], tick=3)
    assert len(posts) == 1
    assert posts[0]["url"] == "http://es:9200/_bulk"
    assert posts[0]["headers"]["Content-Type"] == "application/x-ndjson"
    body = posts[0]["data"]
    lines = body.strip().split("\n")
    assert len(lines) == 2
    action = json.loads(lines[0])
    doc = json.loads(lines[1])
    assert action["index"]["_index"] == "my-findings"
    assert doc["rule.uuid"] == "F-1"
    assert doc["digger.case_id"] == "c1"


def test_bulk_sink_swallows_network_errors(monkeypatch):
    def _boom(*a, **kw):
        raise ConnectionError("down")
    monkeypatch.setattr("requests.post", _boom)
    stderr = io.StringIO()
    sink = ElkBulkSink(url="http://es:9200", _stderr=stderr)
    sink.emit([_f()], tick=1)  # MUST NOT raise
    assert "_bulk POST failed" in stderr.getvalue()


def test_bulk_sink_handles_requests_missing(monkeypatch):
    import builtins
    real = builtins.__import__
    def no_requests(name, *a, **kw):
        if name == "requests":
            raise ImportError("missing")
        return real(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", no_requests)
    stderr = io.StringIO()
    sink = ElkBulkSink(url="http://es:9200", _stderr=stderr)
    sink.emit([_f()], tick=1)
    assert "requests not installed" in stderr.getvalue()


def test_bulk_sink_includes_custom_headers(monkeypatch):
    posts = []
    monkeypatch.setattr("requests.post",
                        lambda *a, **kw: posts.append(kw) or type("R",(),{"status_code":200,"text":"ok"})())
    sink = ElkBulkSink(
        url="http://es:9200",
        headers={"Authorization": "ApiKey abc"},
    )
    sink.emit([_f()], tick=1)
    assert posts[0]["headers"]["Authorization"] == "ApiKey abc"
    # Content-Type is still set by us
    assert posts[0]["headers"]["Content-Type"] == "application/x-ndjson"


# ---- CLI smoke ---- #


def test_cli_export_elk_writes_file(tmp_path):
    from digger.core.evidence import EvidenceStore, Finding
    store = EvidenceStore(tmp_path)
    store.add_finding(Finding(
        detector="x", severity="critical", title="t", summary="",
        artifact_refs=[], evidence={"campaign": "TrapDoor"},
        mitre="T1195.001",
    ))
    store.close()
    out = tmp_path / "out.ndjson"
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "export", "elk",
         "--case-dir", str(tmp_path),
         "--out", str(out),
         "--no-artifacts"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert out.exists()
    lines = out.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["index"]["_index"] == "digger-findings"
