"""Falco eBPF runtime-security bridge tests."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from digger.core.evidence import EvidenceStore
from digger.falco.runner import (
    FalcoError,
    FalcoIngestSummary,
    _mitre_from_tags,
    _parse_ts,
    _severity,
    discover_binary,
    ingest_file,
    parse_event,
    stream_events,
)


# ---- binary discovery ---- #


def test_discover_binary_honors_env(monkeypatch, tmp_path):
    fake = tmp_path / "fake_falco"
    fake.write_text("#!/bin/sh\necho hi\n")
    fake.chmod(0o755)
    monkeypatch.setenv("DIGGER_FALCO_BIN", str(fake))
    assert discover_binary() == str(fake)


def test_discover_binary_env_missing_returns_none(monkeypatch):
    monkeypatch.setenv("DIGGER_FALCO_BIN", "/nonexistent/zzz")
    assert discover_binary() is None


def test_discover_binary_path_scan(monkeypatch):
    monkeypatch.delenv("DIGGER_FALCO_BIN", raising=False)
    monkeypatch.setattr(
        "digger.falco.runner.shutil.which",
        lambda name: "/usr/bin/falco" if name == "falco" else None,
    )
    assert discover_binary() == "/usr/bin/falco"


# ---- helpers ---- #


def test_parse_ts_nanosecond_iso():
    ts = _parse_ts("2026-05-25T13:00:00.123456789Z")
    # 2026-05-25T13:00:00Z is well-defined
    assert ts is not None
    assert ts > 1.7e9
    assert ts < 2.0e9


def test_parse_ts_no_fractional():
    ts = _parse_ts("2026-05-25T13:00:00Z")
    assert ts is not None


def test_parse_ts_none_or_invalid():
    assert _parse_ts(None) is None
    assert _parse_ts("") is None
    assert _parse_ts("not a date") is None


def test_mitre_from_tags_prefers_explicit_technique():
    assert _mitre_from_tags(["filesystem", "T1552.001",
                              "mitre_credential_access"]) == "T1552.001"


def test_mitre_from_tags_no_technique_returns_empty():
    assert _mitre_from_tags(["filesystem", "mitre_credential_access"]) == ""


def test_mitre_from_tags_empty():
    assert _mitre_from_tags([]) == ""
    assert _mitre_from_tags(None) == ""


@pytest.mark.parametrize("prio,expected", [
    ("Emergency", "critical"),
    ("alert",     "critical"),
    ("Critical",  "critical"),
    ("Error",     "high"),
    ("Warning",   "high"),
    ("Notice",    "medium"),
    ("Info",      "low"),
    ("Informational", "low"),
    ("Debug",     "info"),
    ("unknown",   "low"),
    ("",          "low"),
    (None,        "low"),
])
def test_severity_mapping(prio, expected):
    assert _severity(prio) == expected


# ---- parse_event ---- #


_FALCO_EVENT_JSON = json.dumps({
    "time": "2026-05-25T13:00:00.000000000Z",
    "priority": "Warning",
    "rule": "Read sensitive file untrusted",
    "output": "Sensitive file opened — user=root program=cat",
    "output_fields": {
        "proc.pid": 4242,
        "proc.ppid": 1001,
        "proc.name": "cat",
        "proc.cmdline": "cat /etc/shadow",
        "user.name": "root",
        "fd.name": "/etc/shadow",
        "container.id": "host",
    },
    "tags": ["filesystem", "mitre_credential_access", "T1552.001"],
})


def test_parse_event_extracts_promoted_fields():
    p = parse_event(_FALCO_EVENT_JSON)
    assert p["falco_rule"] == "Read sensitive file untrusted"
    assert p["falco_priority"] == "Warning"
    assert p["pid"] == 4242
    assert p["ppid"] == 1001
    assert p["name"] == "cat"
    assert p["cmdline"] == "cat /etc/shadow"
    assert p["username"] == "root"
    assert p["path"] == "/etc/shadow"
    assert p["container_id"] == "host"
    assert p["mitre"] == "T1552.001"
    assert p["falco_ts"] is not None


def test_parse_event_handles_dict_input():
    """parse_event accepts already-parsed dicts too."""
    raw = json.loads(_FALCO_EVENT_JSON)
    p = parse_event(raw)
    assert p["falco_rule"] == "Read sensitive file untrusted"


def test_parse_event_returns_none_for_blank():
    assert parse_event("") is None
    assert parse_event("   ") is None


def test_parse_event_returns_none_for_non_json():
    assert parse_event("this is not json") is None


def test_parse_event_skips_status_lines():
    """Falco emits status events (no 'rule' field) for hot-reload and
    startup. The parser must skip these silently."""
    status = json.dumps({
        "time": "2026-05-25T13:00:00Z",
        "type": "Notification",
        "message": "Falco started",
    })
    assert parse_event(status) is None


def test_parse_event_truncates_huge_output():
    huge = "x" * 20_000
    ev_dict = {
        "time": "2026-05-25T13:00:00Z",
        "priority": "Warning",
        "rule": "Test",
        "output": huge,
        "output_fields": {"proc.cmdline": huge},
        "tags": [],
    }
    p = parse_event(json.dumps(ev_dict))
    assert "<truncated>" in p["falco_output"]
    assert "<truncated>" in p["cmdline"]


# ---- ingest_file ---- #


def _write_ndjson(tmp_path, events):
    p = tmp_path / "falco.ndjson"
    p.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return p


def _ev(rule, priority="Warning", *, pid=1234, ts="2026-05-25T13:00:00Z",
        tags=None, **extra):
    base = {
        "time": ts, "priority": priority, "rule": rule,
        "output": f"Falco event: {rule}",
        "output_fields": {
            "proc.pid": pid, "proc.name": "cat",
            "proc.cmdline": "cat /etc/shadow",
            **extra,
        },
        "tags": tags or [],
    }
    return base


def test_ingest_file_basic(tmp_path):
    log = _write_ndjson(tmp_path, [
        _ev("Read sensitive file untrusted"),
        _ev("Shell in container"),
    ])
    store = EvidenceStore(tmp_path / "case")
    summary = ingest_file(log, store)
    assert isinstance(summary, FalcoIngestSummary)
    assert summary.events_total == 2
    assert summary.events_emitted == 2
    arts = list(store.iter_artifacts())
    assert len(arts) == 2
    # Findings also emitted (one per event)
    findings = list(store.iter_findings())
    assert len(findings) == 2
    assert all(f["detector"] == "falco" for f in findings)
    store.close()


def test_ingest_file_emits_findings_with_correct_severity(tmp_path):
    log = _write_ndjson(tmp_path, [
        _ev("Crit rule", priority="Critical"),
        _ev("Warn rule", priority="Warning"),
        _ev("Info rule", priority="Info"),
    ])
    store = EvidenceStore(tmp_path / "case")
    ingest_file(log, store)
    sev_by_rule = {f["title"]: f["severity"]
                   for f in store.iter_findings()}
    assert sev_by_rule["Falco: Crit rule"] == "critical"
    assert sev_by_rule["Falco: Warn rule"] == "high"
    assert sev_by_rule["Falco: Info rule"] == "low"
    store.close()


def test_ingest_file_promotes_mitre_to_finding(tmp_path):
    log = _write_ndjson(tmp_path, [
        _ev("Read sensitive file untrusted",
            tags=["filesystem", "T1552.001"]),
    ])
    store = EvidenceStore(tmp_path / "case")
    ingest_file(log, store)
    f = next(iter(store.iter_findings()))
    assert f["mitre"] == "T1552.001"
    store.close()


def test_ingest_file_priorities_filter(tmp_path):
    log = _write_ndjson(tmp_path, [
        _ev("A", priority="Critical"),
        _ev("B", priority="Warning"),
        _ev("C", priority="Info"),
    ])
    store = EvidenceStore(tmp_path / "case")
    summary = ingest_file(log, store, priorities=["critical"])
    assert summary.events_emitted == 1
    assert summary.events_skipped == 2
    store.close()


def test_ingest_file_rules_filter(tmp_path):
    log = _write_ndjson(tmp_path, [
        _ev("Read sensitive file untrusted"),
        _ev("Shell in container"),
        _ev("Outbound TCP connection"),
    ])
    store = EvidenceStore(tmp_path / "case")
    summary = ingest_file(log, store,
                            rules=["Read sensitive file untrusted",
                                    "Shell in container"])
    assert summary.events_emitted == 2
    assert summary.events_skipped == 1
    store.close()


def test_ingest_file_time_window_filter(tmp_path):
    log = _write_ndjson(tmp_path, [
        _ev("a", ts="2023-01-01T00:00:00Z"),
        _ev("b", ts="2024-06-15T12:00:00Z"),
        _ev("c", ts="2030-01-01T00:00:00Z"),
    ])
    store = EvidenceStore(tmp_path / "case")
    summary = ingest_file(
        log, store,
        after_ts=1_577_836_800.0,    # 2020-01-01
        before_ts=1_735_689_600.0,   # 2025-01-01
    )
    assert summary.events_emitted == 2  # 2023 + 2024
    assert summary.events_skipped == 1
    store.close()


def test_ingest_file_limit(tmp_path):
    log = _write_ndjson(tmp_path, [_ev(f"rule-{i}") for i in range(10)])
    store = EvidenceStore(tmp_path / "case")
    summary = ingest_file(log, store, limit=4)
    assert summary.events_emitted == 4
    store.close()


def test_ingest_file_missing_log_raises(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        with pytest.raises(FalcoError, match="not found"):
            ingest_file(tmp_path / "does-not-exist.ndjson", store)
    finally:
        store.close()


def test_ingest_file_skips_unparseable_lines(tmp_path):
    """Falco logs can include log lines from other sources or
    corrupted entries — the parser should skip non-JSON / non-event
    lines silently."""
    p = tmp_path / "falco.ndjson"
    p.write_text(
        "Falco starting up...\n"
        + json.dumps(_ev("good rule")) + "\n"
        + "garbage line\n"
        + json.dumps(_ev("another")) + "\n"
    )
    store = EvidenceStore(tmp_path / "case")
    summary = ingest_file(p, store)
    assert summary.events_total == 4   # all 4 lines counted
    assert summary.events_emitted == 2   # only the 2 valid events
    assert summary.events_skipped == 2
    store.close()


def test_ingest_file_oversize_cap(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "digger.falco.runner._MAX_FALCO_LOG_BYTES", 100,
    )
    big = tmp_path / "big.ndjson"
    big.write_bytes(b"\x00" * 200)
    store = EvidenceStore(tmp_path / "case")
    try:
        with pytest.raises(FalcoError, match="bytes"):
            ingest_file(big, store)
    finally:
        store.close()


def test_ingest_file_artifact_data_includes_promoted_fields(tmp_path):
    """The Artifact's data must carry the promoted top-level fields
    the storyline walker reads (pid, path, host, name, etc.)."""
    log = _write_ndjson(tmp_path, [_ev(
        "Read sensitive file untrusted",
        pid=4242, **{"fd.name": "/etc/shadow", "user.name": "root"},
    )])
    store = EvidenceStore(tmp_path / "case")
    ingest_file(log, store)
    art = next(iter(store.iter_artifacts()))
    assert art["data"]["pid"] == 4242
    assert art["data"]["path"] == "/etc/shadow"
    assert art["data"]["username"] == "root"
    store.close()


# ---- stream_events (Linux-only) ---- #


def test_stream_events_refuses_on_non_linux(monkeypatch, tmp_path):
    """On non-Linux platforms, stream_events must raise immediately
    with a clean error pointing at ingest mode."""
    monkeypatch.setattr("sys.platform", "darwin")
    store = EvidenceStore(tmp_path / "case")
    try:
        with pytest.raises(FalcoError, match="requires Linux"):
            stream_events(store)
    finally:
        store.close()


def test_stream_events_refuses_when_no_binary(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.delenv("DIGGER_FALCO_BIN", raising=False)
    monkeypatch.setattr(
        "digger.falco.runner.shutil.which", lambda name: None,
    )
    store = EvidenceStore(tmp_path / "case")
    try:
        with pytest.raises(FalcoError, match="no falco binary"):
            stream_events(store)
    finally:
        store.close()


# ---- CLI smoke ---- #


def test_cli_falco_ingest_end_to_end(tmp_path):
    """Build a small NDJSON log + ingest via the CLI."""
    log = _write_ndjson(tmp_path, [
        _ev("Read sensitive file untrusted", priority="Warning"),
        _ev("Shell in container", priority="Critical"),
    ])
    case = tmp_path / "case"
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "falco", "ingest",
         "--case-dir", str(case),
         "--log", str(log)],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert "2 emitted" in r.stdout


def test_cli_falco_ingest_missing_log():
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "falco", "ingest",
         "--case-dir", "/tmp/nope",
         "--log", "/does/not/exist.ndjson"],
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 2
    assert "not found" in r.stderr


def test_cli_falco_stream_refuses_on_macos(monkeypatch):
    """Smoke-test only meaningful on non-Linux (which our test host is)."""
    if sys.platform == "linux":
        pytest.skip("test only meaningful on non-Linux hosts")
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "falco", "stream",
         "--case-dir", "/tmp/nope"],
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 2
    assert "requires Linux" in r.stderr
