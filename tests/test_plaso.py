"""Plaso .plaso ingestion bridge tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from digger.core.evidence import EvidenceStore
from digger.plaso.runner import (
    PlasoError,
    PlasoIngestSummary,
    _normalize_event,
    _ts_iso,
    _us_to_seconds,
    discover_binary,
    info,
    ingest,
)


# ---- binary discovery ---- #


def test_discover_binary_honors_env(monkeypatch, tmp_path):
    fake = tmp_path / "fake_psort"
    fake.write_text("#!/bin/sh\necho hi\n")
    fake.chmod(0o755)
    monkeypatch.setenv("DIGGER_PLASO_BIN", str(fake))
    assert discover_binary() == str(fake)


def test_discover_binary_env_missing_returns_none(monkeypatch):
    monkeypatch.setenv("DIGGER_PLASO_BIN", "/nonexistent/zzz")
    assert discover_binary() is None


def test_discover_binary_path_scan(monkeypatch):
    monkeypatch.delenv("DIGGER_PLASO_BIN", raising=False)
    monkeypatch.setattr(
        "digger.plaso.runner.shutil.which",
        lambda name: "/usr/local/bin/psort" if name == "psort" else None,
    )
    assert discover_binary() == "/usr/local/bin/psort"


def test_discover_binary_path_scan_misses(monkeypatch):
    monkeypatch.delenv("DIGGER_PLASO_BIN", raising=False)
    monkeypatch.setattr(
        "digger.plaso.runner.shutil.which", lambda name: None,
    )
    assert discover_binary() is None


# ---- helpers ---- #


def test_us_to_seconds_round_trip():
    assert _us_to_seconds(1_000_000_000_000) == 1_000_000.0
    assert _us_to_seconds(None) is None


def test_us_to_seconds_handles_bad_input():
    assert _us_to_seconds("not a number") is None


def test_ts_iso_2024_value():
    iso = _ts_iso(1_700_000_000_000_000)  # 2023-11-14
    assert iso.startswith("2023") or iso.startswith("2024")


def test_ts_iso_handles_none_and_zero():
    assert _ts_iso(None) == "0"
    assert _ts_iso(0) == "0"


def test_normalize_event_truncates_huge_fields():
    huge = "x" * 20_000
    out = _normalize_event({"message": huge, "short": "ok"})
    assert "<truncated>" in out["message"]
    assert out["short"] == "ok"


# ---- fake psort harness ---- #


def _make_fake_psort(tmp_path, events, *, rc=0):
    """Drop a tiny fake `psort` binary that emits one JSON-line per
    event in ``events`` and exits with ``rc``."""
    fake = tmp_path / "fake_psort"
    body = "\n".join(json.dumps(e) for e in events)
    # The path of the script will be substituted; we use a heredoc-
    # style cat so the rc applies last
    script = (
        "#!/bin/sh\n"
        f"cat <<'EVENTS_EOF'\n{body}\nEVENTS_EOF\n"
        f"exit {rc}\n"
    )
    fake.write_text(script)
    fake.chmod(0o755)
    return fake


def _event(timestamp, parser, data_type, **extra):
    return {
        "__container_type__": "event",
        "__type__": "AttributeContainer",
        "timestamp": timestamp,
        "timestamp_desc": "Test",
        "source": "TEST",
        "source_long": "Test Source",
        "parser": parser,
        "data_type": data_type,
        "message": f"event from {parser}",
        **extra,
    }


# ---- info ---- #


def test_info_reports_parsers_and_data_types(monkeypatch, tmp_path):
    events = [
        _event(1_700_000_000_000_000, "chrome_history",
               "chrome:history:page_visited"),
        _event(1_700_000_001_000_000, "chrome_history",
               "chrome:history:page_visited"),
        _event(1_700_000_002_000_000, "winreg", "windows:registry:key_value"),
    ]
    fake = _make_fake_psort(tmp_path, events)
    monkeypatch.setenv("DIGGER_PLASO_BIN", str(fake))
    plaso_file = tmp_path / "fake.plaso"
    plaso_file.write_bytes(b"PLASO_FAKE")
    summary = info(plaso_file)
    assert isinstance(summary, PlasoIngestSummary)
    assert summary.events_total == 3
    assert summary.parsers_seen["chrome_history"] == 2
    assert summary.parsers_seen["winreg"] == 1
    assert summary.data_types_seen["chrome:history:page_visited"] == 2


def test_info_rejects_missing_file(monkeypatch, tmp_path):
    fake = _make_fake_psort(tmp_path, [])
    monkeypatch.setenv("DIGGER_PLASO_BIN", str(fake))
    with pytest.raises(PlasoError, match="not found"):
        info(tmp_path / "missing.plaso")


def test_info_rejects_when_no_binary(monkeypatch, tmp_path):
    monkeypatch.delenv("DIGGER_PLASO_BIN", raising=False)
    monkeypatch.setattr(
        "digger.plaso.runner.shutil.which", lambda name: None,
    )
    plaso_file = tmp_path / "x.plaso"
    plaso_file.write_bytes(b"PLASO")
    with pytest.raises(PlasoError, match="no psort"):
        info(plaso_file)


def test_info_rejects_when_file_too_large(monkeypatch, tmp_path):
    fake = _make_fake_psort(tmp_path, [])
    monkeypatch.setenv("DIGGER_PLASO_BIN", str(fake))
    monkeypatch.setattr(
        "digger.plaso.runner._MAX_PLASO_BYTES", 100,
    )
    plaso_file = tmp_path / "big.plaso"
    plaso_file.write_bytes(b"\x00" * 200)
    with pytest.raises(PlasoError, match="bytes"):
        info(plaso_file)


def test_info_skips_unparseable_lines(monkeypatch, tmp_path):
    """psort sometimes prints status lines mixed with JSON. The
    parser should skip non-JSON lines silently."""
    plaso_file = tmp_path / "x.plaso"
    plaso_file.write_bytes(b"PLASO")
    # Build the script with a status line mixed in
    fake = tmp_path / "fake_psort"
    valid = json.dumps(_event(1_700_000_000_000_000, "winreg", "x"))
    fake.write_text(
        "#!/bin/sh\n"
        "cat <<'EVENTS_EOF'\n"
        f"Processing 1234 events from /fake.plaso\n"
        f"{valid}\n"
        f"not valid json at all\n"
        f"{valid}\n"
        f"EVENTS_EOF\n"
        "exit 0\n"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("DIGGER_PLASO_BIN", str(fake))
    summary = info(plaso_file)
    assert summary.events_total == 2   # only the 2 valid JSON lines


# ---- ingest ---- #


def test_ingest_emits_one_artifact_per_event(monkeypatch, tmp_path):
    events = [
        _event(1_700_000_000_000_000, "chrome_history",
               "chrome:history:page_visited", url="https://x.example"),
        _event(1_700_000_001_000_000, "winreg",
               "windows:registry:key_value", key="HKLM\\foo"),
    ]
    fake = _make_fake_psort(tmp_path, events)
    monkeypatch.setenv("DIGGER_PLASO_BIN", str(fake))
    plaso_file = tmp_path / "fake.plaso"
    plaso_file.write_bytes(b"PLASO")
    store = EvidenceStore(tmp_path / "case")
    summary = ingest(plaso_file, store)
    assert summary.events_total == 2
    assert summary.events_emitted == 2
    assert summary.events_filtered == 0
    arts = list(store.iter_artifacts())
    assert len(arts) == 2
    by_collector = {a["collector"] for a in arts}
    assert "plaso:chrome_history" in by_collector
    assert "plaso:winreg" in by_collector
    # Subjects include ISO timestamps
    for a in arts:
        assert a["subject"].startswith("plaso:202")
    # Data has the round-tripped event
    chrome = next(a for a in arts if a["collector"] == "plaso:chrome_history")
    assert chrome["data"]["plaso_event"]["url"] == "https://x.example"
    assert chrome["category"] == "timeline"
    store.close()


def test_ingest_parser_filter_drops_others(monkeypatch, tmp_path):
    events = [
        _event(1_700_000_000_000_000, "chrome_history", "x"),
        _event(1_700_000_001_000_000, "winreg", "y"),
        _event(1_700_000_002_000_000, "syslog", "z"),
    ]
    fake = _make_fake_psort(tmp_path, events)
    monkeypatch.setenv("DIGGER_PLASO_BIN", str(fake))
    plaso_file = tmp_path / "fake.plaso"
    plaso_file.write_bytes(b"PLASO")
    store = EvidenceStore(tmp_path / "case")
    summary = ingest(plaso_file, store, parsers=["chrome_history", "winreg"])
    assert summary.events_total == 3
    assert summary.events_emitted == 2
    assert summary.events_filtered == 1
    arts = list(store.iter_artifacts())
    assert len(arts) == 2
    store.close()


def test_ingest_data_type_filter(monkeypatch, tmp_path):
    events = [
        _event(1_700_000_000_000_000, "chrome", "chrome:history:page_visited"),
        _event(1_700_000_001_000_000, "chrome", "chrome:cookie:entry"),
        _event(1_700_000_002_000_000, "chrome", "chrome:cache:entry"),
    ]
    fake = _make_fake_psort(tmp_path, events)
    monkeypatch.setenv("DIGGER_PLASO_BIN", str(fake))
    plaso_file = tmp_path / "fake.plaso"
    plaso_file.write_bytes(b"PLASO")
    store = EvidenceStore(tmp_path / "case")
    summary = ingest(plaso_file, store,
                      data_types=["chrome:history:page_visited"])
    assert summary.events_emitted == 1
    assert summary.events_filtered == 2
    store.close()


def test_ingest_time_window_filter(monkeypatch, tmp_path):
    events = [
        _event(1_700_000_000_000_000, "p", "x"),  # 2023-11-14
        _event(1_500_000_000_000_000, "p", "x"),  # 2017-07-14
        _event(1_900_000_000_000_000, "p", "x"),  # 2030-03-17
    ]
    fake = _make_fake_psort(tmp_path, events)
    monkeypatch.setenv("DIGGER_PLASO_BIN", str(fake))
    plaso_file = tmp_path / "fake.plaso"
    plaso_file.write_bytes(b"PLASO")
    store = EvidenceStore(tmp_path / "case")
    # Keep events between 2020 and 2025
    summary = ingest(
        plaso_file, store,
        after_ts=1_577_836_800.0,    # 2020-01-01
        before_ts=1_735_689_600.0,   # 2025-01-01
    )
    assert summary.events_emitted == 1
    assert summary.events_filtered == 2
    store.close()


def test_ingest_limit_caps_emissions(monkeypatch, tmp_path):
    events = [_event(1_700_000_000_000_000 + i, "p", "x")
              for i in range(20)]
    fake = _make_fake_psort(tmp_path, events)
    monkeypatch.setenv("DIGGER_PLASO_BIN", str(fake))
    plaso_file = tmp_path / "fake.plaso"
    plaso_file.write_bytes(b"PLASO")
    store = EvidenceStore(tmp_path / "case")
    summary = ingest(plaso_file, store, limit=5)
    assert summary.events_emitted == 5
    arts = list(store.iter_artifacts())
    assert len(arts) == 5
    store.close()


def test_ingest_normalizes_huge_message_fields(monkeypatch, tmp_path):
    """A 20KB message in an event should be truncated before storage."""
    huge = "x" * 20_000
    events = [_event(1_700_000_000_000_000, "p", "x", message=huge)]
    fake = _make_fake_psort(tmp_path, events)
    monkeypatch.setenv("DIGGER_PLASO_BIN", str(fake))
    plaso_file = tmp_path / "fake.plaso"
    plaso_file.write_bytes(b"PLASO")
    store = EvidenceStore(tmp_path / "case")
    summary = ingest(plaso_file, store)
    assert summary.events_emitted == 1
    arts = list(store.iter_artifacts())
    stored_msg = arts[0]["data"]["plaso_event"]["message"]
    assert "<truncated>" in stored_msg
    assert len(stored_msg) < len(huge)
    store.close()


# ---- CLI smoke ---- #


def test_cli_plaso_info_without_binary_errors(tmp_path):
    env = {k: v for k, v in os.environ.items()
           if k != "DIGGER_PLASO_BIN"}
    env["PATH"] = "/usr/local/bin"
    env["DIGGER_PLASO_BIN"] = "/nonexistent/zzz/psort"
    plaso_file = tmp_path / "x.plaso"
    plaso_file.write_bytes(b"PLASO")
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "plaso", "info", "--plaso", str(plaso_file)],
        capture_output=True, text=True, timeout=15, env=env,
    )
    assert r.returncode == 1
    assert "no psort" in r.stderr


def test_cli_plaso_ingest_end_to_end(tmp_path):
    events = [_event(1_700_000_000_000_000, "winreg", "x")]
    fake = _make_fake_psort(tmp_path, events)
    plaso_file = tmp_path / "x.plaso"
    plaso_file.write_bytes(b"PLASO")
    case = tmp_path / "case"
    env = {**os.environ, "DIGGER_PLASO_BIN": str(fake)}
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "plaso", "ingest",
         "--case-dir", str(case),
         "--plaso", str(plaso_file)],
        capture_output=True, text=True, timeout=20, env=env,
    )
    assert r.returncode == 0, r.stderr
    assert "1 emitted" in r.stdout
