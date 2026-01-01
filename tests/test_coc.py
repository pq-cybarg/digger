"""Chain of custody record."""

from __future__ import annotations

import json
from pathlib import Path

from digger.coc import open_custody
from digger.coc.record import append_event


def test_open_writes_record(tmp_path: Path):
    coc = open_custody(tmp_path, case_id="case-1", classification="UNCLASSIFIED", tlp="TLP:AMBER")
    f = tmp_path / "chain_of_custody.json"
    assert f.exists()
    data = json.loads(f.read_text())
    assert data["case_id"] == "case-1"
    assert data["events"], "expected at least one event"
    assert data["events"][0]["event_type"] == "case_opened"
    assert data["tlp"] == "TLP:AMBER"
    assert data["iso_27037_compliance"] is True
    assert data["nist_800_86_compliance"] is True


def test_append_event_round_trips(tmp_path: Path):
    coc = open_custody(tmp_path, case_id="case-2")
    append_event(tmp_path, coc, "scan_started", "detector run begun")
    append_event(tmp_path, coc, "scan_finished", "detector run ended")
    data = json.loads((tmp_path / "chain_of_custody.json").read_text())
    types = [e["event_type"] for e in data["events"]]
    assert "scan_started" in types
    assert "scan_finished" in types


def test_open_loads_existing_record(tmp_path: Path):
    open_custody(tmp_path, case_id="case-3", custodian_name="alice")
    again = open_custody(tmp_path, case_id="case-3")
    assert again.custodian_name == "alice"
