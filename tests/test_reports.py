"""Report renderers produce valid output even on an empty store."""

from __future__ import annotations

import json
from pathlib import Path

from digger.core import Artifact, EvidenceStore, Finding
from digger.report import render_html, render_json, render_markdown


def _populated_store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path)
    store.set_meta("case_id", "case-test-1")
    store.set_meta("host", {"os": "macos", "node": "test-host", "release": "25.1"})
    store.add_artifact(Artifact(collector="processes", category="process",
                                subject="pid=1 init", data={"pid": 1, "name": "init"}))
    store.add_finding(Finding(detector="test", severity="medium",
                              title="example finding", summary="example summary"))
    return store


def test_json_report_parses(tmp_path: Path):
    store = _populated_store(tmp_path)
    out = render_json(store)
    parsed = json.loads(out)
    assert parsed["case_id"] == "case-test-1"
    assert parsed["counts"]["findings"] == 1
    store.close()


def test_markdown_report_contains_expected(tmp_path: Path):
    store = _populated_store(tmp_path)
    out = render_markdown(store)
    assert "digger forensic report" in out
    assert "example finding" in out
    store.close()


def test_html_report_contains_logo_and_finding(tmp_path: Path):
    store = _populated_store(tmp_path)
    out = render_html(store)
    assert "<svg" in out
    assert "DIGGER" in out
    assert "example finding" in out
    store.close()
