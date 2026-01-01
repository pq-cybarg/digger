"""Intel-exchange exporters: STIX 2.1, MISP, ATT&CK Navigator, Sigma."""

from __future__ import annotations

from pathlib import Path

from digger.core import Artifact, EvidenceStore, Finding
from digger.exchange import (
    SigmaLoader, sigma_detect, to_misp_event, to_navigator_layer, to_stix_bundle,
)


def _populated_store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path)
    store.set_meta("case_id", "case-test-1")
    store.set_meta("host", {"node": "tst", "os": "macos"})
    store.add_artifact(Artifact(collector="processes", category="process", subject="pid=1",
                                data={"pid": 1, "name": "init"}))
    f = Finding(
        detector="c2", severity="critical",
        title="example",
        summary="x",
        mitre="T1071.001",
        evidence={"iocs": {"ipv4": ["1.2.3.4"], "domain": ["evil.test"]}},
    )
    store.add_finding(f)
    return store


def test_stix_bundle_structure(tmp_path: Path):
    store = _populated_store(tmp_path)
    findings = list(store.iter_findings())
    bundle = to_stix_bundle(
        {"case_id": store.get_meta("case_id"), "host": store.get_meta("host")},
        findings,
    )
    assert bundle["type"] == "bundle"
    types = {o["type"] for o in bundle["objects"]}
    assert "incident" in types
    assert "indicator" in types
    assert "attack-pattern" in types
    assert "marking-definition" in types
    assert "identity" in types
    # Each indicator must carry a STIX pattern
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert all(o.get("pattern") for o in indicators)
    store.close()


def test_misp_event_emits_attributes(tmp_path: Path):
    store = _populated_store(tmp_path)
    findings = list(store.iter_findings())
    event = to_misp_event(
        {"case_id": store.get_meta("case_id"), "host": store.get_meta("host")},
        findings,
    )
    attrs = event["Event"]["Attribute"]
    types = {a["type"] for a in attrs}
    assert "ip-dst" in types
    assert "domain" in types
    store.close()


def test_attack_navigator_layer(tmp_path: Path):
    store = _populated_store(tmp_path)
    findings = list(store.iter_findings())
    layer = to_navigator_layer(
        {"case_id": store.get_meta("case_id"), "host": store.get_meta("host")},
        findings,
    )
    assert layer["domain"] == "enterprise-attack"
    assert any(t["techniqueID"] == "T1071.001" for t in layer["techniques"])
    store.close()


def test_sigma_loader_does_not_crash_on_empty_dir(tmp_path: Path):
    rules = SigmaLoader(dirs=[tmp_path]).load()
    assert rules == []


def test_sigma_detect_matches_process_creation(tmp_path: Path):
    # Build a tiny on-disk sigma rule and run it.
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "ps_encoded.yml").write_text("""
title: Encoded PowerShell
id: 11111111-2222-3333-4444-555555555555
description: powershell -EncodedCommand
level: high
tags:
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: 'powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
""", encoding="utf-8")
    store = EvidenceStore(tmp_path / "case")
    store.add_artifact(Artifact(
        collector="processes", category="process", subject="pid=100",
        data={"pid": 100, "name": "powershell.exe", "exe": "C:/Windows/powershell.exe",
              "cmdline": ["powershell.exe", "-EncodedCommand", "QQBB"]},
    ))
    n = sigma_detect(store, dirs=[rules_dir])
    assert n >= 1
    findings = list(store.iter_findings())
    assert findings[0]["mitre"] == "T1059.001"
    store.close()
