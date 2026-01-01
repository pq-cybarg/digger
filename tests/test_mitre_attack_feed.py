"""MITRE ATT&CK STIX 2.1 → actors-list pipeline + detector integration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.threat_actor import ThreatActorDetector
from digger.intel import feeds as feeds_mod
from digger.intel.sources import mitre_attack


def _point_intel_dir(monkeypatch, root):
    monkeypatch.setattr(feeds_mod, "intel_dir", lambda: root)
    monkeypatch.setenv("DIGGER_INTEL_NO_VERIFY", "1")
    from digger.detectors import _rules_io
    _rules_io._reset_intel_verdict_for_tests()


# ---- registry ---- #


def test_mitre_attack_feed_registered():
    f = [x for x in feeds_mod.FEEDS if x.name == "mitre_attack_groups"]
    assert len(f) == 1
    assert f[0].fetch_fn is not None
    # Weekly cadence (ATT&CK ships ~quarterly major)
    assert f[0].interval >= 24 * 3600


# ---- parser ---- #


def _stix_bundle():
    """Minimal STIX 2.1 bundle: one group using one tool + one technique."""
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--apt99",
                "name": "APT99",
                "aliases": ["APT99", "FakeKitten"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G9999"}
                ],
            },
            {
                "type": "tool",
                "id": "tool--frobulator",
                "name": "frobulator",
                "aliases": ["frobby"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "S9999"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--reflective",
                "name": "Reflective Code Loading",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1620"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--g99-uses-tool",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt99",
                "target_ref": "tool--frobulator",
            },
            {
                "type": "relationship",
                "id": "relationship--g99-uses-tech",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt99",
                "target_ref": "attack-pattern--reflective",
            },
        ],
    }


def test_parse_bundle_produces_actor_with_software_and_techniques():
    actors = mitre_attack.parse_bundle(_stix_bundle())
    assert len(actors) == 1
    a = actors[0]
    assert a["attack_group_id"] == "G9999"
    assert a["primary_name"] == "APT99"
    assert "FakeKitten" in a["aliases"]
    # Software → proc_patterns
    pats = " ".join(a["proc_patterns"])
    assert "frobulator" in pats
    assert "frobby" in pats
    assert a["techniques"][0]["id"] == "T1620"
    assert a["software"][0]["name"] == "frobulator"
    assert a["mitre"] == "T1620"


def test_parse_skips_revoked_and_deprecated():
    bundle = _stix_bundle()
    bundle["objects"][0]["revoked"] = True
    assert mitre_attack.parse_bundle(bundle) == []


def test_proc_pattern_word_boundary_escaping():
    actors = mitre_attack.parse_bundle(_stix_bundle())
    pat = actors[0]["proc_patterns"][0]
    # word-boundary regex around the literal
    assert pat.startswith(r"\b")
    assert pat.endswith(r"\b")


def test_generic_names_excluded():
    """A tool literally named "PowerShell" should NOT be turned into a proc_pattern."""
    bundle = _stix_bundle()
    bundle["objects"].append({
        "type": "tool",
        "id": "tool--powershell",
        "name": "PowerShell",
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "S0194"}
        ],
    })
    bundle["objects"].append({
        "type": "relationship",
        "id": "relationship--apt99-uses-powershell",
        "relationship_type": "uses",
        "source_ref": "intrusion-set--apt99",
        "target_ref": "tool--powershell",
    })
    a = mitre_attack.parse_bundle(bundle)[0]
    pats = " ".join(a["proc_patterns"]).lower()
    assert "powershell" not in pats


# ---- detector consumes live feed ---- #


def test_detector_uses_live_feed_before_bundled(tmp_path, monkeypatch):
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    _point_intel_dir(monkeypatch, intel_dir)

    # Plant a live MITRE feed payload
    payload = {
        "source": "mitre/attack",
        "fetched_at": 0,
        "actor_count": 1,
        "actors": [{
            "name": "Synthetic APT-LIVE",
            "primary_name": "Synthetic APT-LIVE",
            "severity": "high",
            "attack_group_id": "G9001",
            "aliases": [],
            "proc_patterns": [r"\bsynthetic_payload_xyz\b"],
            "techniques": [{"id": "T1059", "name": "Command Scripting Interpreter"}],
            "software": [{"id": "S9001", "name": "synthetic_payload_xyz",
                          "type": "tool", "aliases": []}],
            "mitre": "T1059",
            "notes": "test live entry",
        }],
    }
    (intel_dir / "mitre_attack_groups.json").write_text(json.dumps(payload))

    store = EvidenceStore(tmp_path / "evidence.db")
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=100 myproc",
        data={"pid": 100, "ppid": 1, "name": "myproc", "exe": "/usr/bin/myproc",
              "cmdline": ["myproc", "--run", "synthetic_payload_xyz"]},
    ))

    findings = list(ThreatActorDetector().detect(store))
    live = [f for f in findings if "Synthetic APT-LIVE" in f.title]
    assert live, [f.title for f in findings]
    assert "T1059" in (live[0].mitre or "")
    store.close()


def test_detector_falls_back_to_bundled_when_no_live_feed(tmp_path, monkeypatch):
    empty_intel = tmp_path / "empty_intel"
    empty_intel.mkdir()
    _point_intel_dir(monkeypatch, empty_intel)

    store = EvidenceStore(tmp_path / "evidence.db")
    # APT29 signature: vssadmin delete shadows
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=200 cmd.exe",
        data={"pid": 200, "ppid": 1, "name": "cmd.exe", "exe": "C:\\Windows\\cmd.exe",
              "cmdline": ["cmd.exe", "/c", "vssadmin delete shadows /all /quiet"]},
    ))

    findings = list(ThreatActorDetector().detect(store))
    # Should match the bundled APT29 entry
    apt29 = [f for f in findings if "APT29" in f.title]
    assert apt29, [f.title for f in findings]
    store.close()
