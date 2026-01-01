"""shai_hulud detector: live-feed markers override bundled."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.shai_hulud import ShaiHuludDetector, _normalize_compromised
from digger.intel import feeds as feeds_mod
from digger.intel.sources import shai_hulud as sh_src


def _point_intel_dir(monkeypatch, root):
    monkeypatch.setattr(feeds_mod, "intel_dir", lambda: root)
    monkeypatch.setenv("DIGGER_INTEL_NO_VERIFY", "1")
    from digger.detectors import _rules_io
    _rules_io._reset_intel_verdict_for_tests()


# ---- parser ---- #


def test_parser_handles_aikido_modern_schema():
    raw = json.dumps({
        "compromised_packages": [
            "evil-pkg@1.0.0",
            {"name": "wormy", "version": "2.0.0"},
            "any-version-evil@*",
        ],
        "worm_unambiguous_markers": ["shai-hulud-workflow",
                                       "Shai-Hulud Migration"],
        "worm_suggestive_markers": ["trufflehog"],
        "worm_webhook_patterns": [r"webhook\.site/[a-f0-9-]{30,}"],
        "worm_workflow_filename": "shai-hulud-workflow.yml",
    }).encode()
    parsed = sh_src.parse_iocs(raw)
    assert "evil-pkg@1.0.0" in parsed["compromised_packages"]
    assert "wormy@2.0.0" in parsed["compromised_packages"]
    assert "any-version-evil@*" in parsed["compromised_packages"]
    assert parsed["worm_unambiguous_markers"] == [
        "shai-hulud-workflow", "Shai-Hulud Migration"]
    assert parsed["worm_suggestive_markers"] == ["trufflehog"]
    assert parsed["worm_workflow_filename"] == "shai-hulud-workflow.yml"


def test_parser_handles_legacy_packages_array_only():
    """An old snapshot that's just a flat list still works."""
    raw = json.dumps(["evil-pkg@1.0.0", "wormy@*"]).encode()
    parsed = sh_src.parse_iocs(raw)
    assert "evil-pkg@1.0.0" in parsed["compromised_packages"]
    assert "wormy@*" in parsed["compromised_packages"]


def test_parser_handles_nested_iocs_envelope():
    raw = json.dumps({
        "iocs": {
            "compromised_packages": ["nested@1.0"],
            "self_replicating_repo_names": ["shai-hulud"],
        },
    }).encode()
    parsed = sh_src.parse_iocs(raw)
    assert "nested@1.0" in parsed["compromised_packages"]
    assert "shai-hulud" in parsed["worm_artifact_repos"]


# ---- normalizer: live markers win ---- #


def test_live_markers_override_bundled():
    bundled = {
        "compromised_packages": ["bundled-only@1"],
        "worm_unambiguous_markers": ["bundled-strong"],
        "worm_suggestive_markers": ["bundled-weak"],
        "worm_webhook_patterns": [r"bundled\.example/abc"],
        "worm_workflow_filename": "bundled-workflow.yml",
    }
    live = {
        "compromised_packages": ["live-only@2"],
        "worm_unambiguous_markers": ["live-strong-marker"],
        "worm_suggestive_markers": ["live-weak"],
        "worm_webhook_patterns": [r"live\.example/xyz"],
        "worm_workflow_filename": "live-workflow.yml",
    }
    exact, wild, webhook, unamb, sugg, filename = _normalize_compromised(bundled, live)
    assert exact == {"live-only@2"}
    assert unamb == ["live-strong-marker"]
    assert sugg == ["live-weak"]
    assert filename == "live-workflow.yml"
    # Webhook regex compiled from live string (dot is escaped in pattern)
    assert any(r"live\.example" in r.pattern for r in webhook)
    assert not any(r"bundled\.example" in r.pattern for r in webhook)


def test_bundled_used_when_live_marker_tier_missing():
    """When a live tier is missing/empty, that specific tier falls back."""
    bundled = {
        "compromised_packages": ["bundled@1"],
        "worm_unambiguous_markers": ["bundled-strong"],
        "worm_suggestive_markers": ["bundled-weak"],
    }
    # Live has packages but no marker tiers
    live = {"compromised_packages": ["live@2"]}
    exact, wild, webhook, unamb, sugg, filename = _normalize_compromised(bundled, live)
    assert exact == {"live@2"}
    assert unamb == ["bundled-strong"]
    assert sugg == ["bundled-weak"]


def test_no_intel_at_all_falls_back_entirely():
    bundled = {
        "compromised_packages": ["bundled@1"],
        "worm_unambiguous_markers": ["b-strong"],
    }
    exact, wild, webhook, unamb, sugg, filename = _normalize_compromised(bundled, None)
    assert exact == {"bundled@1"}
    assert unamb == ["b-strong"]


# ---- end-to-end: detector consumes live markers ---- #


def test_detector_fires_on_live_only_package(tmp_path, monkeypatch):
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    _point_intel_dir(monkeypatch, intel_dir)

    payload = {
        "source": "aikido-shai-hulud",
        "compromised_packages": ["live-worm-pkg@1.2.3"],
        "worm_unambiguous_markers": [],
        "worm_suggestive_markers": [],
        "worm_webhook_patterns": [],
        "raw": {},
    }
    (intel_dir / "shai_hulud_packages.json").write_text(json.dumps(payload))

    store = EvidenceStore(tmp_path / "evidence.db")
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:victim-app",
        data={"project": "victim-app",
              "locked_packages": {"live-worm-pkg": "1.2.3"}},
    ))

    findings = list(ShaiHuludDetector().detect(store))
    hits = [f for f in findings if "live-worm-pkg" in f.title]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    store.close()
