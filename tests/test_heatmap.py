"""ATT&CK coverage heatmap — derived from detector tags."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from digger.genrule.heatmap import (
    ATTACK_TACTICS,
    TACTIC_SLUGS,
    _density_class,
    _load_bundled_tactic_map,
    _tactic_slug_from_tag,
    _technique_from_tag,
    build_coverage,
    render_html,
    render_json,
    render_text,
    write_heatmap,
)


# ---- tag parsing ------------------------------------------------------ #


def test_tactic_slug_underscore_to_kebab():
    assert _tactic_slug_from_tag("attack.defense_evasion") == "defense-evasion"
    assert _tactic_slug_from_tag("attack.privilege_escalation") == "privilege-escalation"
    assert _tactic_slug_from_tag("attack.lateral_movement") == "lateral-movement"
    assert _tactic_slug_from_tag("attack.command_and_control") == "command-and-control"


def test_tactic_slug_unknown_returns_none():
    assert _tactic_slug_from_tag("attack.t1059") is None
    assert _tactic_slug_from_tag("not.a.tag") is None
    assert _tactic_slug_from_tag("") is None


def test_technique_from_tag_basic():
    assert _technique_from_tag("attack.t1059") == "T1059"
    assert _technique_from_tag("attack.t1059.001") == "T1059.001"
    assert _technique_from_tag("attack.t1195.002") == "T1195.002"


def test_technique_from_tag_rejects_non_technique():
    assert _technique_from_tag("attack.defense_evasion") is None
    assert _technique_from_tag("attack.t999") is None  # too short
    assert _technique_from_tag("") is None


# ---- tactic map ------------------------------------------------------- #


def test_bundled_tactic_map_loads_and_has_entries():
    m = _load_bundled_tactic_map()
    assert isinstance(m, dict)
    # Must contain core techniques our detectors emit
    for tid in ("T1059", "T1190", "T1070", "T1086", "T1486", "T1561",
                "T1041", "T1567", "T1572", "T1490", "T1489"):
        # T1086 is the only deprecated one — skip
        if tid == "T1086":
            continue
        assert tid in m, f"missing technique mapping: {tid}"


def test_tactic_map_values_are_known_tactics():
    m = _load_bundled_tactic_map()
    for tid, tactics in m.items():
        assert isinstance(tactics, list), tid
        for t in tactics:
            assert t in TACTIC_SLUGS, f"{tid} maps to unknown tactic {t!r}"


# ---- coverage build --------------------------------------------------- #


def test_build_coverage_shape():
    cov = build_coverage()
    assert set(cov.keys()) == {"detectors", "techniques", "tactics", "summary"}
    # Detectors keyed by name
    for name, info in cov["detectors"].items():
        assert isinstance(name, str)
        assert "sigma_template_present" in info
        assert "tags" in info
    # Techniques keyed by T####
    for tid, info in cov["techniques"].items():
        assert tid.startswith("T")
        assert isinstance(info["tactics"], list)
        assert isinstance(info["detectors"], list)
    # Tactics keyed by canonical slug, all 14 present
    assert list(cov["tactics"].keys()) == TACTIC_SLUGS


def test_summary_self_consistent():
    cov = build_coverage()
    s = cov["summary"]
    assert s["detectors_total"] == len(cov["detectors"])
    assert s["techniques_covered"] == len(cov["techniques"])
    template_count = sum(
        1 for d in cov["detectors"].values() if d["sigma_template_present"]
    )
    assert s["detectors_with_template"] == template_count
    tactics_with_cov = sum(
        1 for slug in TACTIC_SLUGS if cov["tactics"][slug]["technique_ids"]
    )
    assert s["tactics_covered"] == tactics_with_cov


def test_full_kill_chain_coverage_present():
    """With the 12 Decepticon countermeasures complete, we should cover
    at least 12 of the 14 tactics."""
    cov = build_coverage()
    assert cov["summary"]["tactics_covered"] >= 12


def test_impact_detector_appears_in_impact_tactic():
    cov = build_coverage()
    impact = cov["tactics"]["impact"]
    assert impact["technique_ids"], "impact tactic has no techniques"
    # ImpactDetector must be a covering detector for at least one impact tactic
    covering = set()
    for tid in impact["technique_ids"]:
        covering.update(cov["techniques"][tid]["detectors"])
    assert "impact" in covering


def test_exfiltration_detector_covers_exfil_tactic():
    cov = build_coverage()
    exfil = cov["tactics"]["exfiltration"]
    covering = set()
    for tid in exfil["technique_ids"]:
        covering.update(cov["techniques"][tid]["detectors"])
    assert "exfiltration" in covering


def test_anti_forensics_covers_defense_evasion():
    cov = build_coverage()
    de = cov["tactics"]["defense-evasion"]
    covering = set()
    for tid in de["technique_ids"]:
        covering.update(cov["techniques"][tid]["detectors"])
    assert "anti_forensics" in covering


def test_trapdoor_covers_initial_access():
    cov = build_coverage()
    ia = cov["tactics"]["initial-access"]
    covering = set()
    for tid in ia["technique_ids"]:
        covering.update(cov["techniques"][tid]["detectors"])
    assert "trapdoor" in covering


# ---- renderers -------------------------------------------------------- #


def test_render_text_lists_every_tactic():
    cov = build_coverage()
    out = render_text(cov)
    for slug, label in ATTACK_TACTICS:
        assert label in out, f"missing tactic in text render: {label}"
    assert "SUMMARY:" in out
    assert f"{cov['summary']['detectors_total']} detectors" in out


def test_render_json_parses_roundtrip():
    cov = build_coverage()
    out = render_json(cov)
    reparsed = json.loads(out)
    assert reparsed["summary"] == cov["summary"]
    # Sorted-keys means output is deterministic for the same input
    assert render_json(cov) == render_json(cov)


def test_render_html_emits_self_contained_doc():
    cov = build_coverage()
    out = render_html(cov)
    assert out.startswith("<!doctype html>")
    assert "</html>" in out
    assert "<style>" in out  # CSS inlined, not external
    # Every tactic header present
    for _, label in ATTACK_TACTICS:
        assert label in out
    # Legend present
    assert "uncovered" in out
    assert "1 detector" in out


def test_density_class_thresholds():
    assert _density_class(0) == "cov0"
    assert _density_class(1) == "cov1"
    assert _density_class(2) == "cov2"
    assert _density_class(3) == "cov3"
    assert _density_class(10) == "cov3"


# ---- write_heatmap ---------------------------------------------------- #


@pytest.mark.parametrize("fmt", ["text", "json", "html"])
def test_write_heatmap_creates_file(tmp_path, fmt):
    cov = build_coverage()
    suffix = "json" if fmt == "json" else "html" if fmt == "html" else "txt"
    out_path = tmp_path / f"cov.{suffix}"
    written = write_heatmap(cov, fmt=fmt, out_path=out_path)
    assert written == out_path
    assert out_path.exists()
    assert out_path.stat().st_size > 100


def test_write_heatmap_unknown_format(tmp_path):
    with pytest.raises(ValueError):
        write_heatmap({}, fmt="xml", out_path=tmp_path / "x.xml")


# ---- CLI smoke ------------------------------------------------------- #


def test_cli_generate_heatmap_text(tmp_path):
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "generate", "heatmap", "--format", "text"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert "MITRE ATT&CK coverage" in r.stdout
    assert "SUMMARY:" in r.stdout


def test_cli_generate_heatmap_json(tmp_path):
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "generate", "heatmap", "--format", "json"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    parsed = json.loads(r.stdout)
    assert "summary" in parsed
    assert parsed["summary"]["tactics_covered"] >= 12


def test_cli_generate_heatmap_html_writes_file(tmp_path):
    out_path = tmp_path / "cov.html"
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "generate", "heatmap", "--format", "html",
         "--out", str(out_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert out_path.exists()
    body = out_path.read_text(encoding="utf-8")
    assert "<!doctype html>" in body
    assert "Defense Evasion" in body


def test_cli_generate_heatmap_html_without_out_errors():
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "generate", "heatmap", "--format", "html"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 2
    assert "--out is required" in r.stderr
