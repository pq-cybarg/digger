"""Every Decepticon-countermeasure detector must ship a Sigma template
that round-trips cleanly through ``digger.exchange.sigma.SigmaLoader``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from digger.detectors import all_detectors
from digger.exchange.sigma import SigmaLoader
from digger.genrule import generate_detector_templates, write_sigma_rules


# These are the detectors built in tasks #53-#62 that the user's "every new
# detector ships SIEM-deployable" requirement applies to.
_REQUIRED_DETECTORS = {
    "recon", "exploitation", "privesc", "lateral", "ad_attacks",
    "cloud_attacks", "counter_re", "persistent_sessions",
    "attacker_tooling",
}

# Foundational detectors that also have clean Sigma mappings — added as
# the per-detector template surface expanded post-v0.1.0.
_ALSO_REQUIRED = {
    "lolbins", "suspicious_processes", "c2", "env_hijack",
}


def test_every_required_detector_implements_to_sigma_template():
    impl = {d.name for d in all_detectors() if d.to_sigma_template() is not None}
    missing = _REQUIRED_DETECTORS - impl
    assert not missing, f"detectors missing to_sigma_template(): {missing}"


def test_foundational_detectors_also_have_templates():
    """Beyond the 9 Decepticon countermeasures, the foundational
    detectors with clean Sigma mappings should ship templates too —
    so `digger generate sigma --from-detectors` covers the full
    SIEM-deployable surface, not just the counter-offensive subset."""
    impl = {d.name for d in all_detectors() if d.to_sigma_template() is not None}
    missing = _ALSO_REQUIRED - impl
    assert not missing, (
        f"foundational detectors missing to_sigma_template(): {missing}"
    )


def test_generate_detector_templates_returns_valid_dicts():
    rules = generate_detector_templates()
    assert rules, "generate_detector_templates() returned nothing"
    for rule in rules:
        for k in ("title", "id", "logsource", "detection"):
            assert k in rule, f"rule {rule.get('id')} missing required field {k}"
        assert "condition" in rule["detection"], (
            f"rule {rule.get('id')} has no condition")
        # Detection must be a dict of selection blocks
        assert isinstance(rule["detection"], dict)


def test_templates_round_trip_through_sigma_loader(tmp_path):
    out_dir = tmp_path / "templates"
    rules = generate_detector_templates()
    written = write_sigma_rules(rules, out_dir)
    assert len(written) == len(rules)

    loaded = SigmaLoader([out_dir]).load()
    loaded_titles = {r.title for r in loaded}
    written_titles = {r["title"] for r in rules}
    assert written_titles == loaded_titles, (
        "round-trip lost rules. emitted=" + str(written_titles - loaded_titles)
        + " loaded_only=" + str(loaded_titles - written_titles))
    # Each loaded rule must have a detection block + tags.
    for r in loaded:
        assert r.detection, f"{r.title} has empty detection"
        # Tags optional but every Decepticon-countermeasure rule should
        # carry at least one attack.* tag
        if r.id.startswith("digger-") and r.id.endswith("-template"):
            attack_tags = [t for t in r.tags if t.startswith("attack.")]
            assert attack_tags, (
                f"{r.title} ({r.id}) is missing attack.* MITRE tags")


def test_cli_from_detectors_flag(tmp_path):
    """Smoke-test the CLI path via subprocess."""
    import subprocess, sys as _sys
    out_dir = tmp_path / "cli_out"
    r = subprocess.run(
        [_sys.executable, "-m", "digger", "--no-banner",
         "generate", "sigma", "--from-detectors",
         "--out-dir", str(out_dir)],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert out_dir.is_dir()
    yml_count = sum(1 for _ in out_dir.glob("*.yml"))
    assert yml_count >= len(_REQUIRED_DETECTORS), (
        f"expected at least {len(_REQUIRED_DETECTORS)} files, got {yml_count}")


def test_default_to_sigma_template_returns_none():
    """Detectors that don't override return None; the generator skips them."""
    from digger.detectors.timeline import TimelineBuilder
    assert TimelineBuilder().to_sigma_template() is None
