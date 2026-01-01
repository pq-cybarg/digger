"""Aftermath-style storyline reconstruction tests."""

from __future__ import annotations

import json
import subprocess
import sys
import time


from digger.report.storyline import (
    WINDOW_S,
    build_storylines,
    render_storyline_html,
    render_storyline_markdown,
    render_storyline_text,
    storylines_to_json,
)


# ---- helpers ---- #


def _f(uuid, detector, sev, mitre, title, ts, evidence=None, refs=None):
    return {
        "finding_uuid": uuid,
        "detector": detector,
        "severity": sev,
        "mitre": mitre,
        "title": title,
        "ts": ts,
        "evidence": evidence or {},
        "artifact_refs": refs or [],
    }


# ---- clustering ---- #


def test_empty_findings_returns_empty():
    assert build_storylines([]) == []


def test_singleton_finding_makes_own_storyline():
    t = time.time()
    sl = build_storylines([_f("A", "lolbins", "high", "T1059",
                                "x", t)])
    assert len(sl) == 1
    assert len(sl[0].findings) == 1
    assert sl[0].label == "lolbins sequence (1 findings)"


def test_shared_pid_clusters():
    t = time.time()
    sl = build_storylines([
        _f("A", "detA", "high", "T1059", "x", t,
           evidence={"pid": 1234}),
        _f("B", "detB", "high", "T1071", "y", t + 5000,
           evidence={"pid": 1234}),
    ])
    # Same pid → single storyline, even though they're outside the
    # temporal window (5000s > WINDOW_S 600s)
    assert len(sl) == 1
    assert len(sl[0].findings) == 2


def test_shared_path_clusters():
    t = time.time()
    sl = build_storylines([
        _f("A", "yara", "high", "T1027", "x", t,
           evidence={"path": "/tmp/.malware/payload"}),
        _f("B", "loki", "high", "T1027", "y", t + 10000,
           evidence={"path": "/tmp/.malware/payload"}),
    ])
    assert len(sl) == 1


def test_shared_basename_clusters():
    t = time.time()
    sl = build_storylines([
        _f("A", "detA", "high", "T1027", "x", t,
           evidence={"path": "/tmp/foo/router_init.js"}),
        _f("B", "detB", "high", "T1027", "y", t + 10000,
           evidence={"path": "/home/user/dl/router_init.js"}),
    ])
    assert len(sl) == 1


def test_shared_host_clusters():
    t = time.time()
    sl = build_storylines([
        _f("A", "exfiltration", "high", "T1041", "x", t,
           evidence={"host": "evil.example"}),
        _f("B", "exfiltration", "high", "T1041", "y", t + 9999,
           evidence={"domain": "evil.example"}),
    ])
    assert len(sl) == 1


def test_shared_hash_clusters():
    t = time.time()
    h = "a" * 64
    sl = build_storylines([
        _f("A", "ioc", "high", "T1027", "x", t,
           evidence={"sha256": h}),
        _f("B", "detB", "high", "T1027", "y", t + 50000,
           evidence={"hash": h}),
    ])
    assert len(sl) == 1


def test_shared_campaign_clusters():
    t = time.time()
    sl = build_storylines([
        _f("A", "mini_shai_hulud", "critical", "T1195.002", "x", t,
           evidence={"campaign": "Mini Shai-Hulud"}),
        _f("B", "exfiltration", "high", "T1041", "y", t + 5000,
           evidence={"campaign": "Mini Shai-Hulud"}),
    ])
    assert len(sl) == 1
    assert sl[0].suspected_campaign == "Mini Shai-Hulud"


def test_shared_artifact_uuid_clusters():
    t = time.time()
    sl = build_storylines([
        _f("A", "detA", "high", "T1059", "x", t,
           refs=["shared-artifact"]),
        _f("B", "detB", "high", "T1071", "y", t + 80000,
           refs=["shared-artifact"]),
    ])
    assert len(sl) == 1


def test_temporal_window_clusters_no_other_overlap():
    """Two findings with no other join keys but within WINDOW_S
    still cluster — temporal proximity alone is an edge."""
    t = time.time()
    sl = build_storylines([
        _f("A", "detA", "high", "T1059", "x", t,
           evidence={"pid": 100}),
        _f("B", "detB", "high", "T1071", "y", t + 60,  # 60s apart
           evidence={"pid": 200}),
    ])
    assert len(sl) == 1


def test_unrelated_findings_dont_cluster():
    t = time.time()
    sl = build_storylines([
        _f("A", "detA", "high", "T1059", "x", t,
           evidence={"pid": 100}),
        _f("B", "detB", "high", "T1071", "y", t + WINDOW_S + 7200,
           evidence={"pid": 200}),
    ])
    assert len(sl) == 2


# ---- ranking ---- #


def test_rank_prefers_severity_and_breadth():
    t = time.time()
    # Storyline 1: 3 critical findings spanning 3 tactics
    f1 = [
        _f("A", "mini_shai_hulud", "critical", "T1195.002", "pkg", t,
           evidence={"campaign": "Mini Shai-Hulud"}),
        _f("B", "persistence", "critical", "T1543", "persist", t + 30,
           evidence={"campaign": "Mini Shai-Hulud"}),
        _f("C", "exfiltration", "high", "T1041", "c2", t + 90,
           evidence={"campaign": "Mini Shai-Hulud"}),
    ]
    # Storyline 2: 5 low findings, all same tactic (defense-evasion)
    f2 = [
        _f(f"D{i}", "anti_forensics", "low", "T1070.003",
           "history wipe", t + 20000 + i,
           evidence={"pid": 9000})
        for i in range(5)
    ]
    sl = build_storylines(f1 + f2)
    # The critical-cross-tactic chain must rank higher than the
    # 5-low-same-tactic one
    assert sl[0].suspected_campaign == "Mini Shai-Hulud"
    assert sl[0].severity_max == "critical"
    assert sl[0].rank > sl[1].rank


def test_severity_max_is_max_across_chain():
    t = time.time()
    sl = build_storylines([
        _f("A", "detA", "low", "T1059", "x", t, evidence={"pid": 1}),
        _f("B", "detB", "critical", "T1059", "y", t + 30,
           evidence={"pid": 1}),
        _f("C", "detC", "high", "T1059", "z", t + 60, evidence={"pid": 1}),
    ])
    assert len(sl) == 1
    assert sl[0].severity_max == "critical"


def test_tactics_are_union_across_chain():
    t = time.time()
    sl = build_storylines([
        _f("A", "exploitation", "high", "T1190", "x", t,
           evidence={"pid": 1}),
        _f("B", "lateral", "high", "T1021", "y", t + 30,
           evidence={"pid": 1}),
        _f("C", "impact", "critical", "T1486", "z", t + 60,
           evidence={"pid": 1}),
    ])
    assert len(sl) == 1
    s = sl[0]
    # The tactic map should resolve T1190 → initial-access, T1021 →
    # lateral-movement, T1486 → impact
    assert "initial-access" in s.tactics
    assert "lateral-movement" in s.tactics
    assert "impact" in s.tactics


# ---- primary actors / labels ---- #


def test_campaign_label_when_all_agree():
    t = time.time()
    sl = build_storylines([
        _f("A", "trapdoor", "critical", "T1195.001", "x", t,
           evidence={"campaign": "TrapDoor"}),
        _f("B", "exfiltration", "high", "T1041", "y", t + 30,
           evidence={"campaign": "TrapDoor"}),
    ])
    assert "TrapDoor" in sl[0].label


def test_no_campaign_label_when_findings_disagree():
    """Two findings with different campaigns should not get a
    suspected_campaign tag — but they may still cluster if they share
    another key."""
    t = time.time()
    sl = build_storylines([
        _f("A", "trapdoor", "critical", "T1195.001", "x", t,
           evidence={"campaign": "TrapDoor", "pid": 100}),
        _f("B", "mini_shai_hulud", "critical", "T1195.002", "y", t + 30,
           evidence={"campaign": "Mini Shai-Hulud", "pid": 100}),
    ])
    assert len(sl) == 1
    assert sl[0].suspected_campaign == ""  # disagreement → empty


# ---- renderers ---- #


def test_render_text_lists_top_storylines():
    t = time.time()
    sl = build_storylines([
        _f("A", "mini_shai_hulud", "critical", "T1195.002", "pkg", t,
           evidence={"campaign": "Mini Shai-Hulud"}),
        _f("B", "persistence", "critical", "T1543",
           "gh-token-monitor", t + 30,
           evidence={"campaign": "Mini Shai-Hulud",
                     "path": "/home/u/.config/systemd/user/gh-token-monitor.service"}),
    ])
    out = render_storyline_text(sl)
    assert "Likely event chains" in out
    assert "Mini Shai-Hulud" in out
    assert "CRITICAL" in out
    assert "persistence" in out


def test_render_text_empty_input():
    out = render_storyline_text([])
    assert "No storylines" in out


def test_render_markdown_emits_table():
    t = time.time()
    sl = build_storylines([
        _f("A", "exfiltration", "high", "T1041", "exfil", t,
           evidence={"campaign": "TrapDoor"}),
        _f("B", "exfiltration", "high", "T1041", "exfil2", t + 30,
           evidence={"campaign": "TrapDoor"}),
    ])
    md = render_storyline_markdown(sl)
    assert "## Likely event chains" in md
    assert "TrapDoor" in md
    assert "| ts |" in md


def test_render_html_is_self_contained_snippet():
    t = time.time()
    sl = build_storylines([
        _f("A", "mini_shai_hulud", "critical", "T1195.002", "p", t,
           evidence={"campaign": "Mini Shai-Hulud"}),
        _f("B", "exfiltration", "high", "T1041", "x", t + 30,
           evidence={"campaign": "Mini Shai-Hulud"}),
    ])
    out = render_storyline_html(sl)
    assert "<section class='storylines'>" in out
    assert "Mini Shai-Hulud" in out
    assert "</section>" in out


def test_render_html_handles_special_chars_safely():
    t = time.time()
    sl = build_storylines([
        _f("A", "detA", "high", "T1059", "<script>alert(1)</script>", t,
           evidence={"campaign": "<bad>", "host": "evil.com/&path"}),
    ])
    out = render_storyline_html(sl)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_storylines_to_json_roundtrip():
    t = time.time()
    sl = build_storylines([
        _f("A", "detA", "high", "T1059", "x", t,
           evidence={"campaign": "TrapDoor"}),
    ])
    j = storylines_to_json(sl)
    # JSON-safe round-trip
    serialized = json.dumps(j, default=str)
    re_parsed = json.loads(serialized)
    assert re_parsed[0]["label"] == sl[0].label
    assert re_parsed[0]["suspected_campaign"] == "TrapDoor"


# ---- HTML report integration ------------------------------------------ #


def test_html_report_includes_storyline_section_when_multiple_findings(tmp_path):
    """The html_report.render_html() must inject the storylines
    section above the controls when findings cluster meaningfully."""
    from digger.core.evidence import EvidenceStore, Finding
    from digger.report.html_report import render_html

    store = EvidenceStore(tmp_path / "ev.db")
    time.time()

    # Two findings that share a campaign — should produce a multi-
    # finding storyline that renders in the report
    store.add_finding(Finding(
        detector="mini_shai_hulud", severity="critical",
        title="Compromised npm", summary="",
        artifact_refs=[], evidence={"campaign": "Mini Shai-Hulud"},
        mitre="T1195.002",
    ))
    store.add_finding(Finding(
        detector="exfiltration", severity="high",
        title="C2 callout", summary="",
        artifact_refs=[], evidence={"campaign": "Mini Shai-Hulud",
                                      "host": "git-tanstack.com"},
        mitre="T1041",
    ))
    html = render_html(store)
    assert "Likely event chains" in html
    assert "Mini Shai-Hulud" in html
    store.close()


def test_html_report_omits_storyline_when_only_singleton_chains(tmp_path):
    """A case with one finding (or only singleton-chain findings)
    should not waste space on a storyline section."""
    from digger.core.evidence import EvidenceStore, Finding
    from digger.report.html_report import render_html

    store = EvidenceStore(tmp_path / "ev.db")
    store.add_finding(Finding(
        detector="telemetry_jammer", severity="info",
        title="DiagTrack running", summary="",
        artifact_refs=[], evidence={"service": "DiagTrack"},
        mitre="T1059.001",
    ))
    html = render_html(store)
    # The storyline header should NOT appear
    assert "Likely event chains" not in html
    store.close()


# ---- CLI smoke ------------------------------------------------------- #


def test_cli_storyline_text(tmp_path):
    from digger.core.evidence import EvidenceStore, Finding
    store = EvidenceStore(tmp_path)
    store.add_finding(Finding(
        detector="mini_shai_hulud", severity="critical",
        title="Compromised npm", summary="",
        artifact_refs=[], evidence={"campaign": "Mini Shai-Hulud"},
        mitre="T1195.002",
    ))
    store.add_finding(Finding(
        detector="exfiltration", severity="high",
        title="C2 callout", summary="",
        artifact_refs=[], evidence={"campaign": "Mini Shai-Hulud"},
        mitre="T1041",
    ))
    store.close()
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "storyline", "--case-dir", str(tmp_path),
         "--format", "text"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert "Likely event chains" in r.stdout
    assert "Mini Shai-Hulud" in r.stdout


def test_cli_storyline_json(tmp_path):
    from digger.core.evidence import EvidenceStore, Finding
    store = EvidenceStore(tmp_path)
    store.add_finding(Finding(
        detector="trapdoor", severity="critical",
        title="x", summary="",
        artifact_refs=[], evidence={"campaign": "TrapDoor"},
        mitre="T1195.001",
    ))
    store.close()
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "storyline", "--case-dir", str(tmp_path),
         "--format", "json"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    parsed = json.loads(r.stdout)
    assert isinstance(parsed, list)
    assert len(parsed) >= 1
