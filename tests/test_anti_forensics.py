"""AntiForensicsDetector — log clearing, history wipe, timestomp, secure-delete."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.anti_forensics import AntiForensicsDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, cmdline, exe=None):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}",
        data={"pid": pid, "ppid": 1, "name": name,
              "exe": exe or f"/usr/bin/{name}",
              "cmdline": cm, "username": "user",
              "connections": [], "open_files": []},
    ))


def _shell_history(store, path, size):
    store.add_artifact(Artifact(
        collector="auth_logs", category="logs",
        subject=f"log:{path}",
        data={"path": path, "size": size, "raw": ""},
    ))


# ---- F1 shell history ---- #


def test_history_clear_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash", cmdline=["bash", "-c", "history -c"])
    findings = list(AntiForensicsDetector().detect(store))
    h = [f for f in findings if "history -c" in (f.evidence.get("pattern") or "")]
    assert h, [f.title for f in findings]
    assert h[0].severity == "high"
    assert h[0].mitre == "T1070.003"
    store.close()


def test_bash_history_symlinked_to_devnull(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash",
          cmdline=["bash", "-c", "ln -sf /dev/null ~/.bash_history"])
    findings = list(AntiForensicsDetector().detect(store))
    s = [f for f in findings if "symlinked" in (f.evidence.get("pattern") or "")]
    assert s
    assert s[0].mitre == "T1070.003"
    store.close()


def test_histfile_to_devnull(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash",
          cmdline=["bash", "-c", "export HISTFILE=/dev/null"])
    findings = list(AntiForensicsDetector().detect(store))
    h = [f for f in findings if "HISTFILE=/dev/null" in str(f.evidence)]
    assert h
    store.close()


# ---- F2 Unix log clearing ---- #


def test_truncate_auth_log_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash",
          cmdline=["bash", "-c", "truncate -s 0 /var/log/auth.log"])
    findings = list(AntiForensicsDetector().detect(store))
    t = [f for f in findings if "truncated" in (f.evidence.get("pattern") or "")]
    assert t, [f.title for f in findings]
    assert t[0].severity == "critical"
    assert t[0].mitre == "T1070.002"
    store.close()


def test_journalctl_vacuum_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash",
          cmdline=["bash", "-c", "journalctl --vacuum-time=1s"])
    findings = list(AntiForensicsDetector().detect(store))
    j = [f for f in findings if "journal" in (f.evidence.get("pattern") or "")]
    assert j
    store.close()


def test_rm_auth_log_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash",
          cmdline=["bash", "-c", "rm -f /var/log/auth.log"])
    findings = list(AntiForensicsDetector().detect(store))
    r = [f for f in findings if "removed" in (f.evidence.get("pattern") or "")]
    assert r
    assert r[0].severity == "critical"
    store.close()


# ---- F3 Windows event log ---- #


def test_wevtutil_cl_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "wevtutil.exe",
          cmdline=["wevtutil.exe", "cl", "Security"])
    findings = list(AntiForensicsDetector().detect(store))
    w = [f for f in findings if "wevtutil cl" in (f.evidence.get("pattern") or "")]
    assert w
    assert w[0].severity == "critical"
    assert w[0].mitre == "T1070.001"
    store.close()


def test_clear_eventlog_powershell(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "powershell.exe",
          cmdline=["powershell.exe", "-c", "Clear-EventLog -LogName Security"])
    findings = list(AntiForensicsDetector().detect(store))
    c = [f for f in findings if "Clear-EventLog" in (f.evidence.get("pattern") or "")]
    assert c
    store.close()


# ---- F4 timestomping ---- #


def test_touch_t_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash",
          cmdline=["bash", "-c", "touch -t 202301010000 /etc/passwd"])
    findings = list(AntiForensicsDetector().detect(store))
    t = [f for f in findings if "touch -t" in (f.evidence.get("pattern") or "")]
    assert t
    assert t[0].mitre == "T1070.006"
    store.close()


def test_touch_reference_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash",
          cmdline=["bash", "-c", "touch --reference=/bin/ls /opt/implant"])
    findings = list(AntiForensicsDetector().detect(store))
    t = [f for f in findings if "reference" in (f.evidence.get("pattern") or "")]
    assert t
    store.close()


def test_powershell_setcreationtime_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "powershell.exe",
          cmdline=["powershell.exe", "-c",
                   "(Get-Item C:\\bad.exe).SetCreationTime('2020-01-01')"])
    findings = list(AntiForensicsDetector().detect(store))
    s = [f for f in findings if "SetCreationTime" in (f.evidence.get("pattern") or "")]
    assert s
    store.close()


# ---- F5 secure deletion ---- #


def test_shred_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash", cmdline=["bash", "-c", "shred -uvz /opt/implant"])
    findings = list(AntiForensicsDetector().detect(store))
    s = [f for f in findings if "shred" in (f.evidence.get("pattern") or "")]
    assert s
    assert s[0].mitre == "T1070.004"
    store.close()


def test_sdelete_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "cmd.exe",
          cmdline=["cmd.exe", "/c", "sdelete.exe -p 7 C:\\bad.exe"])
    findings = list(AntiForensicsDetector().detect(store))
    s = [f for f in findings if "sdelete" in (f.evidence.get("pattern") or "")]
    assert s
    store.close()


# ---- F7 empty bash_history ---- #


def test_empty_bash_history_flagged(tmp_path):
    store = _store(tmp_path)
    _shell_history(store, "/home/alice/.bash_history", 0)
    findings = list(AntiForensicsDetector().detect(store))
    e = [f for f in findings if f.evidence.get("kind") == "empty_shell_history"]
    assert e
    assert e[0].severity == "medium"
    store.close()


def test_nonempty_bash_history_not_flagged(tmp_path):
    store = _store(tmp_path)
    _shell_history(store, "/home/alice/.bash_history", 1234)
    findings = list(AntiForensicsDetector().detect(store))
    assert [f for f in findings if f.evidence.get("kind") == "empty_shell_history"] == []
    store.close()


# ---- Sigma generation ---- #


def test_sigma_emitted_for_log_clear(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "wevtutil.exe", cmdline=["wevtutil.exe", "cl", "Security"])
    f = next(AntiForensicsDetector().detect(store))
    fdict = {"detector": f.detector, "title": f.title, "summary": f.summary,
             "severity": f.severity, "evidence": f.evidence,
             "finding_uuid": "af-1"}
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert "attack.t1070" in rule["tags"]
    assert rule["logsource"]["category"] == "process_creation"
    store.close()


def test_per_detector_sigma_template_present():
    """Anti-forensics detector ships a per-class Sigma template too."""
    from digger.detectors.anti_forensics import AntiForensicsDetector
    tpl = AntiForensicsDetector().to_sigma_template()
    assert tpl is not None
    assert tpl["logsource"]["category"] == "process_creation"
    assert "attack.t1070" in tpl["tags"]
    # Five selection blocks covering the five anti-forensics families
    sels = [k for k in tpl["detection"] if k.startswith("selection_")]
    assert len(sels) >= 5
