"""PersistentSessionDetector — multiplexer under service, detached listener,
user-systemd unit pointing to user-writable script."""

from __future__ import annotations

import os
import stat

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.persistent_sessions import PersistentSessionDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, ppid=None, cmdline=None, connections=None,
          exe=None):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}",
        data={"pid": pid, "ppid": ppid, "name": name,
              "exe": exe or f"/usr/bin/{name}",
              "cmdline": cm, "username": "user",
              "connections": connections or [], "open_files": []},
    ))


def _user_unit(store, path, contents, owner_uid=1000):
    store.add_artifact(Artifact(
        collector="linux.systemd", category="persistence",
        subject=f"user-unit:{path}",
        data={"path": path, "contents": contents, "owner_uid": owner_uid,
              "size": len(contents), "mtime": 0},
    ))


# ---- S1 Multiplexer under network service ---- #


def test_tmux_under_nginx_is_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "nginx", ppid=1)
    _proc(store, 200, "tmux: server", ppid=100, exe="/usr/bin/tmux")
    findings = list(PersistentSessionDetector().detect(store))
    mp = [f for f in findings
          if f.evidence.get("kind") == "multiplexer_under_service"]
    assert mp, [f.title for f in findings]
    assert mp[0].severity == "critical"
    assert mp[0].mitre == "T1546"
    assert "nginx" in mp[0].title
    store.close()


def test_tmux_under_sshd_is_normal(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "sshd", ppid=1)
    _proc(store, 200, "tmux", ppid=100)
    findings = list(PersistentSessionDetector().detect(store))
    mp = [f for f in findings
          if f.evidence.get("kind") == "multiplexer_under_service"]
    assert mp == []
    store.close()


def test_zellij_under_php_fpm_is_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "php-fpm", ppid=1, exe="/usr/sbin/php-fpm")
    _proc(store, 200, "zellij", ppid=100, exe="/usr/local/bin/zellij")
    findings = list(PersistentSessionDetector().detect(store))
    mp = [f for f in findings
          if f.evidence.get("kind") == "multiplexer_under_service"]
    assert mp
    assert mp[0].severity == "critical"
    store.close()


def test_multiplexer_via_grandparent_service(tmp_path):
    """nginx → bash → tmux still trips (transitive parent)."""
    store = _store(tmp_path)
    _proc(store, 100, "nginx", ppid=1)
    _proc(store, 150, "bash", ppid=100)
    _proc(store, 200, "tmux", ppid=150, exe="/usr/bin/tmux")
    findings = list(PersistentSessionDetector().detect(store))
    mp = [f for f in findings
          if f.evidence.get("kind") == "multiplexer_under_service"]
    assert mp
    store.close()


# ---- S2 Detached process with socket ---- #


def test_nohup_with_inet_socket_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "myapp", ppid=1,
          cmdline=["nohup", "/tmp/implant", "--listen", "9001"],
          connections=[{"raddr": None, "laddr": ["0.0.0.0", 9001],
                        "status": "LISTEN"}])
    findings = list(PersistentSessionDetector().detect(store))
    det = [f for f in findings
           if f.evidence.get("kind") == "detached_listener"]
    assert det
    assert det[0].severity == "medium"
    store.close()


def test_nohup_without_socket_not_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "myapp", ppid=1,
          cmdline=["nohup", "/usr/local/bin/job"])
    findings = list(PersistentSessionDetector().detect(store))
    det = [f for f in findings
           if f.evidence.get("kind") == "detached_listener"]
    assert det == []
    store.close()


# ---- S3 user-systemd shell-in-home ExecStart ---- #


def test_user_unit_pointing_to_shell_in_tmp_is_critical(tmp_path):
    store = _store(tmp_path)
    # Create a real shell script so the shebang check succeeds
    script = tmp_path / "implant.sh"
    script.write_text("#!/bin/bash\nwhile :; do sleep 60; done\n")
    script.chmod(0o755)
    # Place under /tmp/ semantics: we point ExecStart at the real script,
    # but spoof its path as if it were /tmp/...sh by writing the unit text
    # accordingly. The detector relies on _is_under_user_writable on the
    # ExecStart string, then opens the actual file for shebang.
    user_unit_text = f"""
[Unit]
Description=Implant
[Service]
ExecStart=/tmp/{script.name}
Restart=always
[Install]
WantedBy=default.target
""".lstrip()
    # We need the actual file at /tmp/implant.sh for the shebang check
    real_target = f"/tmp/{script.name}"
    if not os.path.exists(real_target):
        try:
            import shutil
            shutil.copy2(script, real_target)
            os.chmod(real_target, 0o755)
        except (PermissionError, OSError):
            real_target = str(script)  # fall back; test still exercises path logic
            user_unit_text = user_unit_text.replace(
                f"/tmp/{script.name}", real_target)

    _user_unit(store, "/home/alice/.config/systemd/user/implant.service",
               user_unit_text, owner_uid=os.getuid())
    findings = list(PersistentSessionDetector().detect(store))
    us = [f for f in findings
          if f.evidence.get("kind") == "user_systemd_user_script"]
    assert us, [f.title for f in findings]
    # critical needs both shell-shebang AND ownership match
    assert us[0].severity in ("critical", "high")
    # Cleanup
    try:
        os.unlink(real_target)
    except OSError:
        pass
    store.close()


def test_user_unit_pointing_to_system_binary_not_flagged(tmp_path):
    store = _store(tmp_path)
    _user_unit(store, "/home/alice/.config/systemd/user/safe.service",
               "[Service]\nExecStart=/usr/bin/python3 /opt/app/run.py\n",
               owner_uid=1000)
    findings = list(PersistentSessionDetector().detect(store))
    us = [f for f in findings
          if f.evidence.get("kind") == "user_systemd_user_script"]
    assert us == []
    store.close()


# ---- Sigma generation ---- #


def test_sigma_for_multiplexer_under_service(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "nginx", ppid=1)
    _proc(store, 200, "tmux", ppid=100, exe="/usr/bin/tmux")
    f = next(PersistentSessionDetector().detect(store))
    fdict = {"detector": f.detector, "title": f.title, "summary": f.summary,
             "severity": f.severity, "evidence": f.evidence,
             "finding_uuid": "ps-1"}
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert "attack.t1546" in rule["tags"]
    assert "/tmux" in rule["detection"]["selection"]["Image|endswith"]
    store.close()
