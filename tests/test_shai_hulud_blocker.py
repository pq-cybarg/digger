"""ShaiHuludBlockerDetector — active hardening against worm primitives."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.shai_hulud_blocker import ShaiHuludBlockerDetector


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


# ---- H1 destruction primitive (gh-token-monitor) ---------------------- #


def test_gh_token_monitor_present_emits_disarm_first(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home/dev",
        data={"location": "/home/dev",
              "entries": [
                  {"path": "/home/dev/.config/systemd/user/gh-token-monitor.service",
                   "size": 512},
              ]},
    ))
    findings = list(ShaiHuludBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "destruction_primitive_present"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1485"
    mit = hits[0].evidence.get("hardening_commands") or ""
    # Disarm-first must mention killing, unloading, removing in that order
    assert "pkill" in mit
    assert "launchctl unload" in mit
    assert "rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist" in mit
    assert "systemctl --user disable" in mit
    assert "DO NOT revoke" in mit
    # The persistence removal step is explicitly NOT reversible
    assert hits[0].evidence.get("reversible") is False
    store.close()


def test_clean_systemd_user_dir_no_destruction_finding(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home/dev",
        data={"location": "/home/dev",
              "entries": [
                  {"path": "/home/dev/.config/systemd/user/syncthing.service",
                   "size": 512},
              ]},
    ))
    findings = list(ShaiHuludBlockerDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "destruction_primitive_present"]
    store.close()


# ---- H2 npm install-scripts hardening ------------------------------- #


def test_npm_project_present_emits_lifecycle_hardening(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:/proj/x",
        data={"project": "/proj/x", "locked_packages": {"react": "18.0.0"}},
    ))
    findings = list(ShaiHuludBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "npm_lifecycle_scripts_hardening"]
    assert hits
    mit = hits[0].evidence.get("hardening_commands") or ""
    assert "ignore-scripts true" in mit
    assert "unsafe-perm false" in mit
    assert hits[0].evidence.get("reversible") is True
    store.close()


def test_npm_local_finding_warns_about_remote_execution(tmp_path):
    """The local-hardening finding must explicitly warn that ignoring
    scripts locally does NOT protect CI runners. If a user follows
    only the local advice, they get rekt by GitHub Actions."""
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:/proj/x",
        data={"project": "/proj/x", "locked_packages": {"react": "18.0.0"}},
    ))
    f = next(f for f in ShaiHuludBlockerDetector().detect(store)
             if f.evidence.get("kind") == "npm_lifecycle_scripts_hardening")
    summary = f.summary or ""
    assert "CRITICAL" in summary
    assert "GitHub Actions" in summary
    assert "GITHUB_TOKEN" in summary
    # Cross-reference to the CI-side finding
    assert f.evidence.get("see_also") == "github_actions_ci_hardening"
    # The hardening block itself also carries the warning
    mit = f.evidence.get("hardening_commands") or ""
    assert "get rekt by the remote execution" in mit
    store.close()


def test_npm_project_also_emits_ci_hardening(tmp_path):
    """H2 (local) and H2b (CI) must always be paired — applying only
    one leaves the other vector open."""
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="npm_packages", category="inventory",
        subject="npm:/proj/x",
        data={"project": "/proj/x", "locked_packages": {"react": "18.0.0"}},
    ))
    findings = list(ShaiHuludBlockerDetector().detect(store))
    kinds = {f.evidence.get("kind") for f in findings}
    assert "npm_lifecycle_scripts_hardening" in kinds
    assert "github_actions_ci_hardening" in kinds
    # CI hardening must be substantive
    ci = next(f for f in findings
              if f.evidence.get("kind") == "github_actions_ci_hardening")
    mit = ci.evidence.get("hardening_commands") or ""
    # Each of the 7 steps must be present
    assert "ignore-scripts=true" in mit
    assert "VULNERABLE" in mit  # workflow audit step
    assert "NPM_CONFIG_IGNORE_SCRIPTS" in mit  # env-var snippet
    assert "full-40-char-SHA" in mit  # SHA pinning
    assert "actions/checkout@" in mit
    assert "Unpinned actions" in mit
    assert "CODEOWNERS" in mit
    assert "workflow_run" in mit  # privileged-trigger audit
    assert "pull_request_target" in mit
    # Cross-reference back
    assert ci.evidence.get("see_also") == "npm_lifecycle_scripts_hardening"
    store.close()


def test_no_npm_project_no_lifecycle_finding(tmp_path):
    """Without any npm artifact, the lifecycle hardening doesn't fire
    (no value in suggesting a global setting for a host with no npm)."""
    store = _store(tmp_path)
    # Add something else
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=1 init",
        data={"pid": 1, "name": "init", "exe": "/sbin/init",
              "cmdline": ["init"], "username": "root",
              "connections": [], "open_files": []},
    ))
    findings = list(ShaiHuludBlockerDetector().detect(store))
    assert not [f for f in findings
                if f.evidence.get("kind") == "npm_lifecycle_scripts_hardening"]
    store.close()


# ---- H3 IDE-dirs immutable hardening -------------------------------- #


def test_claude_dir_present_emits_ide_hardening(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/proj",
        data={"location": "/proj",
              "entries": [{"path": "/home/dev/proj/.claude/settings.json",
                           "size": 100}]},
    ))
    findings = list(ShaiHuludBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "ide_dirs_writable"]
    assert hits
    mit = hits[0].evidence.get("hardening_commands") or ""
    assert "chflags" in mit  # macOS
    assert "chattr" in mit   # Linux
    assert "icacls" in mit   # Windows
    assert hits[0].evidence.get("reversible") is True
    store.close()


def test_vscode_dir_present_emits_ide_hardening(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/proj",
        data={"location": "/proj",
              "entries": [{"path": "/home/dev/proj/.vscode/tasks.json",
                           "size": 100}]},
    ))
    findings = list(ShaiHuludBlockerDetector().detect(store))
    assert [f for f in findings if f.evidence.get("kind") == "ide_dirs_writable"]
    store.close()


# ---- H4-H7 always-emit hardening (no triggering artifact required) - #


def test_persistence_dirs_hardening_always_emitted(tmp_path):
    store = _store(tmp_path)
    findings = list(ShaiHuludBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "persistence_dirs_writable"]
    assert hits
    mit = hits[0].evidence.get("hardening_commands") or ""
    assert "chmod 500 ~/Library/LaunchAgents" in mit
    assert "chmod 500 ~/.config/systemd/user" in mit
    assert "snapshot" in mit
    assert hits[0].evidence.get("reversible") is True
    store.close()


def test_privesc_audit_always_emitted(tmp_path):
    store = _store(tmp_path)
    findings = list(ShaiHuludBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "privesc_audit"]
    assert hits
    mit = hits[0].evidence.get("hardening_commands") or ""
    assert "NOPASSWD" in mit
    assert "getcap" in mit
    assert "find /home" in mit
    assert hits[0].mitre == "T1548"
    store.close()


def test_hosts_block_always_emitted(tmp_path):
    store = _store(tmp_path)
    findings = list(ShaiHuludBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "c2_hosts_block"]
    assert hits
    mit = hits[0].evidence.get("hardening_commands") or ""
    # Must cover Shai-Hulud + Mini Shai-Hulud + TrapDoor + Nightmare-Eclipse
    for host in ["webhook.site", "git-tanstack.com", "filev2.getsession.org",
                 "ddjidd564.github.io", "staybud.dpdns.org"]:
        assert host in mit
    store.close()


def test_github_token_hardening_always_emitted(tmp_path):
    store = _store(tmp_path)
    findings = list(ShaiHuludBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "github_token_hardening"]
    assert hits
    mit = hits[0].evidence.get("hardening_commands") or ""
    assert "gh api -X PUT" in mit
    assert "default_workflow_permissions=read" in mit
    store.close()


# ---- H8 Session messenger ------------------------------------------- #


def test_session_messenger_install_flagged(tmp_path):
    store = _store(tmp_path)
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem",
        subject="recent:/home/dev",
        data={"location": "/home/dev",
              "entries": [{"path": "/home/dev/.config/Session/messages.db",
                           "size": 16384}]},
    ))
    findings = list(ShaiHuludBlockerDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "session_messenger_present"]
    assert hits
    assert hits[0].severity == "low"
    store.close()


# ---- Sigma + registration ------------------------------------------- #


def test_sigma_template_present():
    tpl = ShaiHuludBlockerDetector().to_sigma_template()
    assert tpl is not None
    assert "selection_persistence" in tpl["detection"]
    assert "selection_ide_dirs" in tpl["detection"]


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "shai_hulud_blocker" in [d.name for d in all_detectors()]


# ---- End-to-end: clean machine still emits hardening advisories ---- #


def test_empty_store_emits_hardening_advisories(tmp_path):
    """A truly empty case still emits H4, H5, H6, H7 — the always-on
    hardening surface — because those are present-state regardless of
    what was collected. H1, H2, H3, H8 are conditional."""
    store = _store(tmp_path)
    findings = list(ShaiHuludBlockerDetector().detect(store))
    kinds = {f.evidence.get("kind") for f in findings}
    assert "persistence_dirs_writable" in kinds
    assert "privesc_audit" in kinds
    assert "c2_hosts_block" in kinds
    assert "github_token_hardening" in kinds
    # Conditional ones should NOT fire on an empty store
    assert "destruction_primitive_present" not in kinds
    assert "npm_lifecycle_scripts_hardening" not in kinds
    assert "ide_dirs_writable" not in kinds
    assert "session_messenger_present" not in kinds
    store.close()
