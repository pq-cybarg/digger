"""CI workflow auditor + CiWorkflowAuditDetector tests."""

from __future__ import annotations

from digger.ci import (
    WorkflowRecord,
    audit_workflows,
    emit_records_to_store,
    parse_workflow_file,
)
from digger.ci.workflow_auditor import (
    INJECTABLE_GITHUB_CONTEXTS,
    TRUSTED_ACTION_OWNERS,
    _parse_uses,
    _scan_run_for_injectables,
    _self_modifying,
    _trusted_owner_set,
    _workflow_files_under,
)
from digger.core.evidence import EvidenceStore
from digger.detectors.ci_workflow_audit import CiWorkflowAuditDetector


# ---- _parse_uses ---- #


def test_parse_uses_sha_pinned():
    a = _parse_uses(
        "actions/checkout@" + "a" * 40,
    )
    assert a.owner == "actions"
    assert a.repo == "checkout"
    assert a.sha_pinned is True
    assert a.is_trusted_owner is True


def test_parse_uses_moving_tag():
    a = _parse_uses("tj-actions/changed-files@v40")
    assert a.owner == "tj-actions"
    assert a.repo == "changed-files"
    assert a.sha_pinned is False
    assert a.is_trusted_owner is False


def test_parse_uses_trusted_owner_unpinned():
    a = _parse_uses("actions/setup-node@v3")
    assert a.is_trusted_owner is True
    assert a.sha_pinned is False


def test_parse_uses_local_action():
    a = _parse_uses("./.github/actions/my-action")
    assert a.is_local is True


def test_parse_uses_no_ref():
    a = _parse_uses("owner/repo")
    assert a.owner == "owner"
    assert a.repo == "repo"
    assert a.ref == ""
    assert a.sha_pinned is False


# ---- _scan_run_for_injectables ---- #


def test_scan_run_finds_pr_title_injection():
    out = _scan_run_for_injectables(
        "echo ${{ github.event.pull_request.title }}",
        step_label="echo",
    )
    assert len(out) == 1
    assert "pull_request.title" in out[0]["context"]


def test_scan_run_finds_issue_body_injection():
    out = _scan_run_for_injectables(
        "echo ${{ github.event.issue.body }}",
        step_label="echo",
    )
    assert len(out) == 1


def test_scan_run_ignores_safe_contexts():
    out = _scan_run_for_injectables(
        "echo ${{ github.sha }}\necho ${{ runner.os }}",
        step_label="echo",
    )
    assert out == []


def test_scan_run_handles_non_string():
    assert _scan_run_for_injectables(None, "x") == []
    assert _scan_run_for_injectables(42, "x") == []


def test_scan_run_clips_huge_input():
    # Should not hang. The injection is way past the cap.
    huge = "x" * 100_000 + "${{ github.event.issue.title }}"
    out = _scan_run_for_injectables(huge, "x")
    # Truncated before the marker, so nothing matches:
    assert out == []


# ---- _self_modifying ---- #


def test_self_modifying_writes_workflow_file():
    jobs = {
        "j": {"steps": [
            {"run": "echo evil >> .github/workflows/secondary.yml"},
        ]},
    }
    assert _self_modifying(jobs) is True


def test_self_modifying_negative_for_read():
    jobs = {
        "j": {"steps": [
            {"run": "cat .github/workflows/main.yml"},
        ]},
    }
    assert _self_modifying(jobs) is False


def test_self_modifying_negative_for_no_workflow_writes():
    jobs = {
        "j": {"steps": [{"run": "echo hi"}, {"run": "ls -la"}]},
    }
    assert _self_modifying(jobs) is False


# ---- _trusted_owner_set env override ---- #


def test_trusted_owner_set_default_includes_actions():
    s = _trusted_owner_set()
    assert "actions" in s
    assert "github" in s


def test_trusted_owner_set_env_override(monkeypatch):
    monkeypatch.setenv("DIGGER_CI_TRUSTED_ACTION_OWNERS",
                        "mycorp, internal-org")
    s = _trusted_owner_set()
    assert "mycorp" in s
    assert "internal-org" in s


# ---- _workflow_files_under ---- #


def test_workflow_files_under_repo_root(tmp_path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "a.yml").write_text("name: a\non: push\njobs: {}\n")
    (wf_dir / "b.yaml").write_text("name: b\non: push\njobs: {}\n")
    (wf_dir / "notes.txt").write_text("ignore me")
    files = list(_workflow_files_under(tmp_path))
    names = {f.name for f in files}
    assert names == {"a.yml", "b.yaml"}


def test_workflow_files_under_workflows_dir_direct(tmp_path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "x.yml").write_text("name: x\n")
    files = list(_workflow_files_under(wf_dir))
    assert len(files) == 1


def test_workflow_files_under_single_file(tmp_path):
    f = tmp_path / "loose.yml"
    f.write_text("name: x\n")
    assert list(_workflow_files_under(f)) == [f]


def test_workflow_files_under_empty_dir(tmp_path):
    assert list(_workflow_files_under(tmp_path)) == []


# ---- parse_workflow_file ---- #


def test_parse_workflow_basic(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text(
        "name: Build\n"
        "on: [push, pull_request]\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@" + "a" * 40 + "\n"
        "      - uses: tj-actions/changed-files@v40\n"
        "      - run: echo hi\n"
    )
    rec = parse_workflow_file(p)
    assert rec.workflow_name == "Build"
    assert set(rec.on_triggers) == {"push", "pull_request"}
    assert rec.job_count == 1
    assert rec.step_count == 3
    assert len(rec.actions) == 2
    assert rec.actions[0].sha_pinned is True
    assert rec.actions[1].sha_pinned is False
    assert rec.parse_error == ""


def test_parse_workflow_pwn_request_pattern(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text(
        "name: Pwn\n"
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.ref }}\n"
    )
    rec = parse_workflow_file(p)
    assert rec.has_pull_request_target_with_checkout_head is True


def test_parse_workflow_workflow_run_trigger(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text(
        "name: After\n"
        "on:\n"
        "  workflow_run:\n"
        "    workflows: [\"Build\"]\n"
        "    types: [completed]\n"
        "jobs:\n"
        "  x:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    rec = parse_workflow_file(p)
    assert rec.has_workflow_run_trigger is True


def test_parse_workflow_injectable_interpolation(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text(
        "name: Inj\n"
        "on: pull_request_target\n"
        "jobs:\n"
        "  x:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo \"${{ github.event.pull_request.title }}\"\n"
    )
    rec = parse_workflow_file(p)
    assert len(rec.injectable_interpolations) == 1


def test_parse_workflow_persist_credentials_true(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text(
        "name: P\n"
        "on: push\n"
        "jobs:\n"
        "  x:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          persist-credentials: true\n"
    )
    rec = parse_workflow_file(p)
    assert rec.has_persist_credentials_true is True


def test_parse_workflow_runs_with_secrets(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text(
        "name: S\n"
        "on: push\n"
        "jobs:\n"
        "  x:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ${{ secrets.GITHUB_TOKEN }}\n"
    )
    rec = parse_workflow_file(p)
    assert rec.runs_with_secrets is True


def test_parse_workflow_self_modifying(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text(
        "name: M\n"
        "on: push\n"
        "jobs:\n"
        "  x:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo 'evil' > .github/workflows/added.yml\n"
    )
    rec = parse_workflow_file(p)
    assert rec.self_modifying is True


def test_parse_workflow_top_level_permissions(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text(
        "name: P\n"
        "on: push\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  x:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    rec = parse_workflow_file(p)
    assert rec.permissions_top_level == "write-all"


def test_parse_workflow_default_permissions(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text(
        "name: P\n"
        "on: push\n"
        "jobs:\n"
        "  x:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: []\n"
    )
    rec = parse_workflow_file(p)
    assert rec.permissions_top_level == "default"


def test_parse_workflow_missing_file(tmp_path):
    rec = parse_workflow_file(tmp_path / "nope.yml")
    assert rec.parse_error == "file not found"


def test_parse_workflow_invalid_yaml(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text("name: x\non: [\n")
    rec = parse_workflow_file(p)
    assert rec.parse_error


def test_parse_workflow_non_mapping(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text("- one\n- two\n")
    rec = parse_workflow_file(p)
    assert "not a mapping" in rec.parse_error


def test_parse_workflow_oversize(tmp_path, monkeypatch):
    p = tmp_path / "w.yml"
    p.write_text("name: x\non: push\n")
    monkeypatch.setattr(
        "digger.ci.workflow_auditor._MAX_WORKFLOW_BYTES", 5,
    )
    rec = parse_workflow_file(p)
    assert "cap" in rec.parse_error


def test_parse_workflow_yaml_on_keyword(tmp_path):
    """YAML parses bare `on:` as True; the auditor must recover."""
    p = tmp_path / "w.yml"
    p.write_text("on: push\njobs: {}\n")
    rec = parse_workflow_file(p)
    assert rec.on_triggers == ["push"]


# ---- audit_workflows walker ---- #


def test_audit_workflows_walks_repo(tmp_path):
    wf_dir = tmp_path / "myrepo" / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "a.yml").write_text("name: a\non: push\njobs: {}\n")
    (wf_dir / "b.yml").write_text("name: b\non: push\njobs: {}\n")
    recs = audit_workflows(roots=[tmp_path / "myrepo"])
    assert len(recs) == 2


def test_audit_workflows_defaults_to_cwd(tmp_path, monkeypatch):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "x.yml").write_text("name: x\non: push\njobs: {}\n")
    monkeypatch.chdir(tmp_path)
    recs = audit_workflows()
    assert len(recs) == 1


# ---- emit_records_to_store ---- #


def test_emit_records_to_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        recs = [WorkflowRecord(file_path="/x/w.yml", workflow_name="W")]
        n = emit_records_to_store(recs, store)
        assert n == 1
        arts = list(store.iter_artifacts(collector="ci.workflow_audit",
                                          category="ci_cd"))
        assert len(arts) == 1
        assert arts[0]["data"]["workflow_name"] == "W"
    finally:
        store.close()


# ---- detector ---- #


def _seed(store, **kwargs):
    rec = WorkflowRecord(file_path="/x/w.yml", workflow_name="W")
    for k, v in kwargs.items():
        setattr(rec, k, v)
    emit_records_to_store([rec], store)


def test_detector_w1_pwn_request(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, has_pull_request_target_with_checkout_head=True,
              on_triggers=["pull_request_target"])
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "pwn_request"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].mitre == "T1199"
    finally:
        store.close()


def test_detector_w2_workflow_run(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, has_workflow_run_trigger=True,
              on_triggers=["workflow_run"])
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "workflow_run_trigger"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_w3_injectable_interpolation(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, injectable_interpolations=[
            {"context": "github.event.pull_request.title",
             "step": "echo"},
            {"context": "github.event.issue.body", "step": "echo"},
        ])
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "injectable_interpolation"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].evidence["occurrence_count"] == 2
    finally:
        store.close()


def test_detector_w4_unpinned_third_party_action(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, actions=[
            {"uses": "tj-actions/changed-files@v40",
             "owner": "tj-actions", "repo": "changed-files",
             "ref": "v40", "sha_pinned": False,
             "is_trusted_owner": False, "is_local": False},
        ])
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "unpinned_third_party_action"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_w4_no_finding_for_sha_pinned(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, actions=[
            {"uses": "tj-actions/changed-files@" + "a" * 40,
             "owner": "tj-actions", "repo": "changed-files",
             "ref": "a" * 40, "sha_pinned": True,
             "is_trusted_owner": False, "is_local": False},
        ])
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "unpinned_third_party_action"]
    finally:
        store.close()


def test_detector_w4_no_finding_for_trusted_owner(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, actions=[
            {"uses": "actions/checkout@v4",
             "owner": "actions", "repo": "checkout",
             "ref": "v4", "sha_pinned": False,
             "is_trusted_owner": True, "is_local": False},
        ])
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "unpinned_third_party_action"]
    finally:
        store.close()


def test_detector_w5_persist_credentials(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, has_persist_credentials_true=True)
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "persist_credentials"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_w6_write_all_permissions(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, permissions_top_level="write-all")
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "permissions_write_all"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_w6_default_permissions_info(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, permissions_top_level="default")
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "permissions_write_all"]
        assert len(f) == 1
        assert f[0].severity == "info"
    finally:
        store.close()


def test_detector_w6_no_finding_for_explicit_perms(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, permissions_top_level="object")
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "permissions_write_all"]
    finally:
        store.close()


def test_detector_w7_self_modifying(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, self_modifying=True)
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "self_modifying_workflow"]
        assert len(f) == 1
        assert f[0].severity == "critical"
    finally:
        store.close()


def test_detector_parse_error(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, parse_error="bad YAML")
        det = CiWorkflowAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "workflow_parse_error"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        det = CiWorkflowAuditDetector()
        assert list(det.detect(store)) == []
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "ci_workflow_audit" in names


def test_detector_sigma_template_has_tags():
    det = CiWorkflowAuditDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-ci-workflow-audit-template"
    assert "attack.t1195.002" in tpl["tags"]
    assert "attack.t1199" in tpl["tags"]
    assert tpl["logsource"]["category"] == "ci_cd"


def test_injectable_contexts_covers_known_attacks():
    assert "github.event.issue.title" in INJECTABLE_GITHUB_CONTEXTS
    assert "github.event.pull_request.body" in INJECTABLE_GITHUB_CONTEXTS
    assert "github.event.comment.body" in INJECTABLE_GITHUB_CONTEXTS
    assert "github.head_ref" in INJECTABLE_GITHUB_CONTEXTS


def test_trusted_action_owners_includes_actions():
    assert "actions" in TRUSTED_ACTION_OWNERS
    assert "github" in TRUSTED_ACTION_OWNERS
