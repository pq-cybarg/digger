"""GitHub Actions workflow auditor.

Walks every `.github/workflows/*.yml` (or `.yaml`) file under the
given roots, parses it as YAML, and extracts the structured
features the ``ci_workflow_audit`` detector consumes.

What we parse out
-----------------
For each workflow file:
  - ``on`` triggers (list of trigger names — pull_request,
    pull_request_target, workflow_run, push, schedule, etc.)
  - per-job: id, name, runs-on, permissions block (if present)
  - per-step: name, action ``uses:`` ref (parsed into owner / repo
    / ref / sha-pinned flag), or ``run:`` block (script)
  - every place in the workflow text where
    ``${{ github.event.<sensitive-path> }}`` appears in a run
    block — that's how script injection happens

The detector then runs rule checks against these features.

Strict-local; we don't fetch the action repo, don't talk to
the registry, don't run any of the workflow steps.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class CiAuditError(RuntimeError):
    pass


# ---- safety caps ---- #

_MAX_WORKFLOW_BYTES = 4 * 1024 * 1024
_MAX_RUN_BLOCK_BYTES = 64 * 1024


# Canonical first-party action namespaces — never flagged as
# unpinned-third-party, even if they use a moving tag like @v4.
# Operators extend via DIGGER_CI_TRUSTED_ACTION_OWNERS env var.
TRUSTED_ACTION_OWNERS = (
    "actions",                              # github.com/actions/*
    "github",                               # github.com/github/*
    "azure",                                # github.com/azure/* (MS)
    "docker",                               # docker official
    "google-github-actions",                # Google official
    "aws-actions",                          # AWS official
    "anthropic-experimental",
    "anthropics",
    "hashicorp",
    "actions-rs",
    "advanced-security",
    "code-scanning",
)


def _trusted_owner_set() -> tuple[str, ...]:
    import os
    extra = os.environ.get("DIGGER_CI_TRUSTED_ACTION_OWNERS", "")
    parts = [s.strip().lower() for s in extra.split(",") if s.strip()]
    return tuple(sorted({*TRUSTED_ACTION_OWNERS, *parts}))


# Untrusted ${{ }} contexts that, if interpolated into a run: block,
# allow script injection by anyone who can submit a PR / issue.
INJECTABLE_GITHUB_CONTEXTS = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.commits",  # commit messages
    "github.head_ref",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.display_title",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.pull_requests",
)


# ---- record shape ---- #


@dataclass
class WorkflowAction:
    uses: str = ""         # full ref: owner/repo[/path]@ref
    owner: str = ""        # parsed
    repo: str = ""
    ref: str = ""          # tag / branch / sha
    sha_pinned: bool = False
    is_trusted_owner: bool = False
    is_local: bool = False  # ./local-action


@dataclass
class WorkflowRecord:
    file_path: str
    workflow_name: str = ""
    on_triggers: list[str] = field(default_factory=list)
    job_count: int = 0
    step_count: int = 0
    actions: list[WorkflowAction] = field(default_factory=list)
    injectable_interpolations: list[dict[str, str]] = field(
        default_factory=list,
    )
    runs_with_secrets: bool = False
    has_persist_credentials_true: bool = False
    has_pull_request_target_with_checkout_head: bool = False
    has_workflow_run_trigger: bool = False
    self_modifying: bool = False
    permissions_top_level: str = ""    # serialized or "default"
    parse_error: str = ""


# ---- parsing helpers ---- #


_SHA_RE = re.compile(r"^[a-f0-9]{40}$")


def _parse_uses(uses: str) -> WorkflowAction:
    """Parse `owner/repo[/sub/path]@ref` into a WorkflowAction."""
    a = WorkflowAction(uses=uses[:256])
    if uses.startswith("./"):
        a.is_local = True
        return a
    if "@" in uses:
        before, ref = uses.rsplit("@", 1)
    else:
        before, ref = uses, ""
    a.ref = ref[:128]
    a.sha_pinned = bool(_SHA_RE.match(ref))
    parts = before.split("/", 2)
    if len(parts) >= 1:
        a.owner = parts[0]
    if len(parts) >= 2:
        a.repo = parts[1]
    a.is_trusted_owner = a.owner.lower() in _trusted_owner_set()
    return a


_INTERP_RE = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")


def _scan_run_for_injectables(
    run: str, step_label: str,
) -> list[dict[str, str]]:
    """Return one entry per injectable interpolation."""
    out: list[dict[str, str]] = []
    if not isinstance(run, str):
        return out
    if len(run) > _MAX_RUN_BLOCK_BYTES:
        run = run[:_MAX_RUN_BLOCK_BYTES]
    for m in _INTERP_RE.finditer(run):
        ctx = m.group(1).strip()
        for inj in INJECTABLE_GITHUB_CONTEXTS:
            if inj in ctx:
                out.append({"context": ctx[:200],
                             "step": step_label[:200]})
                break
    return out


def _self_modifying(jobs_blob: Any) -> bool:
    """Crude scan: any step writes to .github/workflows/?"""
    if not isinstance(jobs_blob, dict):
        return False
    for _job_id, job in jobs_blob.items():
        if not isinstance(job, dict):
            continue
        for step in (job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            run = step.get("run") or ""
            if not isinstance(run, str):
                continue
            if ".github/workflows/" in run and \
                    any(verb in run for verb in
                        (">", ">>", "tee ", "cp ", "mv ", "cat <<")):
                return True
    return False


def _normalize_triggers(on: Any) -> list[str]:
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [t for t in on if isinstance(t, str)]
    if isinstance(on, dict):
        return list(on.keys())
    return []


# ---- per-file parse ---- #


def parse_workflow_file(path: Path | str) -> WorkflowRecord:
    p = Path(path)
    rec = WorkflowRecord(file_path=str(p))
    if not p.is_file():
        rec.parse_error = "file not found"
        return rec
    try:
        sz = p.stat().st_size
    except OSError as exc:
        rec.parse_error = f"stat failed: {exc}"
        return rec
    if sz > _MAX_WORKFLOW_BYTES:
        rec.parse_error = (
            f"workflow {sz} bytes > {_MAX_WORKFLOW_BYTES} cap"
        )
        return rec
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            blob = yaml.safe_load(fh)
    except (yaml.YAMLError, OSError) as exc:
        rec.parse_error = f"{type(exc).__name__}: {exc}"
        return rec
    if not isinstance(blob, dict):
        rec.parse_error = "top-level is not a mapping"
        return rec

    rec.workflow_name = str(blob.get("name") or "")[:200]
    # YAML loads ``on:`` as True (because "on" is a YAML bool keyword).
    on_block = blob.get("on")
    if on_block is None and True in blob:
        on_block = blob[True]
    rec.on_triggers = _normalize_triggers(on_block)
    rec.has_workflow_run_trigger = "workflow_run" in rec.on_triggers

    perms_top = blob.get("permissions")
    if perms_top is None:
        rec.permissions_top_level = "default"
    elif isinstance(perms_top, str):
        rec.permissions_top_level = perms_top
    else:
        rec.permissions_top_level = "object"

    jobs = blob.get("jobs") or {}
    if not isinstance(jobs, dict):
        jobs = {}
    rec.job_count = len(jobs)

    for _job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        rec.step_count += len(steps)
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            step_label = str(step.get("name") or
                              step.get("id") or f"step-{idx}")
            uses = step.get("uses")
            if isinstance(uses, str) and uses.strip():
                rec.actions.append(_parse_uses(uses.strip()))
                if step.get("with") and \
                        isinstance(step["with"], dict) and \
                        any("ref" in k or "head" in k.lower()
                            for k in step["with"]):
                    ref_val = next(
                        (str(v) for k, v in step["with"].items()
                         if "ref" in k.lower() or "head" in k.lower()),
                        "",
                    )
                    if "head.ref" in ref_val or "pull_request" in ref_val:
                        if "pull_request_target" in rec.on_triggers:
                            rec.has_pull_request_target_with_checkout_head \
                                = True
                if isinstance(step.get("with"), dict):
                    pc = step["with"].get("persist-credentials")
                    if pc in (True, "true", "True"):
                        rec.has_persist_credentials_true = True
            run = step.get("run")
            if isinstance(run, str):
                rec.injectable_interpolations += \
                    _scan_run_for_injectables(run, step_label)
                if "${{ secrets." in run or "${{secrets." in run:
                    rec.runs_with_secrets = True
            env = step.get("env")
            if isinstance(env, dict):
                for _k, v in env.items():
                    if isinstance(v, str) and "secrets." in v:
                        rec.runs_with_secrets = True

    rec.self_modifying = _self_modifying(jobs)
    return rec


# ---- walker ---- #


def audit_workflows(
    roots: Iterable[Path | str] | None = None,
) -> list[WorkflowRecord]:
    """Walk every .github/workflows/*.yml under each root and
    parse it. If ``roots`` is None, defaults to ``[cwd]``."""
    if roots is None:
        roots = [Path.cwd()]
    out: list[WorkflowRecord] = []
    for root in roots:
        root_p = Path(root)
        wfs = list(_workflow_files_under(root_p))
        for wf in wfs:
            out.append(parse_workflow_file(wf))
    return out


def _workflow_files_under(root: Path) -> Iterable[Path]:
    """Yield every YAML workflow file under ``root``.

    If ``root`` is itself a .yml file, yield it. If ``root`` is a
    ``.github/workflows`` directory, yield its YAML files. Else,
    scan for ``.github/workflows`` subdirs."""
    if root.is_file() and root.suffix in (".yml", ".yaml"):
        yield root
        return
    if root.is_dir() and root.name == "workflows" and \
            root.parent.name == ".github":
        for child in sorted(root.iterdir()):
            if child.is_file() and child.suffix in (".yml", ".yaml"):
                yield child
        return
    if root.is_dir():
        wf_dir = root / ".github" / "workflows"
        if wf_dir.is_dir():
            for child in sorted(wf_dir.iterdir()):
                if child.is_file() and child.suffix in (".yml", ".yaml"):
                    yield child


# ---- emit to store ---- #


def emit_records_to_store(records: Iterable[WorkflowRecord], store) -> int:
    from dataclasses import asdict
    from digger.core.evidence import Artifact
    n = 0
    for rec in records:
        data = asdict(rec)
        subject = f"ci:workflow:{Path(rec.file_path).name}"
        store.add_artifact(Artifact(
            collector="ci.workflow_audit",
            category="ci_cd",
            subject=subject[:380],
            data=data,
        ))
        n += 1
    return n
