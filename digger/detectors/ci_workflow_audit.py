"""GitHub Actions workflow security detector.

Consumes Artifacts emitted by ``digger.ci.audit_workflows`` (one
WorkflowRecord per .github/workflows/*.yml) and emits findings for
the canonical malicious / risky workflow patterns:

  W1  pull_request_target with checkout-of-PR-head:  critical
      The "pwn-request" pattern. The workflow runs in the base
      repo's privileged context (has GITHUB_TOKEN + secrets), and
      then checks out the attacker's PR code. Any malicious
      build script in the PR now runs with the repo's secrets.

  W2  workflow_run trigger:  high
      ``workflow_run`` re-runs after another workflow (often a
      fork-PR test). The re-run runs in privileged context with
      access to the originating workflow's artifacts — perfect
      for laundering attacker-controlled code into a token-
      bearing context.

  W3  Untrusted-input interpolation in a run: block:  high
      Anywhere a workflow does
        run: |
          echo "${{ github.event.issue.title }}"
      the contents of the input go straight into the bash AST —
      script injection by anyone who can submit an issue or PR
      title. Documented exploit vector (GitHub Security Lab).

  W4  Unpinned third-party action:  medium
      An action that's not owner=actions/github/etc. AND not
      SHA-pinned. The Tj-actions/changed-files compromise is
      the textbook example. Operators extend the trusted-owner
      allowlist via DIGGER_CI_TRUSTED_ACTION_OWNERS env var.

  W5  persist-credentials: true after checkout:  medium
      checkout's default is now ``persist-credentials: true``
      which leaves the GITHUB_TOKEN baked into ``.git/config``
      for the rest of the run. Steps after checkout — even
      attacker-controlled build scripts — pick it up. Set to
      false unless you actually need the token in later steps.

  W6  Workflow has top-level write-all permissions:  medium
      ``permissions: write-all`` (or no permissions block at all,
      which inherits the legacy default of write-all on most
      orgs) means every step gets ``contents: write`` and the
      keys to publish releases.

  W7  Self-modifying workflow:  critical
      The workflow contains a step that writes to
      ``.github/workflows/*``. This is the worm-persistence
      primitive (Shai-Hulud, octofiles).
"""

from __future__ import annotations

from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


class CiWorkflowAuditDetector(Detector):
    name = "ci_workflow_audit"
    description = (
        "GitHub Actions workflow security audit: pull_request_"
        "target + checkout-head (pwn-request), workflow_run from "
        "forks, injectable interpolations, unpinned third-party "
        "actions, persist-credentials, write-all top-level "
        "permissions, self-modifying workflows."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "GitHub Actions workflow risk",
            "id": "digger-ci-workflow-audit-template",
            "description": (
                ".github/workflows/*.yml on a developer host "
                "failed the digger CI workflow audit (pwn-request, "
                "script injection, unpinned third-party action, "
                "self-modifying workflow, etc)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "ci_cd"},
            "detection": {
                "selection": {
                    "kind": [
                        "pwn_request",
                        "workflow_run_trigger",
                        "injectable_interpolation",
                        "unpinned_third_party_action",
                        "persist_credentials",
                        "permissions_write_all",
                        "self_modifying_workflow",
                        "workflow_parse_error",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1195.002", "attack.t1199",
                "attack.t1059", "attack.t1552.001",
                "attack.t1078.004",
                "attack.initial_access",
                "attack.execution",
                "attack.persistence",
                "attack.supply_chain_compromise",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(
            collector="ci.workflow_audit",
            category="ci_cd",
        ):
            yield from self._check_workflow(art)

    def _check_workflow(self, art) -> Iterable[Finding]:
        rec = art["data"] or {}
        file_path = rec.get("file_path") or "?"
        workflow_name = rec.get("workflow_name") or "(unnamed)"
        label = f"{workflow_name} ({file_path})"
        ref = art["artifact_uuid"]

        if rec.get("parse_error"):
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Workflow file unparseable: {file_path}"
                ),
                summary=(
                    f"digger could not parse the workflow at "
                    f"``{file_path}``: ``{rec.get('parse_error')}``. "
                    "Either malformed YAML, a too-large file, or "
                    "a schema digger doesn't yet handle. Worth a "
                    "manual review — a workflow that the GitHub "
                    "runner accepts but a YAML parser rejects "
                    "is itself a smell."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "workflow_parse_error",
                    "file_path": file_path,
                    "parse_error": rec.get("parse_error"),
                },
                mitre="T1195.002",
            )
            return

        # W1 pwn-request
        if rec.get("has_pull_request_target_with_checkout_head"):
            yield Finding(
                detector=self.name,
                severity="critical",
                title=(
                    f"pwn-request pattern: pull_request_target "
                    f"+ checkout of PR head: {label}"
                ),
                summary=(
                    f"Workflow ``{label}`` uses the "
                    "``pull_request_target`` trigger AND checks "
                    "out the PR's head ref (attacker-controlled "
                    "code) into the privileged base-repo context. "
                    "This is the canonical 'pwn-request' pattern "
                    "documented by GitHub Security Lab — the "
                    "checked-out code runs with the repo's "
                    "GITHUB_TOKEN + secrets, so an attacker's PR "
                    "build script exfiltrates them. Either switch "
                    "to ``pull_request`` (no secrets), or check "
                    "out the *base* ref and only run trusted "
                    "code against the PR diff."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "pwn_request",
                    "file_path": file_path,
                    "workflow_name": workflow_name,
                    "triggers": rec.get("on_triggers"),
                },
                mitre="T1199",
            )

        # W2 workflow_run trigger
        if rec.get("has_workflow_run_trigger"):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"workflow_run trigger: {label}"
                ),
                summary=(
                    f"Workflow ``{label}`` is triggered by "
                    "``workflow_run`` — i.e., it runs after some "
                    "other workflow finishes, in privileged "
                    "context and with access to that workflow's "
                    "artifacts. Forked-PR test runs are a "
                    "common originating workflow, so the "
                    "attacker effectively controls a downstream "
                    "privileged context. Review the originator "
                    "workflow's outputs are validated before "
                    "this one consumes them."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "workflow_run_trigger",
                    "file_path": file_path,
                    "workflow_name": workflow_name,
                    "triggers": rec.get("on_triggers"),
                },
                mitre="T1199",
            )

        # W3 injectable interpolations
        injectables = rec.get("injectable_interpolations") or []
        if injectables:
            ctxs = sorted({i.get("context", "") for i in injectables})[:8]
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Untrusted-input interpolation in run: "
                    f"block ({len(injectables)} sites): {label}"
                ),
                summary=(
                    f"Workflow ``{label}`` interpolates "
                    f"attacker-controllable ``${{{{ <context> }}}}`` "
                    f"expressions into ``run:`` blocks "
                    f"({len(injectables)} occurrences). Detected "
                    f"contexts: ``{', '.join(ctxs)}``. Any user "
                    "with permission to open a PR / file an "
                    "issue / leave a comment can write the "
                    "interpolation target — and the workflow's "
                    "bash interpreter then executes it. Replace "
                    "with an env var: ``env: { PR_TITLE: "
                    "${{ github.event.pull_request.title }} }`` "
                    "and then ``echo \"$PR_TITLE\"`` (no eval)."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "injectable_interpolation",
                    "file_path": file_path,
                    "occurrence_count": len(injectables),
                    "contexts": ctxs,
                    "samples": injectables[:5],
                },
                mitre="T1059",
            )

        # W4 unpinned third-party action
        unpinned: list[dict] = []
        for act in (rec.get("actions") or []):
            if act.get("is_local"):
                continue
            if act.get("is_trusted_owner"):
                continue
            if not act.get("sha_pinned"):
                unpinned.append({
                    "uses": act.get("uses"),
                    "owner": act.get("owner"),
                    "repo": act.get("repo"),
                    "ref": act.get("ref"),
                })
        if unpinned:
            sample = sorted({u["uses"] for u in unpinned})[:8]
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Unpinned third-party action(s) "
                    f"({len(unpinned)}): {label}"
                ),
                summary=(
                    f"Workflow ``{label}`` uses "
                    f"{len(unpinned)} third-party GitHub Action(s) "
                    f"that are not SHA-pinned: ``{', '.join(sample)}``. "
                    "Moving tags (``@v4``, ``@main``) silently "
                    "follow whatever the action's owner publishes "
                    "— a single compromised account becomes "
                    "compromised CI for every consumer (Tj-"
                    "actions/changed-files attack). Pin to a "
                    "full SHA. Extend the trusted-owner "
                    "allowlist via DIGGER_CI_TRUSTED_ACTION_OWNERS."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "unpinned_third_party_action",
                    "file_path": file_path,
                    "actions": unpinned[:16],
                },
                mitre="T1195.002",
            )

        # W5 persist-credentials: true
        if rec.get("has_persist_credentials_true"):
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Checkout step keeps GITHUB_TOKEN in "
                    f".git/config: {label}"
                ),
                summary=(
                    f"Workflow ``{label}`` runs an "
                    "actions/checkout with ``persist-credentials: "
                    "true``. The GITHUB_TOKEN gets baked into "
                    "``.git/config`` and is then available to "
                    "every subsequent step — including any "
                    "third-party action and any build script "
                    "the workflow runs. Unless you specifically "
                    "need to push commits back, set persist-"
                    "credentials: false."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "persist_credentials",
                    "file_path": file_path,
                    "workflow_name": workflow_name,
                },
                mitre="T1552.001",
            )

        # W6 permissions
        if rec.get("permissions_top_level") in (
            "write-all", "default",
        ):
            sev = "medium" if \
                rec.get("permissions_top_level") == "write-all" \
                else "info"
            title_word = (
                "write-all"
                if rec.get("permissions_top_level") == "write-all"
                else "no top-level permissions block (legacy "
                     "default)"
            )
            yield Finding(
                detector=self.name,
                severity=sev,
                title=(
                    f"Permissions: {title_word}: {label}"
                ),
                summary=(
                    f"Workflow ``{label}`` runs with "
                    f"``permissions: {rec.get('permissions_top_level')}``. "
                    "Without an explicit minimal permissions "
                    "block, the workflow's GITHUB_TOKEN gets the "
                    "org-default (often write-all on legacy "
                    "orgs), with contents: write / packages: "
                    "write — keys to publish releases. Lock "
                    "down to e.g. ``permissions: { contents: "
                    "read }``."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "permissions_write_all",
                    "file_path": file_path,
                    "permissions_top_level":
                        rec.get("permissions_top_level"),
                },
                mitre="T1078.004",
            )

        # W7 self-modifying workflow
        if rec.get("self_modifying"):
            yield Finding(
                detector=self.name,
                severity="critical",
                title=(
                    f"Self-modifying workflow (writes to "
                    f".github/workflows/): {label}"
                ),
                summary=(
                    f"Workflow ``{label}`` contains at least one "
                    "step that writes into ``.github/workflows/``. "
                    "Modifying or installing a workflow from "
                    "within another workflow is the textbook "
                    "worm-persistence primitive (Shai-Hulud, "
                    "octofiles, the GitGuardian-described "
                    "self-replicating workflow). Even if benign, "
                    "this pattern almost always wants a code "
                    "review by hand."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "self_modifying_workflow",
                    "file_path": file_path,
                },
                mitre="T1195.002",
            )
