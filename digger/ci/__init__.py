"""CI/CD pipeline security auditor — GitHub Actions workflows.

CI pipelines are the highest-leverage attack surface in modern
development. A compromised workflow runs with secrets, can publish
to package registries, and re-keys the production environment.
The canonical attack patterns (covered by W1-W7) are documented
research from GitHub Security Lab, Trail of Bits, and the Aqua
Nautilus team:

  - ``pull_request_target`` + checkout-of-head-ref (Adam Berman's
    "GHSL-2022-058" pattern — pwn-request)
  - Unpinned third-party actions (Tj-actions/changed-files
    compromise)
  - Untrusted-input interpolation in ``run:`` blocks (script
    injection via PR title / issue body)
  - persist-credentials: true after checkout (token re-use)
  - Self-modifying workflows
  - workflow_run triggered from forked PR contexts

Public API
----------
``audit_workflows(roots) -> list[WorkflowRecord]``
``WorkflowRecord`` — single workflow file's parsed result
``CiAuditError`` — raised on caller misuse
``emit_records_to_store(records, store)``
"""

from __future__ import annotations

from digger.ci.workflow_auditor import (
    CiAuditError,
    WorkflowAction,
    WorkflowRecord,
    audit_workflows,
    emit_records_to_store,
    parse_workflow_file,
)

__all__ = [
    "CiAuditError",
    "WorkflowAction",
    "WorkflowRecord",
    "audit_workflows",
    "emit_records_to_store",
    "parse_workflow_file",
]
