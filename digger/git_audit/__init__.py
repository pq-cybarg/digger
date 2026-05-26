"""Git repository security auditor.

Closes a long-standing supply-chain gap: every developer host has
dozens of git repos under it, and ``.git/hooks/*`` runs with the
user's privileges on every `git pull` / `git commit` / `git
checkout`. A poisoned ``post-checkout`` runs silently on every
operation. Existing digger detectors (TrapDoor) only match specific
campaign markers; this auditor catches the general patterns.

Strictly read-only: never writes to the repo, never disables a hook
(remediation is reported, not applied).

Public API
----------
``audit_git_repos(roots) -> list[GitHookRecord]``
``GitHookRecord`` — one record per executable hook
``parse_hook(path) -> GitHookRecord``
``emit_records_to_store(records, store)``
"""

from __future__ import annotations

from digger.git_audit.auditor import (
    GitAuditError,
    GitHookRecord,
    HOOK_NAMES,
    audit_git_repos,
    emit_records_to_store,
    parse_hook,
)

__all__ = [
    "GitAuditError",
    "GitHookRecord",
    "HOOK_NAMES",
    "audit_git_repos",
    "emit_records_to_store",
    "parse_hook",
]
