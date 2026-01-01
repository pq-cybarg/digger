"""VS Code extension + settings security auditor.

VS Code extensions run with the user's privileges, share the
window's network access, and (with no sandbox in the stable
build) can read every workspace file digger's operator opens.
A malicious extension OR a settings.json that disables workspace
trust is the textbook silent-exec persistence vector on
developer hosts.

Public API
----------
``audit_vscode(roots=None) -> VsCodeAudit``
``VsCodeAudit`` — top-level result (extensions + settings)
``VsCodeExtension`` — one extension record
``VsCodeSettings`` — one settings file's parsed contents
``parse_extension_dir(path) -> VsCodeExtension``
``parse_settings_file(path) -> VsCodeSettings``
``emit_records_to_store(audit, store)``
"""

from __future__ import annotations

from digger.vscode.auditor import (
    KNOWN_GOOD_PUBLISHERS,
    VsCodeAudit,
    VsCodeAuditError,
    VsCodeExtension,
    VsCodeSettings,
    audit_vscode,
    emit_records_to_store,
    parse_extension_dir,
    parse_settings_file,
)

__all__ = [
    "KNOWN_GOOD_PUBLISHERS",
    "VsCodeAudit",
    "VsCodeAuditError",
    "VsCodeExtension",
    "VsCodeSettings",
    "audit_vscode",
    "emit_records_to_store",
    "parse_extension_dir",
    "parse_settings_file",
]
