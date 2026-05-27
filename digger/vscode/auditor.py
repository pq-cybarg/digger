"""VS Code extension + user-settings auditor.

What's parsed
-------------
For every extension directory under ~/.vscode/extensions/ (or the
operator-supplied roots), we read:
  - package.json (publisher, name, version, displayName, main,
                  activationEvents, contributes commands, capabilities)
  - .vsixmanifest (sourceMarketplace identifier — Marketplace vs
                   side-loaded VSIX)

For every settings.json at:
  - ~/Library/Application Support/Code/User/settings.json (macOS)
  - ~/.config/Code/User/settings.json (Linux)
  - %APPDATA%/Code/User/settings.json (Windows)
  - Project-scoped ./.vscode/settings.json (always added)

we capture the security-relevant keys:
  - security.workspace.trust.enabled (false = warn)
  - security.workspace.trust.untrustedFiles (open vs prompt)
  - http.proxyStrictSSL (false = MITM-ready)
  - terminal.integrated.shell.* / defaultProfile.* (custom shell)
  - terminal.integrated.automationProfile.* (used by extensions)
  - task autoDetect flags
  - extensions.autoCheckUpdates / autoUpdate

Strictly read-only.
"""

from __future__ import annotations

import json
import os
import platform
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


class VsCodeAuditError(RuntimeError):
    pass


_MAX_SETTINGS_BYTES = 4 * 1024 * 1024
_MAX_MANIFEST_BYTES = 1 * 1024 * 1024
_MAX_EXTENSIONS_PER_ROOT = 4000


# Verified-publisher allowlist for VS Code Marketplace. Substring-
# matched against package.json "publisher". Extend via env var
# DIGGER_VSCODE_TRUSTED_PUBLISHERS.
KNOWN_GOOD_PUBLISHERS = frozenset({
    # Microsoft + first-party
    "ms-python", "ms-azuretools", "ms-vscode", "ms-vscode-remote",
    "ms-toolsai", "ms-dotnettools", "ms-edgedevtools",
    "ms-mssql", "ms-azure-devops", "ms-edu", "ms-iot",
    "github", "vscode", "vscodevim",
    "anthropic", "anthropic-experimental",
    "openai",
    # Popular language servers / formatters
    "rust-lang", "golang", "redhat", "esbenp", "dbaeumer",
    "tamasfe", "denoland", "biomejs", "charliermarsh",
    "kevinrose", "bradlc", "stylelint",
    # Editors / IDE helpers
    "eamodio", "gruntfuggly", "streetsidesoftware",
    "editorconfig", "humao", "rangav", "redocly",
    "tabnine", "continue", "supermaven", "saoudrizwan",
    "rooveterinaryinc", "blackboxapp", "cline", "augment",
    # Containers / cloud
    "ms-azuretools", "amazonwebservices", "googlecloudtools",
    "hashicorp", "fwcd",
})


def _trusted_publishers() -> tuple[str, ...]:
    extra = os.environ.get("DIGGER_VSCODE_TRUSTED_PUBLISHERS", "")
    parts = [s.strip().lower() for s in extra.split(",") if s.strip()]
    return tuple(sorted(KNOWN_GOOD_PUBLISHERS | set(parts)))


# ---- record shapes ---- #


@dataclass
class VsCodeExtension:
    extension_dir: str
    publisher: str = ""
    name: str = ""
    version: str = ""
    display_name: str = ""
    main: str = ""
    activation_events: list[str] = field(default_factory=list)
    declared_capabilities: list[str] = field(default_factory=list)
    contributes_commands_count: int = 0
    is_marketplace_install: bool | None = None
    parse_error: str = ""


@dataclass
class VsCodeSettings:
    settings_path: str
    project_scoped: bool = False
    workspace_trust_enabled: bool | None = None
    workspace_trust_untrusted_files: str = ""
    http_proxy_strict_ssl: bool | None = None
    custom_default_shell: dict[str, str] = field(default_factory=dict)
    custom_automation_profile: dict[str, str] = field(default_factory=dict)
    task_auto_detect: dict[str, str] = field(default_factory=dict)
    extensions_auto_update: bool | None = None
    extensions_auto_check_updates: bool | None = None
    parse_error: str = ""


@dataclass
class VsCodeAudit:
    extensions: list[VsCodeExtension] = field(default_factory=list)
    settings: list[VsCodeSettings] = field(default_factory=list)


# ---- helpers ---- #


def _expand_extension_roots(
    roots: Iterable[Path | str] | None,
) -> list[Path]:
    if roots is not None:
        return [Path(r) for r in roots if Path(r).exists()]
    home = Path.home()
    candidates = [
        home / ".vscode" / "extensions",
        home / ".vscode-insiders" / "extensions",
        home / ".vscode-oss" / "extensions",
        home / ".cursor" / "extensions",
        home / ".windsurf" / "extensions",
    ]
    if platform.system() == "Windows":
        candidates += [
            home / "AppData" / "Roaming" / "Code" / "User" / "extensions",
        ]
    return [p for p in candidates if p.is_dir()]


def _expand_settings_paths() -> list[tuple[Path, bool]]:
    """Return (path, project_scoped) for every settings file we know about."""
    home = Path.home()
    cwd = Path.cwd()
    out: list[tuple[Path, bool]] = []
    out += [
        (home / "Library/Application Support/Code/User/settings.json", False),
        (home / "Library/Application Support/Code - Insiders/User/settings.json", False),
        (home / "Library/Application Support/Cursor/User/settings.json", False),
        (home / ".config/Code/User/settings.json", False),
        (home / ".config/Code - Insiders/User/settings.json", False),
        (home / ".config/Cursor/User/settings.json", False),
        (home / "AppData/Roaming/Code/User/settings.json", False),
        (home / "AppData/Roaming/Cursor/User/settings.json", False),
        (cwd / ".vscode" / "settings.json", True),
    ]
    return [(p, ps) for p, ps in out if p.is_file()]


# ---- parsing: extension ---- #


def parse_extension_dir(path: Path | str) -> VsCodeExtension | None:
    p = Path(path)
    if not p.is_dir():
        return None
    pkg_path = p / "package.json"
    rec = VsCodeExtension(extension_dir=str(p))
    if not pkg_path.is_file():
        rec.parse_error = "no package.json"
        return rec
    try:
        sz = pkg_path.stat().st_size
    except OSError as exc:
        rec.parse_error = f"stat failed: {exc}"
        return rec
    if sz > _MAX_MANIFEST_BYTES:
        rec.parse_error = f"package.json {sz} bytes > cap"
        return rec
    try:
        with open(pkg_path, encoding="utf-8", errors="replace") as fh:
            meta = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        rec.parse_error = f"{type(exc).__name__}: {exc}"
        return rec
    if not isinstance(meta, dict):
        rec.parse_error = "package.json not a mapping"
        return rec
    rec.publisher = str(meta.get("publisher") or "")[:128]
    rec.name = str(meta.get("name") or "")[:128]
    rec.version = str(meta.get("version") or "")[:64]
    rec.display_name = str(meta.get("displayName") or "")[:200]
    rec.main = str(meta.get("main") or "")[:256]
    if isinstance(meta.get("activationEvents"), list):
        rec.activation_events = [
            str(e)[:200]
            for e in meta["activationEvents"][:32]
        ]
    caps = meta.get("capabilities") or {}
    if isinstance(caps, dict):
        rec.declared_capabilities = sorted(
            str(k)[:64] for k in caps.keys()
        )[:16]
    contributes = meta.get("contributes") or {}
    if isinstance(contributes, dict):
        cmds = contributes.get("commands")
        if isinstance(cmds, list):
            rec.contributes_commands_count = len(cmds)

    # .vsixmanifest sourceMarketplace check
    vsix = p / ".vsixmanifest"
    if vsix.is_file():
        try:
            text = vsix.read_text(encoding="utf-8", errors="replace")
            rec.is_marketplace_install = (
                "ExtensionMarketplace" in text
                or "Marketplace" in text
            )
        except OSError:
            rec.is_marketplace_install = None
    return rec


# ---- parsing: settings ---- #


_TRUTHY = (True, "true", "True", 1)
_FALSEY = (False, "false", "False", 0)


def _as_bool(v) -> bool | None:
    if v in _TRUTHY:
        return True
    if v in _FALSEY:
        return False
    return None


def parse_settings_file(
    path: Path | str,
    *,
    project_scoped: bool = False,
) -> VsCodeSettings:
    p = Path(path)
    rec = VsCodeSettings(
        settings_path=str(p),
        project_scoped=project_scoped,
    )
    if not p.is_file():
        rec.parse_error = "not a file"
        return rec
    try:
        sz = p.stat().st_size
    except OSError as exc:
        rec.parse_error = f"stat failed: {exc}"
        return rec
    if sz > _MAX_SETTINGS_BYTES:
        rec.parse_error = f"settings {sz} bytes > cap"
        return rec
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        rec.parse_error = f"read failed: {exc}"
        return rec

    # VS Code settings.json allows JSONC (// comments + trailing commas).
    cleaned = _strip_jsonc_comments(text)
    try:
        blob = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        rec.parse_error = f"JSON parse: {exc}"
        return rec
    if not isinstance(blob, dict):
        rec.parse_error = "top-level not a mapping"
        return rec

    rec.workspace_trust_enabled = _as_bool(
        blob.get("security.workspace.trust.enabled"),
    )
    untrusted = blob.get("security.workspace.trust.untrustedFiles")
    if isinstance(untrusted, str):
        rec.workspace_trust_untrusted_files = untrusted
    rec.http_proxy_strict_ssl = _as_bool(
        blob.get("http.proxyStrictSSL"),
    )
    for k in (
        "terminal.integrated.shell.linux",
        "terminal.integrated.shell.osx",
        "terminal.integrated.shell.windows",
        "terminal.integrated.defaultProfile.linux",
        "terminal.integrated.defaultProfile.osx",
        "terminal.integrated.defaultProfile.windows",
    ):
        v = blob.get(k)
        if isinstance(v, str) and v:
            rec.custom_default_shell[k] = v[:512]
    for k in (
        "terminal.integrated.automationProfile.linux",
        "terminal.integrated.automationProfile.osx",
        "terminal.integrated.automationProfile.windows",
    ):
        v = blob.get(k)
        if isinstance(v, dict):
            path_val = v.get("path") or v.get("source") or ""
            if isinstance(path_val, str):
                rec.custom_automation_profile[k] = path_val[:512]
        elif isinstance(v, str):
            rec.custom_automation_profile[k] = v[:512]
    for k in (
        "task.autoDetect", "npm.autoDetect", "gulp.autoDetect",
        "grunt.autoDetect", "typescript.tsc.autoDetect",
    ):
        v = blob.get(k)
        if isinstance(v, str):
            rec.task_auto_detect[k] = v
    rec.extensions_auto_update = _as_bool(
        blob.get("extensions.autoUpdate"),
    )
    rec.extensions_auto_check_updates = _as_bool(
        blob.get("extensions.autoCheckUpdates"),
    )
    return rec


def _strip_jsonc_comments(text: str) -> str:
    """Strip // line + /* */ block comments and trailing commas
    (good enough for VS Code settings.json files; not a full JSONC
    parser)."""
    import re
    # Remove block comments (non-greedy).
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # Remove line comments (only if not inside a string literal —
    # approximated by scanning line-by-line, skipping lines whose
    # // is preceded by an odd number of quotes).
    out_lines: list[str] = []
    for raw in text.splitlines():
        # Walk char by char, tracking string state.
        in_str = False
        escape = False
        cut = None
        for i, ch in enumerate(raw):
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "/" and i + 1 < len(raw) and raw[i + 1] == "/":
                    cut = i
                    break
        out_lines.append(raw if cut is None else raw[:cut])
    text = "\n".join(out_lines)
    # Strip trailing commas before } or ]
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return text


# ---- discovery walker ---- #


def audit_vscode(
    roots: Iterable[Path | str] | None = None,
) -> VsCodeAudit:
    audit = VsCodeAudit()
    for ext_root in _expand_extension_roots(roots):
        try:
            count = 0
            for child in sorted(ext_root.iterdir()):
                if count >= _MAX_EXTENSIONS_PER_ROOT:
                    break
                if not child.is_dir():
                    continue
                rec = parse_extension_dir(child)
                if rec is not None:
                    audit.extensions.append(rec)
                    count += 1
        except OSError:
            continue
    for s_path, project_scoped in _expand_settings_paths():
        audit.settings.append(
            parse_settings_file(s_path, project_scoped=project_scoped),
        )
    return audit


# ---- emit to store ---- #


def emit_records_to_store(audit: VsCodeAudit, store) -> int:
    from dataclasses import asdict
    from digger.core.evidence import Artifact
    n = 0
    for ext in audit.extensions:
        data = asdict(ext)
        subject = (
            f"vscode:extension:{ext.publisher}.{ext.name}@{ext.version}"
        )
        store.add_artifact(Artifact(
            collector="vscode.extension",
            category="dev_env",
            subject=subject[:380],
            data=data,
        ))
        n += 1
    for s in audit.settings:
        data = asdict(s)
        subject = f"vscode:settings:{s.settings_path}"
        store.add_artifact(Artifact(
            collector="vscode.settings",
            category="dev_env",
            subject=subject[:380],
            data=data,
        ))
        n += 1
    return n
