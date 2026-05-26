"""MCP (Model Context Protocol) configuration auditor.

Reads MCP-server entries from every common host configuration we
know about (Claude Desktop, Claude Code, Cursor, Continue, Cline,
Roo Code, .mcp.json in the repo). Each server entry yields one
McpServerRecord, which the ``mcp_audit`` detector then walks for
suspicious patterns.

What we look at
---------------
- ``command`` and ``args`` (subprocess form: stdio transport)
- ``env`` (server-supplied environment variables; some contain
  credentials — flag them)
- ``url`` (network transport: sse, http, websocket)
- ``transport`` (stdio / sse / http / ws)
- the parsed package identity (npm, pypi, github URL, raw script
  path) — feeds the typo-squat / authorship checks
- whether the server config came from a project file (.mcp.json
  in cwd) or a global user file — project files are higher risk
  because they ship with repos and a `git clone` is enough to
  enroll a server

Strictly local: digger does NOT fetch the published package, run
the binary, or talk to the registry. Network-side checks (SLSA,
typo-squat distance, registry sig) belong in adjacent detectors.

Common config paths searched
----------------------------
Linux / macOS:
  ~/.config/Claude/claude_desktop_config.json
  ~/Library/Application Support/Claude/claude_desktop_config.json
  ~/.claude/settings.json
  ~/.claude.json
  ~/.cursor/mcp.json
  ~/.continue/config.json
  ~/.config/io.continue.continue/config.json
  ~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json
  ~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json

Windows: %APPDATA%\\Claude\\claude_desktop_config.json (+ same
under %USERPROFILE%).

Project-level (always added):
  ./.mcp.json
  ./.claude/settings.json
  ./.cursor/mcp.json
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class McpAuditError(RuntimeError):
    """Raised on bad input (e.g. caller passes a malformed roots
    argument). Walker / per-file failures are NOT raised; they are
    recorded as parse_error fields on the record."""


# ---- canonical config locations ---- #
#
# Substituted at runtime with $HOME / %APPDATA% / the project cwd.
# Project-level paths are flagged ``project_scoped=True`` because
# they ship in git repos and execute automatically when the agent
# launches.

MCP_CONFIG_LOCATIONS = (
    # (relative path under base, kind, project_scoped)
    ("$HOME/.config/Claude/claude_desktop_config.json",
     "claude_desktop", False),
    ("$HOME/Library/Application Support/Claude/claude_desktop_config.json",
     "claude_desktop", False),
    ("$HOME/AppData/Roaming/Claude/claude_desktop_config.json",
     "claude_desktop", False),
    ("$HOME/.claude/settings.json", "claude_code", False),
    ("$HOME/.claude.json", "claude_code", False),
    ("$HOME/.cursor/mcp.json", "cursor", False),
    ("$HOME/.continue/config.json", "continue", False),
    ("$HOME/.config/io.continue.continue/config.json", "continue", False),
    ("$HOME/.config/Code/User/globalStorage/"
     "saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
     "cline", False),
    ("$HOME/.config/Code/User/globalStorage/"
     "rooveterinaryinc.roo-cline/settings/mcp_settings.json",
     "roo_code", False),
    # Project-scoped: relative to cwd. Higher risk.
    ("$CWD/.mcp.json", "project", True),
    ("$CWD/.claude/settings.json", "project", True),
    ("$CWD/.cursor/mcp.json", "project", True),
)


# ---- record shape ---- #


@dataclass
class McpServerRecord:
    name: str                          # the server's nickname / key
    config_path: str                   # source file
    config_kind: str                   # claude_desktop / cursor / ...
    project_scoped: bool = False       # came from a .mcp.json in cwd
    command: str = ""                  # subprocess form (stdio)
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    transport: str = "stdio"           # stdio / sse / http / ws
    url: str = ""                      # for non-stdio transports
    pkg_ecosystem: str = ""            # npm / pypi / github / raw
    pkg_identifier: str = ""           # @scope/pkg, pypi name, etc.
    pkg_scope: str = ""                # extracted scope prefix
    auto_approve: list[str] = field(default_factory=list)
    disabled: bool = False
    parse_error: str = ""


# ---- helpers ---- #


_MAX_CONFIG_BYTES = 4 * 1024 * 1024


def _expand_paths(roots: Iterable[Path | str] | None) -> list[
    tuple[Path, str, bool],
]:
    if roots is not None:
        return [(Path(p), "manual", False) for p in roots if Path(p).exists()]
    home = Path.home()
    cwd = Path.cwd()
    out: list[tuple[Path, str, bool]] = []
    for tmpl, kind, project_scoped in MCP_CONFIG_LOCATIONS:
        rendered = tmpl.replace("$HOME", str(home)).replace(
            "$CWD", str(cwd),
        )
        p = Path(rendered)
        if p.is_file():
            out.append((p, kind, project_scoped))
    return out


def _truncate_value(v: Any, n: int = 512) -> str:
    s = str(v)
    return s if len(s) <= n else s[:n] + "…"


def _classify_package(command: str, args: list[str]) -> tuple[
    str, str, str,
]:
    """Return (ecosystem, identifier, scope_prefix)."""
    if command == "npx" and args:
        # find the first non-flag arg
        for a in args:
            if a.startswith("-"):
                continue
            ident = a.split("@")[0] if a.startswith("@") is False else a
            scope = ""
            if ident.startswith("@") and "/" in ident:
                scope = ident.split("/", 1)[0]
            return ("npm", a, scope)
        return ("npm", "", "")
    if command in ("uvx", "pipx") and args:
        for a in args:
            if a.startswith("-"):
                continue
            return ("pypi", a, "")
        return ("pypi", "", "")
    if command in ("node",) and args:
        # raw node script — flag as 'raw'
        return ("raw_node", args[0] if args else "", "")
    if command in ("python", "python3") and args:
        return ("raw_python", args[0] if args else "", "")
    if command.startswith("http://") or command.startswith("https://") \
            or command.startswith("ws://"):
        return ("network", command, "")
    if command.endswith(".sh") or command.endswith(".bash"):
        return ("raw_shell", command, "")
    return ("binary", command, "")


# ---- per-file parsing ---- #


def parse_config_file(
    path: Path | str,
    *,
    config_kind: str = "unknown",
    project_scoped: bool = False,
) -> list[McpServerRecord]:
    """Parse one MCP-style config file and return one record per
    declared server.

    Tolerates the four shapes we see in the wild:
      - {"mcpServers": {name: {...}, ...}}              (Claude Desktop, Cursor)
      - {"mcp": {"servers": {name: {...}, ...}}}        (newer Anthropic)
      - {"mcpServers": [{name: ..., ...}, ...]}         (some forks)
      - {"servers": [...]} or {"models": [...mcps...]}  (Continue)

    A missing / malformed file produces no records but logs no
    exception."""
    p = Path(path)
    if not p.is_file():
        return []
    try:
        sz = p.stat().st_size
    except OSError:
        return []
    if sz > _MAX_CONFIG_BYTES:
        return [McpServerRecord(
            name="<oversize>",
            config_path=str(p),
            config_kind=config_kind,
            project_scoped=project_scoped,
            parse_error=f"config file {sz} bytes > "
                        f"{_MAX_CONFIG_BYTES} cap",
        )]
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            blob = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return [McpServerRecord(
            name="<unparseable>",
            config_path=str(p),
            config_kind=config_kind,
            project_scoped=project_scoped,
            parse_error=f"{type(exc).__name__}: {exc}",
        )]
    return _extract_servers(blob, p, config_kind, project_scoped)


def _extract_servers(
    blob: Any,
    source: Path,
    config_kind: str,
    project_scoped: bool,
) -> list[McpServerRecord]:
    out: list[McpServerRecord] = []
    if not isinstance(blob, dict):
        return out

    # Container shapes
    containers: list[tuple[str, Any]] = []
    if "mcpServers" in blob:
        containers.append(("mcpServers", blob["mcpServers"]))
    if isinstance(blob.get("mcp"), dict) and \
            "servers" in blob["mcp"]:
        containers.append(("mcp.servers", blob["mcp"]["servers"]))
    if isinstance(blob.get("servers"), list):
        containers.append(("servers", blob["servers"]))

    for _container_name, container in containers:
        if isinstance(container, dict):
            for name, raw in container.items():
                if not isinstance(raw, dict):
                    continue
                out.append(_parse_one_server(
                    raw, name=str(name),
                    source=source, config_kind=config_kind,
                    project_scoped=project_scoped,
                ))
        elif isinstance(container, list):
            for idx, raw in enumerate(container):
                if not isinstance(raw, dict):
                    continue
                name = str(raw.get("name") or raw.get("id")
                           or f"server-{idx}")
                out.append(_parse_one_server(
                    raw, name=name,
                    source=source, config_kind=config_kind,
                    project_scoped=project_scoped,
                ))
    return out


def _parse_one_server(
    raw: dict[str, Any],
    *,
    name: str,
    source: Path,
    config_kind: str,
    project_scoped: bool,
) -> McpServerRecord:
    rec = McpServerRecord(
        name=name,
        config_path=str(source),
        config_kind=config_kind,
        project_scoped=project_scoped,
    )
    rec.command = str(raw.get("command") or "")
    args = raw.get("args") or []
    if isinstance(args, list):
        rec.args = [_truncate_value(a) for a in args[:64]]
    env = raw.get("env") or {}
    if isinstance(env, dict):
        rec.env = {
            str(k)[:128]: _truncate_value(v, 256)
            for k, v in list(env.items())[:64]
        }
    transport = raw.get("transport") or raw.get("type") or ""
    url = raw.get("url") or raw.get("baseUrl") or ""
    if url:
        rec.url = _truncate_value(url, 512)
        rec.transport = (transport or "http").lower()
    elif transport:
        rec.transport = transport.lower()
    auto = raw.get("autoApprove") or raw.get("auto_approve") or []
    if isinstance(auto, list):
        rec.auto_approve = [_truncate_value(a) for a in auto[:64]]
    if raw.get("disabled") in (True, "true", 1):
        rec.disabled = True
    eco, ident, scope = _classify_package(rec.command, rec.args)
    rec.pkg_ecosystem = eco
    rec.pkg_identifier = ident
    rec.pkg_scope = scope
    return rec


# ---- discovery walker ---- #


def audit_mcp_configs(
    roots: Iterable[Path | str] | None = None,
) -> list[McpServerRecord]:
    """Audit MCP config files at every well-known location (or the
    supplied ``roots`` list of explicit files)."""
    paths = _expand_paths(roots)
    records: list[McpServerRecord] = []
    if roots is not None:
        for p, _kind, _proj in paths:
            records += parse_config_file(p)
    else:
        for p, kind, project_scoped in paths:
            records += parse_config_file(
                p, config_kind=kind,
                project_scoped=project_scoped,
            )
    return records


# ---- emit to store ---- #


def emit_records_to_store(records: Iterable[McpServerRecord], store) -> int:
    from dataclasses import asdict
    from digger.core.evidence import Artifact
    n = 0
    for rec in records:
        data = asdict(rec)
        subject = (
            f"mcp:{rec.config_kind}:{rec.name}"
        )
        store.add_artifact(Artifact(
            collector="mcp.audit",
            category="ai_tools",
            subject=subject[:380],
            data=data,
        ))
        n += 1
    return n
