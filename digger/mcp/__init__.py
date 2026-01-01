"""MCP (Model Context Protocol) configuration auditor.

LLM agents (Claude Desktop, Claude Code, Cursor, Continue, Cline,
Roo, Aider, Goose, etc.) load tool definitions at startup from a
local MCP server registry. Every MCP server runs as a subprocess
or HTTP endpoint with the same privileges as the host process —
so a malicious MCP server gets shell, filesystem, and credential
access. The 2025-2026 "tool poisoning" research thread shows this
is being actively abused: typo-squatted npm packages, suspicious
GitHub repos, prompt-injection via tool descriptions.

Public API
----------
``audit_mcp_configs(roots=None) -> list[McpServerRecord]``
``McpServerRecord`` — single MCP-server entry's audit result
``MCP_CONFIG_LOCATIONS`` — well-known config paths digger searches
``parse_config_file(path) -> list[McpServerRecord]``
``emit_records_to_store(records, store)``
"""

from __future__ import annotations

from digger.mcp.auditor import (
    MCP_CONFIG_LOCATIONS,
    McpAuditError,
    McpServerRecord,
    audit_mcp_configs,
    emit_records_to_store,
    parse_config_file,
)

__all__ = [
    "MCP_CONFIG_LOCATIONS",
    "McpAuditError",
    "McpServerRecord",
    "audit_mcp_configs",
    "emit_records_to_store",
    "parse_config_file",
]
