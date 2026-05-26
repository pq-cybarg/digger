"""MCP (Model Context Protocol) configuration security detector.

Reads ``mcp.audit`` Artifacts (one per declared MCP server) and
emits findings for the five canonical tool-poisoning patterns:

  P1  Project-scoped auto-installing MCP server: high
      The server is declared in a project-local file (.mcp.json,
      .cursor/mcp.json, .claude/settings.json in the repo root)
      and runs at agent launch. Cloning a malicious repo + opening
      it in the agent = arbitrary code exec. The original npm /
      pypi typo-squat dropper attack shape, adapted to AI tooling.

  P2  Server runs an arbitrary script (raw_node / raw_python /
      raw_shell): high
      command=node|python|bash + args=[<file>] means the agent
      runs a local script. The script's filename is the only
      identity check the operator has; rename to look benign and
      hide the payload.

  P3  Environment variables look like credentials: high
      The server's ``env`` block contains key/value pairs whose
      names match well-known credential shapes (AWS_*, GITHUB_TOKEN,
      *_SECRET, *_API_KEY). The MCP server will inherit them at
      exec, with no scoping. Even if the server is benign, this is
      bad hygiene worth surfacing.

  P4  Network transport (sse/http/ws) to unaudited URL: medium
      The server is reached over a network socket rather than the
      stdio-piped subprocess model. The agent's tool catalog is
      then dictated by a remote endpoint; prompt-injection via
      tool descriptions becomes possible.

  P5  Typo-squat-suspicious npm scope: medium
      The npm package's scope prefix is not on the known-good
      MCP-author allowlist (modelcontextprotocol, anthropic-ai,
      cline, etc). The package may be legitimate, but for first-
      party users this is worth confirming.

The detector consumes Artifacts emitted by
``digger.mcp.audit_mcp_configs`` + ``emit_records_to_store``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- tunables ---- #

# Known-good npm scopes / first-party authors for MCP servers.
# Extend via DIGGER_MCP_TRUSTED_SCOPES env var (comma-separated).
KNOWN_GOOD_NPM_SCOPES = {
    "@modelcontextprotocol",     # reference MCP servers
    "@anthropic-ai",
    "@continuedev",
    "@cline",
    "@roo-cline",
    "@cursor",
    "@google",
    "@openai",
    "@microsoft",
    "@github",
}

# Credential-shape variable name patterns. Case-insensitive.
_CRED_PATTERNS = (
    re.compile(r"(?i)api[_-]?key"),
    re.compile(r"(?i)secret"),
    re.compile(r"(?i)token$"),
    re.compile(r"(?i)password"),
    re.compile(r"(?i)access[_-]?key"),
    re.compile(r"(?i)private[_-]?key"),
    re.compile(r"^AWS_"),
    re.compile(r"^GITHUB_TOKEN"),
    re.compile(r"^GH_TOKEN"),
    re.compile(r"^DATABASE_URL"),
    re.compile(r"^OPENAI_"),
    re.compile(r"^ANTHROPIC_"),
    re.compile(r"^AZURE_"),
    re.compile(r"^GOOGLE_APPLICATION_CREDENTIALS"),
    re.compile(r"^STRIPE_"),
    re.compile(r"^TWILIO_"),
)

_NETWORK_TRANSPORTS = {"sse", "http", "https", "ws", "wss"}


def _looks_like_credential(name: str, value: str) -> bool:
    return any(p.search(name) for p in _CRED_PATTERNS)


def _trusted_scope_set() -> tuple[str, ...]:
    import os
    extra = os.environ.get("DIGGER_MCP_TRUSTED_SCOPES", "")
    parts = [s.strip() for s in extra.split(",") if s.strip()]
    return tuple(sorted(KNOWN_GOOD_NPM_SCOPES | set(parts)))


class McpAuditDetector(Detector):
    name = "mcp_audit"
    description = (
        "MCP (Model Context Protocol) server configuration audit: "
        "flags project-scoped auto-installers, raw script "
        "executions, credential-shape env vars, network-transport "
        "servers, and typo-squat-suspicious npm scopes."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "MCP server configuration risk",
            "id": "digger-mcp-audit-template",
            "description": (
                "MCP server entry on a developer host failed "
                "the digger MCP audit (project-scoped autoinstall, "
                "raw script exec, credential env var, untrusted "
                "scope, network-transport server)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "ai_tools"},
            "detection": {
                "selection": {
                    "kind": [
                        "project_scoped_autoinstall",
                        "raw_script_exec",
                        "credential_env_var",
                        "network_transport",
                        "untrusted_npm_scope",
                        "config_parse_error",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1195", "attack.t1195.001",
                "attack.t1195.002", "attack.t1059",
                "attack.t1552.001", "attack.t1071.001",
                "attack.initial_access",
                "attack.supply_chain_compromise",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="mcp.audit",
                                          category="ai_tools"):
            yield from self._check_record(art)

    def _check_record(self, art) -> Iterable[Finding]:
        rec = art["data"] or {}
        name = rec.get("name") or "?"
        config_path = rec.get("config_path") or ""
        config_kind = rec.get("config_kind") or "?"
        ref = art["artifact_uuid"]

        if rec.get("parse_error"):
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"MCP config file unparseable: {config_path}"
                ),
                summary=(
                    f"digger could not parse the MCP config at "
                    f"``{config_path}``: "
                    f"``{rec.get('parse_error')}``. Either the "
                    "file is malformed, oversized, or in a schema "
                    "digger doesn't yet recognize. Verify by hand."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "config_parse_error",
                    "config_path": config_path,
                    "config_kind": config_kind,
                    "parse_error": rec.get("parse_error"),
                },
                mitre="T1195",
            )
            return

        if rec.get("disabled"):
            return

        # P1 project-scoped auto-install
        if rec.get("project_scoped"):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Project-scoped MCP server "
                    f"auto-installs on clone: {name}"
                ),
                summary=(
                    f"MCP server ``{name}`` is declared in a "
                    f"project-local config (``{config_path}``). "
                    "When the agent opens this directory, it "
                    "launches the server automatically — `git "
                    "clone` + open is enough to run arbitrary "
                    "code. The npm / pypi dropper attack shape "
                    "ported to AI tooling. Verify the operator "
                    "actually wants this server, that the package "
                    "identifier is correct, and that the repo's "
                    "history doesn't show a recent unexplained "
                    "edit to the MCP block."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "project_scoped_autoinstall",
                    "server_name": name,
                    "config_path": config_path,
                    "command": rec.get("command"),
                    "args": rec.get("args"),
                    "pkg_ecosystem": rec.get("pkg_ecosystem"),
                    "pkg_identifier": rec.get("pkg_identifier"),
                },
                mitre="T1195.002",
            )

        # P2 raw script execution
        if rec.get("pkg_ecosystem") in (
            "raw_node", "raw_python", "raw_shell",
        ):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"MCP server runs an arbitrary local "
                    f"script: {name}"
                ),
                summary=(
                    f"MCP server ``{name}`` executes "
                    f"``{rec.get('command')}`` with arg "
                    f"``{rec.get('pkg_identifier')}``. Unlike "
                    "an npm / pypi-distributed server with a "
                    "stable identifier, a raw script is whatever "
                    "the file on disk happens to be — anyone "
                    "who can edit the file edits the MCP "
                    "behavior, with no signature check. Verify "
                    "the script contents and the filesystem "
                    "permissions."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "raw_script_exec",
                    "server_name": name,
                    "config_path": config_path,
                    "command": rec.get("command"),
                    "script": rec.get("pkg_identifier"),
                },
                mitre="T1059",
            )

        # P3 credential-shape env vars
        cred_keys = [
            k for k, v in (rec.get("env") or {}).items()
            if _looks_like_credential(k, v)
        ]
        if cred_keys:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"MCP server inherits credential-shape env "
                    f"vars: {name} ({len(cred_keys)} keys)"
                ),
                summary=(
                    f"MCP server ``{name}`` will be launched with "
                    "the following credential-shape environment "
                    f"variables: ``{', '.join(cred_keys[:8])}``. "
                    "Every MCP server runs with the host process's "
                    "privileges; once the server has the env var, "
                    "it can echo it back to the agent via tool "
                    "responses (which the model then includes in "
                    "context, potentially leaking it onwards) or "
                    "use it directly. If you wouldn't paste these "
                    "secrets into a random npm package, don't "
                    "wire them into an MCP server."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "credential_env_var",
                    "server_name": name,
                    "config_path": config_path,
                    "keys": cred_keys[:16],
                },
                mitre="T1552.001",
            )

        # P4 network transport
        if rec.get("transport", "").lower() in _NETWORK_TRANSPORTS:
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"MCP server reached over network transport: "
                    f"{name} ({rec.get('transport')})"
                ),
                summary=(
                    f"MCP server ``{name}`` is configured with "
                    f"transport=``{rec.get('transport')}`` and "
                    f"URL ``{rec.get('url')}``. The agent's tool "
                    "catalog is then dictated by a remote "
                    "endpoint — anyone who controls the URL can "
                    "swap the tool descriptions out from under "
                    "the model. Prompt-injection via tool "
                    "descriptions is a documented attack vector "
                    "(``tool poisoning``). Pin DNS, run the "
                    "endpoint over mutual-TLS, and treat tool "
                    "descriptions as untrusted strings."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "network_transport",
                    "server_name": name,
                    "transport": rec.get("transport"),
                    "url": rec.get("url"),
                    "config_path": config_path,
                },
                mitre="T1071.001",
            )

        # P5 typo-squat-suspicious npm scope
        if rec.get("pkg_ecosystem") == "npm" and rec.get("pkg_scope"):
            scope = rec.get("pkg_scope") or ""
            if scope not in _trusted_scope_set():
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=(
                        f"MCP server from non-allowlisted npm "
                        f"scope: {name} ({scope})"
                    ),
                    summary=(
                        f"MCP server ``{name}`` loads npm package "
                        f"``{rec.get('pkg_identifier')}`` whose "
                        f"scope ``{scope}`` is not on the digger "
                        "MCP-author allowlist. The package may "
                        "still be legitimate (community-published "
                        "server, a private scope, etc.), but for "
                        "a first-party install this is worth "
                        "confirming. Typo-squat campaigns have "
                        "already started shipping `@modelcontxt-"
                        "protocol/*`-style fakes. Extend the "
                        "allowlist via DIGGER_MCP_TRUSTED_SCOPES."
                    ),
                    artifact_refs=[ref],
                    evidence={
                        "kind": "untrusted_npm_scope",
                        "server_name": name,
                        "scope": scope,
                        "pkg_identifier": rec.get("pkg_identifier"),
                        "config_path": config_path,
                    },
                    mitre="T1195.002",
                )
