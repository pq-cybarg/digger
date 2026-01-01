"""VS Code extension + settings security detector.

Consumes Artifacts emitted by ``digger.vscode.audit_vscode``.
Two collector tags: ``vscode.extension`` (one per installed
extension) and ``vscode.settings`` (one per settings.json).

Detection layers:

  V1  Sideloaded extension:                    medium
      Extension's .vsixmanifest doesn't carry the Marketplace
      sourceMarketplace identifier — installed via VSIX file
      directly, no Marketplace review. Legit for in-development
      extensions; suspicious for everything else.

  V2  Untrusted publisher:                     medium
      Extension publisher not on the KNOWN_GOOD_PUBLISHERS
      allowlist. Extend via DIGGER_VSCODE_TRUSTED_PUBLISHERS.

  V3  Workspace trust disabled:                high
      ``security.workspace.trust.enabled = false`` in user
      settings. Workspace trust is the mechanism that prevents
      a malicious .vscode/tasks.json from auto-running on
      folder open. Disabling it removes the prompt — clone +
      open = arbitrary code exec.

  V4  Workspace trust opens untrusted files:   medium
      ``security.workspace.trust.untrustedFiles = "open"`` —
      files outside trusted folders auto-load.

  V5  http.proxyStrictSSL disabled:            high
      ``http.proxyStrictSSL = false`` allows MITM on every
      extension's network call (which is everything: language
      servers, Copilot, package fetches, telemetry).

  V6  Custom default shell from suspicious path:  high
      ``terminal.integrated.defaultProfile.*`` /
      ``terminal.integrated.shell.*`` points at a binary in a
      writable / world-shared directory. Hijacks every terminal
      the user opens.

  V7  Project-scoped settings.json with risky keys:  high
      A ``./.vscode/settings.json`` (ships with repos) that
      sets any of the above risky keys. Clone + open = pwned.

The detector is *conservative*: legitimate operator behavior
(self-built extension, custom shell at /opt/homebrew/bin/fish)
will trip V1 / V6. The operator's job is to confirm and
suppress via the allowlist env vars.
"""

from __future__ import annotations

from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


_SUSPICIOUS_PATH_FRAGMENTS = (
    "/tmp/", "/private/tmp/", "/var/tmp/",
    "/Users/Shared/", "/private/var/folders/",
    "/Library/Caches/", "/.Trash/",
)


def _trusted_publishers_set() -> tuple[str, ...]:
    from digger.vscode.auditor import _trusted_publishers
    return _trusted_publishers()


def _is_suspicious_shell_path(p: str) -> bool:
    if not p:
        return False
    return any(frag in p for frag in _SUSPICIOUS_PATH_FRAGMENTS)


def _settings_has_any_risky_key(s: dict) -> bool:
    return (
        s.get("workspace_trust_enabled") is False
        or s.get("http_proxy_strict_ssl") is False
        or (s.get("workspace_trust_untrusted_files") == "open")
        or bool(s.get("custom_default_shell"))
        or bool(s.get("custom_automation_profile"))
    )


class VsCodeAuditDetector(Detector):
    name = "vscode_audit"
    description = (
        "VS Code extension + user-settings audit: sideloaded "
        "extensions, untrusted publishers, workspace-trust "
        "disablement, http.proxyStrictSSL=false, shell hijacks, "
        "project-scoped settings.json with risky keys."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Suspicious VS Code extension or settings",
            "id": "digger-vscode-audit-template",
            "description": (
                "VS Code extension or settings.json failed the "
                "digger vscode audit (sideloaded, untrusted "
                "publisher, workspace-trust disabled, MITM-"
                "permissive proxy, suspicious shell override, "
                "project-scoped risky settings)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "dev_env"},
            "detection": {
                "selection": {
                    "kind": [
                        "sideloaded_extension",
                        "untrusted_publisher",
                        "workspace_trust_disabled",
                        "workspace_trust_open_untrusted",
                        "proxy_strict_ssl_disabled",
                        "suspicious_shell_override",
                        "project_settings_risky_keys",
                        "vscode_parse_error",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1195.002", "attack.t1546", "attack.t1059",
                "attack.t1557", "attack.t1505.003",
                "attack.persistence", "attack.execution",
                "attack.defense_evasion",
                "attack.initial_access",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="vscode.extension",
                                          category="dev_env"):
            yield from self._check_extension(art)
        for art in store.iter_artifacts(collector="vscode.settings",
                                          category="dev_env"):
            yield from self._check_settings(art)

    # ---- per-extension ---- #

    def _check_extension(self, art) -> Iterable[Finding]:
        ext = art["data"] or {}
        publisher = ext.get("publisher") or ""
        name = ext.get("name") or ""
        version = ext.get("version") or ""
        label = f"{publisher}.{name}@{version}"
        ext_dir = ext.get("extension_dir") or ""
        ref = art["artifact_uuid"]

        if ext.get("parse_error"):
            yield Finding(
                detector=self.name,
                severity="info",
                title=(
                    f"Couldn't parse VS Code extension: "
                    f"{ext_dir}"
                ),
                summary=(
                    f"digger could not parse the extension at "
                    f"``{ext_dir}``: ``{ext.get('parse_error')}``."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "vscode_parse_error",
                    "extension_dir": ext_dir,
                    "parse_error": ext.get("parse_error"),
                },
                mitre="T1195.002",
            )
            return

        # V1 sideloaded
        if ext.get("is_marketplace_install") is False:
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Sideloaded VS Code extension: {label}"
                ),
                summary=(
                    f"Extension ``{label}`` at ``{ext_dir}`` "
                    "appears to have been installed from a VSIX "
                    "file rather than the Marketplace (no "
                    "``ExtensionMarketplace`` source in the "
                    ".vsixmanifest). Sideloaded extensions skip "
                    "the Marketplace's automated checks. "
                    "Legitimate for in-development plugins but a "
                    "smell otherwise — verify the source."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "sideloaded_extension",
                    "publisher": publisher,
                    "name": name,
                    "version": version,
                    "extension_dir": ext_dir,
                },
                mitre="T1195.002",
            )

        # V2 untrusted publisher
        if publisher and publisher.lower() not in _trusted_publishers_set():
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"VS Code extension from untrusted "
                    f"publisher: {label}"
                ),
                summary=(
                    f"Extension ``{label}`` is published by "
                    f"``{publisher}``, not on digger's known-"
                    "good-publisher allowlist. May be legitimate "
                    "(small but well-known plugins, internal "
                    "tooling) — extend the allowlist via "
                    "``DIGGER_VSCODE_TRUSTED_PUBLISHERS`` to "
                    "suppress expected ones."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "untrusted_publisher",
                    "publisher": publisher,
                    "name": name,
                    "version": version,
                    "extension_dir": ext_dir,
                },
                mitre="T1195.002",
            )

    # ---- per-settings ---- #

    def _check_settings(self, art) -> Iterable[Finding]:
        s = art["data"] or {}
        path = s.get("settings_path") or "?"
        project_scoped = bool(s.get("project_scoped"))
        ref = art["artifact_uuid"]

        if s.get("parse_error"):
            yield Finding(
                detector=self.name,
                severity="info",
                title=(
                    f"Couldn't parse VS Code settings: {path}"
                ),
                summary=(
                    f"digger could not parse ``{path}``: "
                    f"``{s.get('parse_error')}``."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "vscode_parse_error",
                    "settings_path": path,
                    "parse_error": s.get("parse_error"),
                },
                mitre="T1195.002",
            )
            return

        # V3 workspace trust disabled
        if s.get("workspace_trust_enabled") is False:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Workspace trust disabled in VS Code "
                    f"settings: {path}"
                ),
                summary=(
                    f"Settings at ``{path}`` has "
                    "``security.workspace.trust.enabled`` = "
                    "false. Workspace trust is what prevents a "
                    "malicious ``.vscode/tasks.json`` in a "
                    "freshly-cloned repo from auto-running on "
                    "first open. Re-enable trust unless you "
                    "have a specific reason to disable it."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "workspace_trust_disabled",
                    "settings_path": path,
                    "project_scoped": project_scoped,
                },
                mitre="T1546",
            )

        # V4 workspace trust opens untrusted files
        if s.get("workspace_trust_untrusted_files") == "open":
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"VS Code opens untrusted files without "
                    f"prompt: {path}"
                ),
                summary=(
                    f"Settings at ``{path}`` has "
                    "``security.workspace.trust.untrustedFiles`` "
                    "= \"open\". Files outside trusted folders "
                    "load and execute their attached tasks "
                    "without prompting."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "workspace_trust_open_untrusted",
                    "settings_path": path,
                    "project_scoped": project_scoped,
                },
                mitre="T1546",
            )

        # V5 proxyStrictSSL disabled
        if s.get("http_proxy_strict_ssl") is False:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"http.proxyStrictSSL disabled: {path}"
                ),
                summary=(
                    f"Settings at ``{path}`` has "
                    "``http.proxyStrictSSL`` = false. Allows "
                    "MITM on every network call VS Code or any "
                    "extension makes — Copilot, Continue, "
                    "Marketplace updates, language servers, "
                    "telemetry."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "proxy_strict_ssl_disabled",
                    "settings_path": path,
                    "project_scoped": project_scoped,
                },
                mitre="T1557",
            )

        # V6 suspicious shell override
        suspicious_shells: dict[str, str] = {}
        for k, v in (s.get("custom_default_shell") or {}).items():
            if _is_suspicious_shell_path(v):
                suspicious_shells[k] = v
        for k, v in (s.get("custom_automation_profile") or {}).items():
            if _is_suspicious_shell_path(v):
                suspicious_shells[k] = v
        if suspicious_shells:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"VS Code terminal shell overridden to "
                    f"writable path: {path}"
                ),
                summary=(
                    f"Settings at ``{path}`` overrides the "
                    f"integrated terminal's shell to a writable "
                    f"or scratch path: ``{suspicious_shells}``. "
                    "Every terminal the user opens then runs the "
                    "attacker-controlled shell."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "suspicious_shell_override",
                    "settings_path": path,
                    "overrides": suspicious_shells,
                },
                mitre="T1059",
            )

        # V7 project-scoped + any risky key (escalation)
        if project_scoped and _settings_has_any_risky_key(s):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Project-scoped .vscode/settings.json sets "
                    f"risky keys: {path}"
                ),
                summary=(
                    f"Project-scoped settings at ``{path}`` "
                    "sets at least one of: workspace-trust "
                    "disabled, untrustedFiles=open, "
                    "proxyStrictSSL=false, custom terminal "
                    "shell, custom automation profile. Project-"
                    "scoped settings ship in the repo — "
                    "``git clone evil-repo && code .`` then "
                    "trips whatever's set. Recommended: never "
                    "let a project settings file override these "
                    "keys; pin them in the user-global file."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "project_settings_risky_keys",
                    "settings_path": path,
                    "workspace_trust_enabled":
                        s.get("workspace_trust_enabled"),
                    "untrusted_files":
                        s.get("workspace_trust_untrusted_files"),
                    "proxy_strict_ssl":
                        s.get("http_proxy_strict_ssl"),
                    "custom_default_shell":
                        s.get("custom_default_shell"),
                },
                mitre="T1195.002",
            )
