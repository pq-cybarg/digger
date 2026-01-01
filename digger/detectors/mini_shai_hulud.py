"""Mini Shai-Hulud / TeamPCP supply-chain worm detector.

Disclosed 2026-05-11 (initial wave) and 2026-05-12 (TanStack
disclosure). 170+ npm + 2 PyPI packages, 404 malicious versions,
attributed to TeamPCP with high confidence.

Distinctive properties:

  * Self-propagation via GitHub GraphQL ``createCommitOnBranch``
    mutation, poisoning IDE configs (.claude/, .vscode/) in
    downstream victim repos.

  * DESTRUCTIVE payload: ``rm -rf ~/`` triggered when the GitHub
    token used by ``gh-token-monitor`` service is revoked. This is
    rare and high-impact — the user must disable the service
    BEFORE rotating the token, hence the mitigation block ships an
    explicit destructive_warning section.

  * Persistence via ``gh-token-monitor`` LaunchAgent (macOS) or
    systemd-user service (Linux), polling GitHub every 60 seconds.

  * Credential-harvest probes: AWS IMDS
    (169.254.169.254/.../iam/security-credentials/) and local
    HashiCorp Vault (127.0.0.1:8200).

Detection layers, in severity order:

  S1  Compromised package in lockfile
      Exact + scope-wildcard matches against the bundled corpus
      (@tanstack/* router + query packages, @mistralai/*,
      @uipath/*, @opensearch-project/opensearch, @squawk/*,
      @tallyui/*, @beproduct/nestjs-auth, plus the two PyPI
      packages guardrails-ai==0.10.1 and mistralai==2.4.6).
      Critical, T1195.002.

  S2  Published payload hash match (router_init.js, setup.mjs)
      against process exe / files-table hashes. Critical, T1195.002.

  S3  Persistence artifacts present
      - ``~/Library/LaunchAgents/com.user.gh-token-monitor.plist``
        on macOS
      - ``~/.config/systemd/user/gh-token-monitor.service`` on Linux
      Single hit on either filename is dispositive. Critical, T1543.
      Mitigation block carries the DESTRUCTIVE-WARNING preamble.

  S4  IDE-config poisoning
      ``.claude/settings.json``, ``.claude/setup.mjs``,
      ``.claude/router_runtime.js``, ``.vscode/tasks.json``,
      ``.vscode/setup.mjs`` written by the worm. Single-hit
      dispositive when basename matches AND the file content
      contains a campaign marker. Critical, T1195.002.

  S5  Campaign-marker strings in process cmdlines / file contents
      Five dispositive markers: ``Shai-Hulud: Here We Go Again``,
      ``IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner``,
      ``With Love TeamPCP``, ``gh-token-monitor``,
      ``tanstack_runner.js``. Critical, T1059.

  S6  C2 callout
      git-tanstack.com or filev2.getsession.org or the published IP
      ``83.142.209.194`` in cmdline / DNS / network artifacts.
      Critical, T1071.

MITRE: T1195.002 (Compromise Software Supply Chain — npm),
T1059 (Command + Scripting Interpreter), T1543 (Create or Modify
System Process — service persistence), T1071 (Application Layer
Protocol — C2), T1485 (Data Destruction — destructive payload).
"""

# live-first-ok: Mini Shai-Hulud IOCs live on vendor blogs (Wiz,
# safedep, Orca, Rescana, NHS Digital). No OSV/STIX live feed for
# the per-package list as of disclosure; CISA KEV may surface
# CVE-style entries later. Bundled YAML is authoritative until then.

from __future__ import annotations

from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors._rules_io import load_yaml
from digger.detectors.base import Detector
from digger.ethics.contract import redact_dangerous_command


def _redact_block(block: str) -> str:
    if not block:
        return ""
    out_lines: list[str] = []
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(line)
            continue
        annotated, was_dangerous = redact_dangerous_command(stripped)
        out_lines.append(annotated if was_dangerous else line)
    return "\n".join(out_lines)


def _expand_pinned(entries: list[str]) -> tuple[set[str], set[str], set[str]]:
    """Split into (exact, wildcards_name, wildcards_scope).

    A scope wildcard like ``@uipath/*`` matches every package in that
    scope, not just versions of one package."""
    exact: set[str] = set()
    name_wild: set[str] = set()
    scope_wild: set[str] = set()
    for entry in entries or []:
        if entry.endswith("/*"):
            scope_wild.add(entry[:-2].lower())
            continue
        if "@" not in entry:
            name_wild.add(entry.lower())
            continue
        if entry.endswith("@*"):
            name_wild.add(entry[:-2].lower())
        else:
            exact.add(entry.lower())
    return exact, name_wild, scope_wild


def _cmdline_str(cmdline) -> str:
    if isinstance(cmdline, list):
        return " ".join(str(c) for c in cmdline if c)
    return cmdline or ""


def _basename(path: str) -> str:
    if not path:
        return ""
    if "/" in path:
        path = path.rsplit("/", 1)[1]
    if "\\" in path:
        path = path.rsplit("\\", 1)[1]
    return path


def _scope_of(npm_pkg: str) -> str:
    """``@tanstack/react-router`` → ``@tanstack``; ``lodash`` → ``''``."""
    if npm_pkg.startswith("@") and "/" in npm_pkg:
        return npm_pkg.split("/", 1)[0].lower()
    return ""


class MiniShaiHuludDetector(Detector):
    name = "mini_shai_hulud"
    description = (
        "Mini Shai-Hulud / TeamPCP supply-chain worm (May 2026): "
        "170+ npm + 2 PyPI compromised packages, self-propagation "
        "via GitHub GraphQL poisoning .claude/ + .vscode/, "
        "DESTRUCTIVE rm-rf-on-token-revoke payload via gh-token-"
        "monitor.service, C2 to git-tanstack.com / Session "
        "messenger network."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Mini Shai-Hulud / TeamPCP supply-chain worm",
            "id": "digger-mini-shai-hulud-template",
            "description": (
                "Matches the Mini Shai-Hulud campaign by any of: "
                "compromised @tanstack/@mistralai/@uipath/@opensearch-"
                "project/@squawk/@tallyui/@beproduct package "
                "installed; gh-token-monitor persistence service "
                "present; campaign markers in cmdline ('Shai-Hulud: "
                "Here We Go Again' / 'IfYouRevokeThisTokenItWill"
                "WipeTheComputerOfTheOwner' / 'With Love TeamPCP' / "
                "'tanstack_runner.js' / 'router_init.js' / 'router_"
                "runtime.js'); C2 callout to git-tanstack.com / "
                "filev2.getsession.org / 83.142.209.194; or the "
                "published payload SHA-256s."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_marker_cmdline": {
                    "CommandLine|contains": [
                        "Shai-Hulud: Here We Go Again",
                        "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner",
                        "With Love TeamPCP",
                        "gh-token-monitor",
                        "tanstack_runner.js",
                        "router_init.js",
                        "router_runtime.js",
                    ],
                },
                "selection_c2_callout": {
                    "CommandLine|contains": [
                        "git-tanstack.com",
                        "filev2.getsession.org",
                        "83.142.209.194",
                    ],
                },
                "selection_persistence_file": {
                    "TargetFilename|endswith": [
                        "/gh-token-monitor.plist",
                        "/gh-token-monitor.service",
                    ],
                },
                "condition": "1 of selection_*",
            },
            "level": "critical",
            "tags": [
                "attack.t1195.002",
                "attack.t1059",
                "attack.t1071",
                "attack.t1485",
                "attack.t1543",
                "attack.initial_access",
                "attack.supply_chain_compromise",
                "attack.command_and_control",
                "attack.impact",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        rules = load_yaml("supply_chain/mini_shai_hulud.yaml") or {}
        if not rules:
            return

        campaign = rules.get("campaign") or "Mini Shai-Hulud"
        attribution = rules.get("attribution") or {}
        references = rules.get("references") or []

        npm_exact, npm_name_wild, npm_scope_wild = _expand_pinned(
            rules.get("npm") or []
        )
        pypi_exact, pypi_name_wild, _ = _expand_pinned(rules.get("pypi") or [])

        markers = [m for m in (rules.get("campaign_markers") or []) if m]
        marker_lower = [(m, m.lower()) for m in markers]

        hashes = rules.get("hashes") or []
        sha256_iocs = {h["sha256"].lower(): h for h in hashes
                       if isinstance(h, dict) and h.get("sha256")}

        persistence_files = [p for p in (rules.get("persistence_files") or []) if p]
        persist_basenames = {p.rsplit("/", 1)[-1].lower() for p in persistence_files}

        ide_files = [p for p in (rules.get("ide_persistence_files") or []) if p]
        ide_basenames = {p.rsplit("/", 1)[-1].lower() for p in ide_files}
        ide_paths_lower = {p.lower() for p in ide_files}

        c2 = rules.get("c2") or {}
        c2_domains = [d.lower() for d in (c2.get("domains") or []) if d]
        c2_ips = [ip for ip in (c2.get("ips") or []) if ip]

        mitigation = rules.get("mitigation") or {}
        npm_mit = _redact_block(mitigation.get("npm", ""))
        pypi_mit = _redact_block(mitigation.get("pypi", ""))
        destructive_warning = _redact_block(
            mitigation.get("destructive_warning", "")
        )

        common_response = (
            "Mini Shai-Hulud (TeamPCP) was disclosed 2026-05-11. "
            f"Attribution: {attribution.get('group', 'TeamPCP')}. "
            "The campaign includes a destructive rm-rf-on-token-"
            "revoke payload — DO NOT revoke any harvested GitHub "
            "token until gh-token-monitor.service has been disabled "
            "AND its persistence file removed. See "
            "evidence.destructive_warning for the safe rotation "
            "sequence."
        )

        # ---- S1 — compromised npm / PyPI packages ---- #

        for art in store.iter_artifacts(collector="npm_packages"):
            d = art["data"] or {}
            project = d.get("project")
            locked = d.get("locked_packages") or {}
            declared = {**(d.get("declared_deps") or {}),
                         **(d.get("declared_dev_deps") or {})}
            seen: set[str] = set()
            for name, ver in {**declared, **locked}.items():
                low = (name or "").lower()
                if not low or low in seen:
                    continue
                pinned = f"{low}@{ver}".lower() if ver else low
                scope = _scope_of(low)
                hit = (pinned in npm_exact or
                       low in npm_name_wild or
                       (scope and scope in npm_scope_wild))
                if not hit:
                    continue
                seen.add(low)
                display = f"{name}@{ver}" if ver else name
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=f"Mini Shai-Hulud compromised npm package: {display}",
                    summary=(
                        f"Project {project} has the Mini Shai-Hulud "
                        f"compromised package {display}. {common_response}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "npm_compromised",
                        "campaign": campaign,
                        "project": project,
                        "package": display,
                        "mitigation_commands": npm_mit,
                        "destructive_warning": destructive_warning,
                        "references": references,
                    },
                    mitre="T1195.002",
                )

        for art in store.iter_artifacts(collector="python_packages"):
            d = art["data"] or {}
            interpreter = d.get("interpreter")
            entries = d.get("entries") or []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = (entry.get("name") or "").lower()
                ver = entry.get("version") or ""
                if not name:
                    continue
                pinned = f"{name}@{ver}".lower() if ver else name
                if pinned in pypi_exact or name in pypi_name_wild:
                    display = f"{name}@{ver}" if ver else name
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"Mini Shai-Hulud compromised PyPI package: {display}",
                        summary=(
                            f"Python env {interpreter} has Mini Shai-"
                            f"Hulud compromised package {display}. "
                            f"{common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "pypi_compromised",
                            "campaign": campaign,
                            "interpreter": interpreter,
                            "package": display,
                            "mitigation_commands": pypi_mit,
                            "destructive_warning": destructive_warning,
                            "references": references,
                        },
                        mitre="T1195.002",
                    )

        # ---- S2 — published payload hash match ---- #

        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            hv = (d.get("exe_sha256") or "").lower()
            if hv and hv in sha256_iocs:
                ioc = sha256_iocs[hv]
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=(
                        f"Mini Shai-Hulud payload SHA-256 match: "
                        f"{ioc.get('name')} (pid {d.get('pid')})"
                    ),
                    summary=(
                        f"Process pid {d.get('pid')} ({d.get('name')}) "
                        f"exe hash matches Mini Shai-Hulud payload "
                        f"{ioc.get('name')}. {common_response}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "payload_hash",
                        "campaign": campaign,
                        "hash": hv,
                        "name": ioc.get("name"),
                        "pid": d.get("pid"),
                        "mitigation_commands": npm_mit,
                        "destructive_warning": destructive_warning,
                        "references": references,
                    },
                    mitre="T1195.002",
                )

        for art in store.iter_artifacts(category="filesystem"):
            d = art["data"] or {}
            entries = d.get("entries") or ([d] if d.get("path") else [])
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                hv = (entry.get("sha256") or "").lower()
                if hv and hv in sha256_iocs:
                    ioc = sha256_iocs[hv]
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Mini Shai-Hulud payload on disk: "
                            f"{entry.get('path')}"
                        ),
                        summary=(
                            f"File ``{entry.get('path')}`` matches "
                            f"Mini Shai-Hulud {ioc.get('name')} "
                            f"SHA-256. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "payload_hash",
                            "campaign": campaign,
                            "hash": hv,
                            "name": ioc.get("name"),
                            "path": entry.get("path"),
                            "mitigation_commands": npm_mit,
                            "destructive_warning": destructive_warning,
                            "references": references,
                        },
                        mitre="T1195.002",
                    )

        # ---- S3 — persistence artifacts (gh-token-monitor) ---- #

        for art in store.iter_artifacts(collector="recent_files"):
            d = art["data"] or {}
            entries = d.get("entries") or ([d] if d.get("path") else [])
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path") or ""
                base = _basename(path).lower()
                if not path or not base:
                    continue
                if base in persist_basenames:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Mini Shai-Hulud persistence file present: "
                            f"{path}"
                        ),
                        summary=(
                            f"File ``{path}`` matches Mini Shai-Hulud "
                            "persistence (``gh-token-monitor`` service "
                            "that polls GitHub every 60s for token "
                            "revocation, then triggers ``rm -rf ~/``). "
                            "DO NOT revoke the GitHub token until "
                            "this file is removed and the service "
                            "stopped. See evidence.destructive_warning "
                            f"for the safe sequence. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "persistence_file",
                            "campaign": campaign,
                            "path": path,
                            "basename": base,
                            "mitigation_commands": npm_mit,
                            "destructive_warning": destructive_warning,
                            "references": references,
                        },
                        mitre="T1543",
                    )

        # ---- S4 — IDE-config poisoning (basename + marker co-presence) ---- #

        for art in store.iter_artifacts(collector="recent_files"):
            d = art["data"] or {}
            entries = d.get("entries") or ([d] if d.get("path") else [])
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path") or ""
                low_path = path.lower()
                base = _basename(path).lower()
                if not base:
                    continue
                # IDE poison candidates: either basename match OR full
                # path ends with one of the known IDE paths.
                is_ide_candidate = (
                    base in ide_basenames
                    or any(low_path.endswith(ip) for ip in ide_paths_lower)
                )
                if not is_ide_candidate:
                    continue
                content = entry.get("contents") or entry.get("content") or ""
                if not isinstance(content, str) or not content:
                    continue
                low_content = content.lower()
                for original, lo in marker_lower:
                    if lo in low_content:
                        yield Finding(
                            detector=self.name,
                            severity="critical",
                            title=(
                                f"Mini Shai-Hulud IDE-poison: marker "
                                f"'{original}' in {path}"
                            ),
                            summary=(
                                f"IDE configuration file ``{path}`` "
                                f"contains Mini Shai-Hulud marker "
                                f"``{original}``. The worm self-"
                                "propagates by committing poisoned "
                                ".claude/ and .vscode/ configs via "
                                "GitHub GraphQL. Audit recent commits "
                                f"for this repo. {common_response}"
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "ide_poison",
                                "campaign": campaign,
                                "path": path,
                                "marker": original,
                                "snippet": content[:300],
                                "mitigation_commands": npm_mit,
                                "destructive_warning": destructive_warning,
                                "references": references,
                            },
                            mitre="T1195.002",
                        )
                        break

        # ---- S5 — campaign markers in process cmdlines ---- #

        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            cmd = _cmdline_str(d.get("cmdline"))
            if not cmd:
                continue
            cmd_low = cmd.lower()
            for original, lo in marker_lower:
                if lo in cmd_low:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Mini Shai-Hulud marker '{original}' in "
                            f"cmdline (pid {d.get('pid')})"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} "
                            f"({d.get('name')}) command line contains "
                            f"campaign marker ``{original}``. "
                            f"{common_response}"
                            f"\n\nCmdline: {cmd[:300]}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "marker_cmdline",
                            "campaign": campaign,
                            "marker": original,
                            "pid": d.get("pid"),
                            "name": d.get("name"),
                            "cmdline": cmd[:400],
                            "mitigation_commands": npm_mit,
                            "destructive_warning": destructive_warning,
                            "references": references,
                        },
                        mitre="T1059",
                    )
                    break  # one marker finding per process

        # ---- S6 — C2 callouts (cmdline + DNS + connection table) ---- #

        seen_c2: set[str] = set()
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            cmd = _cmdline_str(d.get("cmdline")).lower()
            # cmdline domain hits
            for dom in c2_domains:
                if dom in cmd and dom not in seen_c2:
                    seen_c2.add(dom)
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Mini Shai-Hulud C2 domain in cmdline: "
                            f"{dom} (pid {d.get('pid')})"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} ({d.get('name')}) "
                            f"command line references C2 domain "
                            f"``{dom}``. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "c2_cmdline",
                            "campaign": campaign,
                            "domain": dom,
                            "pid": d.get("pid"),
                            "cmdline": cmd[:400],
                            "mitigation_commands": npm_mit,
                            "destructive_warning": destructive_warning,
                            "references": references,
                        },
                        mitre="T1071",
                    )
            # connection table IPs
            for conn in d.get("connections") or []:
                if not isinstance(conn, dict):
                    continue
                rip = (conn.get("raddr") or conn.get("remote_ip") or "").strip()
                if rip and rip in c2_ips and rip not in seen_c2:
                    seen_c2.add(rip)
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Mini Shai-Hulud C2 IP connection: "
                            f"pid {d.get('pid')} → {rip}"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} ({d.get('name')}) "
                            f"holds a connection to known Mini Shai-"
                            f"Hulud C2 IP ``{rip}``. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "c2_connection",
                            "campaign": campaign,
                            "remote_ip": rip,
                            "pid": d.get("pid"),
                            "mitigation_commands": npm_mit,
                            "destructive_warning": destructive_warning,
                            "references": references,
                        },
                        mitre="T1071",
                    )

        for art in store.iter_artifacts(collector="dns"):
            d = art["data"] or {}
            host = (d.get("host") or d.get("name") or "").lower()
            entries = d.get("entries") or []
            haystacks = [host] + [
                (e.get("host") or e.get("name") or "").lower()
                for e in entries if isinstance(e, dict)
            ]
            for hay in haystacks:
                if not hay:
                    continue
                for dom in c2_domains:
                    if dom in hay and dom not in seen_c2:
                        seen_c2.add(dom)
                        yield Finding(
                            detector=self.name,
                            severity="critical",
                            title=f"Mini Shai-Hulud C2 domain resolved: {dom}",
                            summary=(
                                f"DNS history records resolution of "
                                f"Mini Shai-Hulud C2 ``{dom}``. "
                                f"{common_response}"
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "c2_dns",
                                "campaign": campaign,
                                "domain": dom,
                                "mitigation_commands": npm_mit,
                                "destructive_warning": destructive_warning,
                                "references": references,
                            },
                            mitre="T1071",
                        )
                        break
