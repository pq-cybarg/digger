"""TrapDoor crypto-stealer supply-chain campaign detector.

Disclosed by Socket Security on 2026-05-24. Single coordinated campaign
publishing 34 malicious packages across npm (21), PyPI (7), and
crates.io (6). Same payload, same author (``ddjidd564``), same exfil
domain (``ddjidd564.github.io``), same dispositive campaign marker
strings (``P-2024-001``, ``trap-core.js``, ``cargo-build-helper-2026``).

Detection layers, in order of severity:

  T1  Compromised package present in lockfile
      Wildcard match against the bundled corpus. Every version is
      treated as compromised — the campaign re-publishes existing
      version numbers, so version-pinning is no protection. Fires
      ``critical`` with per-ecosystem mitigation commands attached.

  T2  Campaign marker in any process command line
      ``P-2024-001`` or ``trap-core.js`` or ``ddjidd564.github.io`` or
      ``cargo-build-helper-2026`` appearing in a live process cmdline
      means the payload (or its loader) is currently running. Fires
      ``critical``.

  T3  Persistence-file content contains a campaign marker
      Walks ``recent_files`` for ``.cursorrules`` / ``CLAUDE.md`` /
      ``.git/hooks/*`` / ``.zshrc`` / ``.bashrc`` paths whose CONTENT
      (where available) contains a marker. The file's existence is
      not itself an IOC — these are legitimate dev-host files — but
      the marker inside is dispositive.

  T4  Exfil domain in network artifacts or DNS history
      Live process cmdline curl/wget targeting ``ddjidd564.github.io``
      or DNS resolution to that host, fires ``high`` (could be a
      researcher hitting Socket's reference URL, hence non-critical).

Each finding carries:
  - evidence.ecosystem      ('npm' / 'pypi' / 'cargo' / 'process' / 'persistence' / 'network')
  - evidence.package        when applicable (name@version)
  - evidence.marker         which campaign marker matched
  - evidence.mitigation     ecosystem-appropriate copy-paste block,
                            routed through ``redact_dangerous_command``
                            so destructive ops are flagged before display
  - mitre                   T1195.001 (compromised dev-tool / package)
                            or T1059 (process cmdline match)
"""

# live-first-ok: Socket Security publishes the TrapDoor corpus on their
# blog (https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates),
# not as a machine-readable live feed. When/if Socket exposes a STIX
# or OSV endpoint, add a load_intel() call ABOVE the load_yaml() line.

from __future__ import annotations

from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors._rules_io import load_yaml
from digger.detectors.base import Detector
from digger.ethics.contract import redact_dangerous_command


def _expand_pinned(entries: list[str]) -> tuple[set[str], set[str]]:
    """Split ``name@version`` entries into (exact, wildcards).

    ``name@*`` and bare ``name`` both go into wildcards (the campaign
    re-publishes existing version numbers, so wildcard is the
    operationally correct default)."""
    exact: set[str] = set()
    wildcards: set[str] = set()
    for entry in entries or []:
        if "@" not in entry:
            wildcards.add(entry.lower())
            continue
        if entry.endswith("@*"):
            wildcards.add(entry[:-2].lower())
        else:
            exact.add(entry.lower())
    return exact, wildcards


def _redact_block(block: str) -> str:
    """Run each non-comment line of a mitigation block through the
    destructive-command redactor. Lines that match keep their comment
    annotation; everything else is passed through verbatim."""
    if not block:
        return ""
    out_lines: list[str] = []
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(line)
            continue
        annotated, was_dangerous = redact_dangerous_command(stripped)
        if was_dangerous:
            out_lines.append(annotated)
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


class TrapDoorDetector(Detector):
    name = "trapdoor"
    description = (
        "TrapDoor crypto-stealer supply-chain campaign (Socket Security, "
        "2026-05-24): 34 packages across npm/PyPI/crates.io, attributed to "
        "GitHub account ddjidd564. Targets crypto/DeFi/AI/security dev hosts."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "TrapDoor crypto-stealer campaign — package, marker, or exfil-domain hit",
            "id": "digger-trapdoor-template",
            "description": (
                "Detects the TrapDoor campaign by any of: process cmdline "
                "containing a campaign marker (``P-2024-001``, "
                "``trap-core.js``, ``ddjidd564.github.io``, "
                "``cargo-build-helper-2026``); file write of the "
                "trap-core.js loader; outbound HTTP to ddjidd564.github.io."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_marker_cmdline": {
                    "CommandLine|contains": [
                        "P-2024-001",
                        "trap-core.js",
                        "ddjidd564.github.io",
                        "cargo-build-helper-2026",
                    ],
                },
                "selection_marker_file": {
                    "TargetFilename|endswith": ["/trap-core.js"],
                },
                "selection_exfil_domain": {
                    "CommandLine|contains": "ddjidd564.github.io",
                    "Image|endswith": [
                        "/curl", "/wget", "/node", "/python",
                        "/python3", "/cargo",
                    ],
                },
                "condition": "1 of selection_*",
            },
            "level": "critical",
            "tags": [
                "attack.t1195.001",
                "attack.t1059",
                "attack.initial_access",
                "attack.supply_chain_compromise",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        rules = load_yaml("supply_chain/trapdoor.yaml") or {}
        if not rules:
            return

        campaign = rules.get("campaign") or "TrapDoor"
        source = rules.get("source") or "socket.dev"
        disclosed = rules.get("disclosed") or "2026-05-24"
        attribution = rules.get("attribution") or {}
        github_account = (attribution or {}).get("github_account") or ""
        references = rules.get("references") or []

        npm_exact, npm_wild = _expand_pinned(rules.get("npm", []))
        pypi_exact, pypi_wild = _expand_pinned(rules.get("pypi", []))
        crates_exact, crates_wild = _expand_pinned(rules.get("crates", []))

        markers = [m for m in (rules.get("campaign_markers") or []) if m]
        exfil_domains = [d for d in (rules.get("exfil_domains") or []) if d]
        persistence_files = [p for p in (rules.get("persistence_files") or []) if p]
        trap_core_filename = (rules.get("trap_core_filename") or "trap-core.js").lower()

        mitigation = rules.get("mitigation") or {}
        npm_mitigation = _redact_block(mitigation.get("npm", ""))
        pypi_mitigation = _redact_block(mitigation.get("pypi", ""))
        crates_mitigation = _redact_block(mitigation.get("crates", ""))

        attribution_blurb = (
            f"Attributed by {source} to GitHub account "
            f"``{github_account}``. " if github_account else ""
        )
        common_response = (
            "TrapDoor exfiltrates SSH keys, crypto wallets (Sui / Solana / "
            "Aptos / browser-extension wallets), AWS credentials, GitHub "
            "tokens, browser login DBs, env vars, and API keys. Treat the "
            "host as compromised: rotate every credential the dev "
            "environment touched, audit ``~/.cursorrules`` / ``CLAUDE.md`` "
            "/ ``~/.zshrc`` / ``~/.bashrc`` / ``~/.config/systemd/user/`` "
            "for injected payloads, and audit ``~/.ssh/authorized_keys`` "
            "for newly added keys (SSH-based propagation is part of the "
            "campaign). Disclosed by " + source + " on " + str(disclosed)
            + ". " + attribution_blurb
        )

        # ---- T1 — compromised packages per ecosystem ---- #

        for art in store.iter_artifacts(collector="npm_packages"):
            data = art["data"] or {}
            project = data.get("project")
            locked = data.get("locked_packages") or {}
            declared = {
                **(data.get("declared_deps") or {}),
                **(data.get("declared_dev_deps") or {}),
            }
            seen: set[str] = set()
            for name, ver in {**declared, **locked}.items():
                low = (name or "").lower()
                if not low or low in seen:
                    continue
                pinned = f"{low}@{ver}".lower() if ver else low
                if pinned in npm_exact or low in npm_wild:
                    seen.add(low)
                    display = f"{name}@{ver}" if ver else name
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"TrapDoor compromised npm package: {display}",
                        summary=(
                            f"Project {project} has the TrapDoor "
                            f"compromised package {display}. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "ecosystem": "npm",
                            "campaign": campaign,
                            "project": project,
                            "package": display,
                            "mitigation_commands": npm_mitigation,
                            "references": references,
                        },
                        mitre="T1195.001",
                    )

        for art in store.iter_artifacts(collector="python_packages"):
            data = art["data"] or {}
            interpreter = data.get("interpreter")
            entries = data.get("entries") or []
            seen_py: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = (entry.get("name") or "").lower()
                ver = entry.get("version") or ""
                if not name or name in seen_py:
                    continue
                pinned = f"{name}@{ver}".lower() if ver else name
                if pinned in pypi_exact or name in pypi_wild:
                    seen_py.add(name)
                    display = f"{name}@{ver}" if ver else name
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"TrapDoor compromised PyPI package: {display}",
                        summary=(
                            f"Python env {interpreter} has the TrapDoor "
                            f"compromised package {display}. The PyPI "
                            "variant downloads ``trap-core.js`` from "
                            "ddjidd564.github.io and executes it via "
                            "``node -e``, so check for unexpected Node "
                            "processes spawned by Python in your "
                            f"history. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "ecosystem": "pypi",
                            "campaign": campaign,
                            "interpreter": interpreter,
                            "package": display,
                            "mitigation_commands": pypi_mitigation,
                            "references": references,
                        },
                        mitre="T1195.001",
                    )

        for art in store.iter_artifacts(collector="cargo_packages"):
            data = art["data"] or {}
            project = data.get("project")
            locked = data.get("locked_packages") or {}
            seen_cr: set[str] = set()
            for name, ver in locked.items():
                low = (name or "").lower()
                if not low or low in seen_cr:
                    continue
                pinned = f"{low}@{ver}".lower() if ver else low
                if pinned in crates_exact or low in crates_wild:
                    seen_cr.add(low)
                    display = f"{name}@{ver}" if ver else name
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"TrapDoor compromised crates.io package: {display}",
                        summary=(
                            f"Cargo project {project} has the TrapDoor "
                            f"compromised crate {display}. The crates.io "
                            "variant embeds the stealer logic in "
                            "``build.rs`` with XOR key "
                            "``cargo-build-helper-2026``, so the payload "
                            "executes at every ``cargo build``. "
                            f"{common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "ecosystem": "cargo",
                            "campaign": campaign,
                            "project": project,
                            "package": display,
                            "mitigation_commands": crates_mitigation,
                            "references": references,
                        },
                        mitre="T1195.001",
                    )

        # ---- T2 — campaign marker in process cmdlines ---- #

        marker_lower = [(m, m.lower()) for m in markers]
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            cmd = " ".join(d.get("cmdline") or [])
            if not cmd:
                continue
            cmd_low = cmd.lower()
            for original, lo in marker_lower:
                if lo in cmd_low:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"TrapDoor marker '{original}' in process "
                            f"cmdline (pid {d.get('pid')} {d.get('name')})"
                        ),
                        summary=(
                            f"Live process (pid {d.get('pid')}, "
                            f"{d.get('name')}, user {d.get('username')}) "
                            f"has command line containing TrapDoor "
                            f"campaign marker ``{original}``. This is "
                            "dispositive of TrapDoor running on the host."
                            f" {common_response}\n\nCmdline: {cmd[:300]}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "ecosystem": "process",
                            "campaign": campaign,
                            "marker": original,
                            "pid": d.get("pid"),
                            "name": d.get("name"),
                            "username": d.get("username"),
                            "cmdline": cmd[:400],
                            "references": references,
                        },
                        mitre="T1059",
                    )
                    break  # one finding per process is enough

        # ---- T2b — trap-core.js by filename in recent files ---- #

        for art in store.iter_artifacts(collector="recent_files"):
            d = art["data"] or {}
            entries = d.get("entries") or [d] if d.get("path") else (d.get("entries") or [])
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                path = (entry.get("path") or "").lower()
                if not path:
                    continue
                if trap_core_filename in path.rsplit("/", 1)[-1]:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"TrapDoor loader file present: {entry.get('path')}",
                        summary=(
                            f"File ``{entry.get('path')}`` matches the "
                            f"TrapDoor loader filename ({trap_core_filename}). "
                            f"{common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "ecosystem": "loader_file",
                            "campaign": campaign,
                            "path": entry.get("path"),
                            "references": references,
                        },
                        mitre="T1195.001",
                    )

        # ---- T3 — persistence-file content contains a marker ---- #

        persist_basenames = {
            p.rsplit("/", 1)[-1].lower() for p in persistence_files if p
        }
        for art in store.iter_artifacts(collector="recent_files"):
            d = art["data"] or {}
            entries = d.get("entries") or ([d] if d.get("path") else [])
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path") or ""
                base = path.rsplit("/", 1)[-1].lower()
                if not path:
                    continue
                if base not in persist_basenames:
                    continue
                content = entry.get("contents") or entry.get("content") or ""
                if not isinstance(content, str) or not content:
                    continue
                content_low = content.lower()
                for original, lo in marker_lower:
                    if lo in content_low:
                        yield Finding(
                            detector=self.name,
                            severity="critical",
                            title=(
                                f"TrapDoor persistence: marker '{original}' "
                                f"in {path}"
                            ),
                            summary=(
                                f"Persistence-file ``{path}`` contains the "
                                f"TrapDoor campaign marker ``{original}``. "
                                "TrapDoor writes references into developer-"
                                "host config files (.cursorrules, CLAUDE.md, "
                                "shell rc files, git hooks, systemd user "
                                "units) so the payload re-executes after "
                                f"reboot. {common_response}"
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "ecosystem": "persistence",
                                "campaign": campaign,
                                "path": path,
                                "marker": original,
                                "snippet": content[:300],
                                "references": references,
                            },
                            mitre="T1546",
                        )
                        break

        # ---- T4 — exfil domain in process cmdlines (curl/wget) ---- #

        exfil_low = [(d, d.lower()) for d in exfil_domains]
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            cmd = " ".join(d.get("cmdline") or [])
            cmd_low = cmd.lower()
            if not cmd_low:
                continue
            for original, lo in exfil_low:
                if lo in cmd_low:
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=(
                            f"TrapDoor exfil domain in cmdline: {original} "
                            f"(pid {d.get('pid')})"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} ({d.get('name')}) "
                            f"references TrapDoor exfil domain "
                            f"``{original}`` in its command line. "
                            "May be a researcher hitting Socket's "
                            "reference URL — verify the calling process "
                            f"is expected. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "ecosystem": "network",
                            "campaign": campaign,
                            "domain": original,
                            "pid": d.get("pid"),
                            "name": d.get("name"),
                            "cmdline": cmd[:400],
                            "references": references,
                        },
                        mitre="T1041",
                    )
                    break

        # DNS history can also expose exfil-domain hits.
        for art in store.iter_artifacts(collector="dns"):
            d = art["data"] or {}
            host = (d.get("host") or d.get("name") or "").lower()
            entries = d.get("entries") or []
            haystacks = [host] + [
                (e.get("host") or e.get("name") or "").lower()
                for e in entries
                if isinstance(e, dict)
            ]
            for hay in haystacks:
                if not hay:
                    continue
                for original, lo in exfil_low:
                    if lo in hay:
                        yield Finding(
                            detector=self.name,
                            severity="high",
                            title=f"TrapDoor exfil domain resolved: {original}",
                            summary=(
                                f"DNS history records resolution of TrapDoor "
                                f"exfil domain ``{original}``. {common_response}"
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "ecosystem": "network",
                                "campaign": campaign,
                                "domain": original,
                                "host_observed": hay,
                                "references": references,
                            },
                            mitre="T1041",
                        )
                        return  # one DNS finding is enough
