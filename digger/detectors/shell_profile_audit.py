"""Shell rc / profile / login file deep-audit detector.

Consumes Artifacts emitted by ``digger.collectors.common.shell_profiles``
(collector ``shell.profile``, subjects ``shell-rc:user:*`` and
``shell-rc:system:*``). Runs SH1-SH8 rules over the captured
contents.

Existing detectors only partially cover this surface:
  - ``trapdoor`` matches specific TrapDoor campaign markers
  - ``persistence_outlier`` / ``lateral`` catch shared-NFS rc files
This detector adds the general malicious-pattern audit modeled on
the ``systemd_audit`` and ``macos_launchd`` detectors.

Detection layers (SH1-SH8)
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- patterns ---- #

_NETWORK_FETCH_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|socat|fetch|"
    r"python[23]?\s+-c\s+['\"]?import\s+(?:socket|urllib|http))",
    re.IGNORECASE,
)
_PIPE_TO_SHELL_RE = re.compile(
    r"(?:curl|wget|fetch)[^|]*\|\s*(?:sh|bash|zsh|/bin/sh|/bin/bash)",
    re.IGNORECASE,
)
_LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_LONG_HEX_RE = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}){40,}",
)

# `export PATH=...` / `PATH=...` / `set -gx PATH ...` (fish) with a
# leading writable path. We're matching the canonical user-shell
# syntaxes; nu and ksh are not in scope today.
_PATH_PREPEND_BASH = re.compile(
    r"^\s*(?:export\s+)?PATH\s*=\s*([\"']?)"
    r"(?P<head>[^\"'\n\s$:]+)"
    r"\1?:",
    re.MULTILINE,
)
_PATH_PREPEND_FISH = re.compile(
    r"^\s*set\s+-gx?\s+(?:--)?\s*PATH\s+\"?"
    r"(?P<head>[^\"'\n\s$]+)\"?(?:\s|$)",
    re.MULTILINE,
)

# alias hijack of a security-critical builtin. ``alias <name>='...'``
_ALIAS_RE = re.compile(
    r"^\s*alias\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\s*=\s*['\"](?P<target>[^'\"]+)['\"]",
    re.MULTILINE,
)
_HIJACK_TARGETS = {
    "ls", "cd", "rm", "cp", "mv", "find",
    "sudo", "su", "doas",
    "ssh", "scp", "sftp", "rsync",
    "curl", "wget",
    "git", "gh",
    "docker", "kubectl",
    "gpg", "openssl",
    "ps", "kill", "top", "htop",
    "history", "less", "more", "cat",
    "which", "type",
    "vim", "vi", "nano", "code", "emacs",
}

# trap with a network-fetch / interpreter spawn
_TRAP_RE = re.compile(r"^\s*trap\s+", re.MULTILINE)

_PROMPT_COMMAND_RE = re.compile(
    r"^\s*(?:export\s+)?PROMPT_COMMAND\s*=", re.MULTILINE,
)
_PRECMD_RE = re.compile(
    r"^\s*(?:precmd|preexec|chpwd)\s*\(\s*\)\s*\{|"
    r"^\s*(?:precmd|preexec|chpwd|add-zsh-hook|"
    r"precmd_functions|preexec_functions)\b",
    re.MULTILINE,
)

# `source <file>` / `. <file>` with writable target
_SOURCE_RE = re.compile(
    r"^\s*(?:source|\.)\s+(?:\"|')?(?P<target>[^\"'\n\s]+)",
    re.MULTILINE,
)

# `export LD_PRELOAD=...` / `export DYLD_INSERT_LIBRARIES=...`
_LIB_INJECT_RE = re.compile(
    r"^\s*(?:export\s+)?(LD_PRELOAD|LD_AUDIT|DYLD_INSERT_LIBRARIES|"
    r"DYLD_LIBRARY_PATH|LD_LIBRARY_PATH)\s*=\s*([\"']?)"
    r"(?P<target>[^\"'\n]+)\2",
    re.MULTILINE,
)

_USER_WRITABLE_PATH_FRAGMENTS = (
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/home/", "/root/",
    "/Users/", "/private/var/folders/",
    "/Library/Caches/",
    "/.cache/", "/.config/",
    "/Downloads/", "/Users/Shared/",
)


def _looks_writable(path: str) -> bool:
    """Match canonical user-writable + scratch path prefixes.
    Bare ``.`` / ``./x`` / ``~/`` are also writable but those are
    relative — match them too."""
    if not path:
        return False
    if path.startswith(("./", "../", "~/")) or path in (".", ".."):
        return True
    return any(frag in path for frag in _USER_WRITABLE_PATH_FRAGMENTS)


class ShellProfileAuditDetector(Detector):
    name = "shell_profile_audit"
    description = (
        "Shell rc / profile / login file deep audit: network-fetch, "
        "encoded payload, PATH prepend with writable dir, alias "
        "hijack of security-critical commands, trap / precmd / "
        "PROMPT_COMMAND, source from writable, LD_PRELOAD-class "
        "library injection export."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Suspicious shell rc / profile file",
            "id": "digger-shell-profile-audit-template",
            "description": (
                "Shell init file under HOME or /etc/ matches a "
                "malware-style pattern (network-fetch, encoded "
                "payload, PATH hijack, alias hijack, trap / "
                "PROMPT_COMMAND, source-writable, LD_PRELOAD "
                "export)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "shell_init"},
            "detection": {
                "selection": {
                    "kind": [
                        "shell_network_fetch",
                        "shell_encoded_payload",
                        "shell_path_writable_prepend",
                        "shell_alias_hijack",
                        "shell_trap_or_prompt",
                        "shell_source_writable",
                        "shell_lib_inject",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1546.004", "attack.t1059.004",
                "attack.t1027", "attack.t1574.007",
                "attack.t1574.006", "attack.t1546",
                "attack.persistence", "attack.execution",
                "attack.defense_evasion",
                "attack.privilege_escalation",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="shell.profile"):
            subj = art.get("subject") or ""
            if not subj.startswith("shell-rc:"):
                continue
            yield from self._check_rc(art)

    def _check_rc(self, art) -> Iterable[Finding]:
        data = art["data"] or {}
        path = data.get("path") or "?"
        contents = data.get("contents") or ""
        scope = data.get("scope") or "user"
        ref = art["artifact_uuid"]
        label = path.rsplit("/", 1)[-1]

        # SH1 network-fetch
        pipe = _PIPE_TO_SHELL_RE.search(contents)
        net = _NETWORK_FETCH_RE.search(contents)
        if pipe or net:
            sev = "critical" if pipe else "high"
            yield Finding(
                detector=self.name,
                severity=sev,
                title=(
                    f"Shell init file fetches from the network: "
                    f"{label}"
                ),
                summary=(
                    f"``{path}`` contains a network-fetch command "
                    "(curl/wget/nc/socat/python-socket). Shell "
                    "init files fire on every new terminal, so "
                    "the fetch runs constantly. A pipe-to-shell "
                    "shape is essentially never legitimate."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "shell_network_fetch",
                    "path": path,
                    "scope": scope,
                    "pipe_to_shell": bool(pipe),
                },
                mitre="T1546.004",
            )

        # SH2 encoded payload
        if _LONG_BASE64_RE.search(contents) or \
                _LONG_HEX_RE.search(contents):
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Shell init file contains encoded payload: "
                    f"{label}"
                ),
                summary=(
                    f"``{path}`` has a long base64 or escaped-hex "
                    "sequence. Sometimes legitimate (vendored "
                    "completion scripts, encoded keys), often a "
                    "hidden one-liner that gets decoded and "
                    "executed at shell start."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "shell_encoded_payload",
                    "path": path,
                    "scope": scope,
                },
                mitre="T1027",
            )

        # SH3 PATH prepend with writable head
        path_heads: list[str] = []
        for m in _PATH_PREPEND_BASH.finditer(contents):
            head = m.group("head")
            if _looks_writable(head):
                path_heads.append(head)
        for m in _PATH_PREPEND_FISH.finditer(contents):
            head = m.group("head")
            if _looks_writable(head):
                path_heads.append(head)
        if path_heads:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Shell init prepends writable dir to PATH: "
                    f"{label}"
                ),
                summary=(
                    f"``{path}`` prepends a user-writable "
                    f"directory to PATH: ``{path_heads[:3]}``. "
                    "Anyone who can drop a file at that path "
                    "with the same name as a system binary "
                    "shadows it on the user's next shell — "
                    "GTFOBins-style path hijack primitive."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "shell_path_writable_prepend",
                    "path": path,
                    "scope": scope,
                    "writable_heads": path_heads[:8],
                },
                mitre="T1574.007",
            )

        # SH4 alias hijack of security-critical commands
        hijacks: list[dict] = []
        for m in _ALIAS_RE.finditer(contents):
            name = m.group("name")
            target = m.group("target")
            if name in _HIJACK_TARGETS:
                hijacks.append({"name": name, "target": target[:200]})
        if hijacks:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Shell init aliases security-critical "
                    f"command(s): {label}"
                ),
                summary=(
                    f"``{path}`` aliases "
                    f"``{', '.join(h['name'] for h in hijacks[:5])}`` "
                    "— security-critical commands the user "
                    "regularly types. Aliasing ``sudo`` / "
                    "``ssh`` / ``git`` / ``ls`` is a classic "
                    "credential-theft + command-substitution "
                    "primitive (mimic the binary, log the "
                    "args, then call through to the real "
                    "command)."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "shell_alias_hijack",
                    "path": path,
                    "scope": scope,
                    "hijacks": hijacks[:10],
                },
                mitre="T1546.004",
            )

        # SH5 trap / precmd / PROMPT_COMMAND
        trap_hit = _TRAP_RE.search(contents)
        prompt_hit = _PROMPT_COMMAND_RE.search(contents)
        precmd_hit = _PRECMD_RE.search(contents)
        if trap_hit or prompt_hit or precmd_hit:
            triggers: list[str] = []
            if trap_hit:
                triggers.append("trap")
            if prompt_hit:
                triggers.append("PROMPT_COMMAND")
            if precmd_hit:
                triggers.append("precmd/preexec")
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Shell init declares per-command "
                    f"trigger(s) ({', '.join(triggers)}): {label}"
                ),
                summary=(
                    f"``{path}`` declares one or more per-"
                    "command-fire hooks "
                    f"({', '.join(triggers)}). Legitimate uses "
                    "exist (oh-my-zsh, starship, async git "
                    "status) but the hooks are also a textbook "
                    "keystroke-injection / command-logging "
                    "primitive — anything in PROMPT_COMMAND / "
                    "precmd runs before every prompt. Verify "
                    "the bodies."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "shell_trap_or_prompt",
                    "path": path,
                    "scope": scope,
                    "triggers": triggers,
                },
                mitre="T1546",
            )

        # SH6 source from writable
        sourced_writable: list[str] = []
        for m in _SOURCE_RE.finditer(contents):
            target = m.group("target")
            if _looks_writable(target):
                sourced_writable.append(target)
        if sourced_writable:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Shell init sources file from writable "
                    f"path: {label}"
                ),
                summary=(
                    f"``{path}`` sources "
                    f"``{sourced_writable[:3]}`` — the sourced "
                    "file is in a user-writable / scratch dir. "
                    "Whoever can write to that path edits "
                    "what the shell runs on every startup."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "shell_source_writable",
                    "path": path,
                    "scope": scope,
                    "sourced": sourced_writable[:10],
                },
                mitre="T1546.004",
            )

        # SH7 LD_PRELOAD-class library injection
        lib_injections: list[dict] = []
        for m in _LIB_INJECT_RE.finditer(contents):
            var = m.group(1)
            target = m.group("target").strip()
            lib_injections.append({
                "var": var, "target": target[:300],
            })
        if lib_injections:
            yield Finding(
                detector=self.name,
                severity="critical",
                title=(
                    f"Shell init exports library-injection env "
                    f"var: {label}"
                ),
                summary=(
                    f"``{path}`` exports "
                    f"``{lib_injections[0]['var']}=...`` (and "
                    f"{len(lib_injections) - 1} more) in shell "
                    "startup. LD_PRELOAD / LD_AUDIT / "
                    "DYLD_INSERT_LIBRARIES inject a shared "
                    "object into every process the shell "
                    "spawns. Even pointing at a system path "
                    "is unusual — pointing at a writable path "
                    "is the canonical user-mode rootkit "
                    "primitive (Symbiote, Cuttlefish, FontOnLake)."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "shell_lib_inject",
                    "path": path,
                    "scope": scope,
                    "injections": lib_injections[:10],
                },
                mitre="T1574.006",
            )
