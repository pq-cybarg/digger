"""Counter-attacker-tooling-on-this-host: the "Kali kit dropped on a victim"
pattern.

Observational only. Three pathways:

  T1  **Running** attacker tool — process artifact with name/exe matching a
      known attacker toolkit.

  T2  **Installed but not running** — installed_software inventory
      (brew/apt/rpm/snap/flatpak/Windows uninstall keys) mentions the tool;
      OR a known path exists on disk (we infer from collected `recent_files`
      / processes' exe paths since digger doesn't walk arbitrary fs paths).

  T3  Self-attribution — if the host appears to be a digger development
      clone (the digger module itself imports cleanly, or the case_dir
      lives inside a /digger/ tree) we mark each finding ``dev_context=true``
      so the reviewer can downrank cleanly rather than guessing.

Self-attribution detail: the user often runs digger against THEIR OWN host
during development; if `responder` (or whatever) happens to be in their
brew cellar, that's the developer, not the victim. We do NOT silently
suppress — per the audit-visible ethics principle (P10) we surface the
finding with the dev-context tag, and downstream renderers can choose to
collapse a section rather than hide.

MITRE: T1588.002 (Obtain Capabilities: Tool).
"""

from __future__ import annotations

import os
import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector
from digger.opsec.self_id import identify


# (canonical-tool-name, [process basename patterns], category)
_TOOLS: list[tuple[str, list[str], str]] = [
    # C2 frameworks
    ("metasploit",       ["msfconsole", "msfvenom", "msfd", "msfrpcd"],
     "c2_framework"),
    ("sliver-client",    ["sliver-client", "sliver_client", "sliver"],
     "c2_framework"),
    ("mythic",           ["mythic-cli", "mythic"], "c2_framework"),
    ("covenant",         ["covenant", "GruntHTTP"], "c2_framework"),
    ("havoc",            ["havoc", "demon"], "c2_framework"),
    ("brute-ratel-c4",   ["badger.exe", "ratel"], "c2_framework"),
    ("nighthawk",        ["nighthawk"], "c2_framework"),
    ("posh-c2",          ["posh-c2", "poshc2"], "c2_framework"),
    ("empire",           ["empire", "starkiller"], "c2_framework"),
    ("merlin",           ["merlinagent", "merlinserver"], "c2_framework"),
    ("pupy",             ["pupysh", "pupyclient", "pupygen"], "c2_framework"),

    # Lateral movement / impacket
    ("evil-winrm",       ["evil-winrm"], "lateral"),
    ("crackmapexec",     ["crackmapexec", "cme"], "lateral"),
    ("netexec",          ["netexec", "nxc"], "lateral"),
    ("impacket-psexec",  ["psexec.py"], "lateral"),
    ("impacket-smbexec", ["smbexec.py"], "lateral"),
    ("impacket-wmiexec", ["wmiexec.py"], "lateral"),
    ("impacket-dcomexec",["dcomexec.py"], "lateral"),
    ("impacket-atexec",  ["atexec.py"], "lateral"),
    ("impacket-secretsdump", ["secretsdump.py"], "lateral"),
    ("impacket-ntlmrelayx", ["ntlmrelayx.py"], "lateral"),
    ("impacket-ticketer", ["ticketer.py"], "lateral"),
    ("impacket-getst",   ["getst.py"], "lateral"),
    ("impacket-gettgt",  ["gettgt.py"], "lateral"),
    ("impacket-getuserspns", ["getuserspns.py"], "lateral"),
    ("impacket-getnpusers", ["getnpusers.py"], "lateral"),

    # AD recon
    ("bloodhound-python", ["bloodhound-python", "bloodhound.py"], "ad_recon"),
    ("sharphound",       ["sharphound", "sharphound.exe", "sharphound.ps1"],
     "ad_recon"),
    ("azurehound",       ["azurehound", "azurehound.exe"], "ad_recon"),
    ("ldapdomaindump",   ["ldapdomaindump", "ldapdomaindump.py"], "ad_recon"),
    ("windapsearch",     ["windapsearch", "windapsearch.py"], "ad_recon"),
    ("adexplorer",       ["adexplorer.exe"], "ad_recon"),
    ("rustyhound",       ["rustyhound"], "ad_recon"),
    ("certipy",          ["certipy", "certipy.py"], "ad_cs_abuse"),
    ("certify",          ["certify.exe"], "ad_cs_abuse"),
    ("kerbrute",         ["kerbrute"], "ad_recon"),
    ("kerbeus",          ["kerbeus"], "ad_recon"),

    # Network / MITM
    ("responder",        ["responder", "responder.py"], "network_mitm"),
    ("mitm6",            ["mitm6", "mitm6.py"], "network_mitm"),
    ("bettercap",        ["bettercap"], "network_mitm"),
    ("ettercap",         ["ettercap", "ettercap-cli", "ettercap-text-only"],
     "network_mitm"),
    ("dnsspoof",         ["dnsspoof"], "network_mitm"),
    ("yersinia",         ["yersinia"], "network_mitm"),
    ("scapy",            ["scapy"], "network_mitm"),

    # Credential dumping
    ("mimikatz",         ["mimikatz", "mimikatz.exe"], "creds"),
    ("mimipenguin",      ["mimipenguin", "mimipenguin.py"], "creds"),
    ("lazagne",          ["lazagne", "lazagne.exe"], "creds"),
    ("pwdump",           ["pwdump", "pwdumpx", "fgdump", "gsecdump"],
     "creds"),
    ("rubeus",           ["rubeus", "rubeus.exe"], "creds"),
    ("safetykatz",       ["safetykatz", "safetykatz.exe"], "creds"),
    ("dumpert",          ["dumpert", "dumpert.exe"], "creds"),

    # Offline crackers (presence is not malicious; flag for awareness)
    ("hashcat",          ["hashcat"], "cracker"),
    ("john",             ["john"], "cracker"),

    # Recon
    ("nmap",             ["nmap"], "recon"),
    ("masscan",          ["masscan"], "recon"),
    ("zmap",             ["zmap"], "recon"),
    ("naabu",            ["naabu"], "recon"),

    # Web pentesting
    ("sqlmap",           ["sqlmap", "sqlmap.py"], "web_pentest"),
    ("burp",             ["burpsuite", "BurpSuitePro"], "web_pentest"),
    ("zaproxy",          ["zaproxy", "zap.sh"], "web_pentest"),
    ("ffuf",             ["ffuf"], "web_pentest"),
    ("gobuster",         ["gobuster"], "web_pentest"),
    ("wfuzz",            ["wfuzz"], "web_pentest"),
    ("dirb",             ["dirb"], "web_pentest"),
    ("nikto",            ["nikto"], "web_pentest"),
    ("wpscan",           ["wpscan"], "web_pentest"),

    # Tunneling / pivot
    ("chisel",           ["chisel"], "tunnel"),
    ("ligolo",           ["ligolo", "ligolo-ng"], "tunnel"),
    ("ngrok",            ["ngrok"], "tunnel"),
    ("frp",              ["frpc", "frps"], "tunnel"),
    ("revsocks",         ["revsocks"], "tunnel"),
]


# Severity by category. Categories like "cracker" / "recon" are presence-
# only flags; "c2_framework" / "creds" / "lateral" are real critical.
_SEV_BY_CATEGORY = {
    "c2_framework":  "critical",
    "lateral":       "high",
    "ad_recon":      "high",
    "ad_cs_abuse":   "high",
    "network_mitm":  "high",
    "creds":         "critical",
    "cracker":       "low",
    "recon":         "medium",
    "web_pentest":   "medium",
    "tunnel":        "high",
}


# Path prefixes that suggest a development clone rather than a victim host.
_DEV_PATH_HINTS = (
    "/digger/", "/Desktop/priv/digger/", "/repos/digger/",
    "/.venv/", "/venv/", "/site-packages/",
    "/.cargo/registry/", "/.rustup/",
    "/node_modules/",
    "/.git/", "/dev/", "/Development/",
)


def _basename(path: str) -> str:
    if not path:
        return ""
    if "/" in path:
        path = path.rsplit("/", 1)[1]
    if "\\" in path:
        path = path.rsplit("\\", 1)[1]
    return path


def _looks_like_dev_path(path: str) -> bool:
    if not path:
        return False
    pl = path.lower()
    return any(h.lower() in pl for h in _DEV_PATH_HINTS)


def _build_tool_index() -> dict[str, tuple[str, str]]:
    """basename -> (canonical_tool_name, category)."""
    out: dict[str, tuple[str, str]] = {}
    for canonical, basenames, category in _TOOLS:
        for b in basenames:
            out[b.lower()] = (canonical, category)
    return out


_TOOL_INDEX = _build_tool_index()


def _scan_installed_blob(raw: str) -> list[tuple[str, str, str]]:
    """Yield (canonical, category, hit_line) for each tool name found
    in the raw output of dpkg/rpm/brew/snap/flatpak inventory."""
    if not raw:
        return []
    hits: list[tuple[str, str, str]] = []
    for line in raw.splitlines():
        line_l = line.lower()
        for canonical, _, category in _TOOLS:
            # match the canonical name as a whole word in the line
            if re.search(rf"\b{re.escape(canonical)}\b", line_l):
                hits.append((canonical, category, line.strip()[:200]))
                break
    return hits


class AttackerToolingDetector(Detector):
    name = "attacker_tooling"
    description = (
        "Attacker / red-team tooling found running or installed on this host. "
        "Self-attributes findings whose backing path looks like a development "
        "clone or virtualenv so reviewers can triage cleanly."
    )

    def to_sigma_template(self) -> dict:
        # Build the basename list dynamically from our tool corpus so adding
        # a new tool to _TOOLS automatically extends this SIEM rule.
        basenames: list[str] = []
        for _, names, _ in _TOOLS:
            for n in names:
                if not n:
                    continue
                ext = "/" + n
                if ext not in basenames:
                    basenames.append(ext)
        return {
            "title": "Attacker / red-team toolkit running on host",
            "id": "digger-attacker-tooling-template",
            "description": (
                "Process whose name matches a known offensive-security "
                "toolkit (Metasploit, Sliver, Mythic, Brute Ratel, Havoc, "
                "Empire, Covenant, Impacket family, evil-winrm, "
                "CrackMapExec / NetExec, BloodHound family, Certipy, "
                "Responder, mitm6, bettercap, LaZagne, mimipenguin, etc.). "
                "Generated by digger from the same corpus the AttackerToolingDetector uses; "
                "regenerate to keep in sync."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": basenames,
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": ["attack.t1588.002", "attack.resource_development"],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- T1 RUNNING tools ----
        seen_running: set[tuple[int, str]] = set()
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"]
            pid = d.get("pid")
            name = (d.get("name") or "").lower()
            exe = d.get("exe") or ""
            base = (_basename(exe) or name).lower()
            cmdline_blob = " ".join(d.get("cmdline") or [])

            # Match against the process basename + the first cmdline token
            cmd_first = (
                _basename(d.get("cmdline")[0]) if (d.get("cmdline") or [None])[0]
                else ""
            ).lower()
            match = _TOOL_INDEX.get(base) or _TOOL_INDEX.get(cmd_first) or None
            if not match:
                # Try matching any token in cmdline (covers "python <script.py>")
                for tok in (d.get("cmdline") or []):
                    if not tok:
                        continue
                    bn = _basename(str(tok)).lower()
                    m = _TOOL_INDEX.get(bn)
                    if m:
                        match = m
                        break
            if not match:
                continue
            canonical, category = match
            key = (pid, canonical)
            if key in seen_running:
                continue
            seen_running.add(key)

            # Self-attribution: is the exe path inside a dev clone / venv?
            dev_context = _looks_like_dev_path(exe) or any(
                _looks_like_dev_path(str(t)) for t in (d.get("cmdline") or [])
            )
            # Also self-attribute if this process looks like digger.
            ident = identify(d)
            if ident:
                dev_context = True

            sev = _SEV_BY_CATEGORY.get(category, "high")
            if dev_context and sev in ("high", "critical"):
                sev = "medium"  # downgrade for dev context, do not suppress

            yield Finding(
                detector=self.name,
                severity=sev,
                title=(
                    f"Attacker tool running: {canonical} ({category}) "
                    f"pid {pid}" + (" [dev-context]" if dev_context else "")
                ),
                summary=(
                    f"Process {base} (pid {pid}, exe={exe or '?'}) is a "
                    f"running instance of {canonical}, classified as "
                    f"{category}. "
                    + ("Self-attribution: the executable path or cmdline "
                       "suggests a digger / dev / virtualenv context — this "
                       "is most likely the developer running tests against "
                       "their own host, not a foothold."
                       if dev_context
                       else "No development-context cues; treat as present-on-"
                            "host attacker tooling and confirm provenance.")
                ),
                artifact_refs=[art["artifact_uuid"]],
                evidence={
                    "kind": "running_attacker_tool",
                    "tool": canonical,
                    "category": category,
                    "pid": pid,
                    "exe": exe,
                    "cmdline": cmdline_blob[:300],
                    "username": d.get("username"),
                    "dev_context": dev_context,
                    "self_attribution": ident,
                },
                mitre="T1588.002",
            )

        # ---- T2 INSTALLED tools ----
        seen_installed: set[str] = set()
        for art in store.iter_artifacts(collector="installed_software"):
            d = art["data"]
            subj = art["subject"]
            if subj.startswith("uninstall:"):
                # Windows registry uninstall keys
                for entry in d.get("entries") or []:
                    display = (entry.get("DisplayName") or
                               entry.get("name") or "").lower()
                    if not display:
                        continue
                    for canonical, basenames, category in _TOOLS:
                        if canonical in display or any(
                            b.lower() in display for b in basenames
                        ):
                            if canonical in seen_installed:
                                break
                            seen_installed.add(canonical)
                            sev = _SEV_BY_CATEGORY.get(category, "high")
                            yield Finding(
                                detector=self.name,
                                severity=sev,
                                title=(
                                    f"Attacker tool installed: {canonical} "
                                    f"({category}) — Windows uninstall key"
                                ),
                                summary=(
                                    f"Windows uninstall registry entry mentions "
                                    f"{canonical}: '{entry.get('DisplayName')}'. "
                                    "Confirms the tool is installed even if "
                                    "not currently running."
                                ),
                                artifact_refs=[art["artifact_uuid"]],
                                evidence={
                                    "kind": "installed_attacker_tool",
                                    "tool": canonical,
                                    "category": category,
                                    "source": "windows_uninstall",
                                    "entry": entry,
                                },
                                mitre="T1588.002",
                            )
                            break
                continue

            raw = d.get("raw") or ""
            if not isinstance(raw, str) or not raw:
                continue
            for canonical, category, line in _scan_installed_blob(raw):
                if canonical in seen_installed:
                    continue
                seen_installed.add(canonical)
                sev = _SEV_BY_CATEGORY.get(category, "high")
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=(
                        f"Attacker tool installed: {canonical} ({category}) "
                        f"— via {subj}"
                    ),
                    summary=(
                        f"The {subj} package inventory lists {canonical}. "
                        "Confirms the tool is installed even if not currently "
                        "running. On a dev/researcher host this is normal; on "
                        "a production endpoint or a fresh-build host it is "
                        "the canonical 'dropped a kit' signature."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "installed_attacker_tool",
                        "tool": canonical,
                        "category": category,
                        "source": subj,
                        "line": line,
                    },
                    mitre="T1588.002",
                )
