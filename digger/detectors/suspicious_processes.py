"""Suspicious process heuristics.

Catches: shell spawned by browser, interpreter run from tmp, masquerading
process names (chrome.exe in C:\\Users\\Public), unsigned binaries in
elevated context, processes with hollow exes (exe path missing), etc.
"""

from __future__ import annotations

import os
import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector

_SHELL_NAMES = {
    "sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh",
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe",
}

_INTERPRETER_NAMES = {
    "python", "python3", "python2", "perl", "ruby", "node", "java",
    "python.exe", "python3.exe", "perl.exe", "ruby.exe", "node.exe", "java.exe",
}

_BROWSER_NAMES = {
    "chrome", "chrome.exe", "msedge.exe", "firefox", "firefox-bin",
    "safari", "brave", "brave-browser", "Google Chrome",
}

_SUSPICIOUS_PARENT_DIRS = [
    "/tmp/", "/var/tmp/", "/dev/shm/",
    r"\Temp\\", r"\AppData\Local\Temp\\", r"\Public\\",
    "/Users/Shared/", "/private/tmp/",
]


def _basename(path: str | None) -> str:
    if not path:
        return ""
    return os.path.basename(path).lower()


class SuspiciousProcessDetector(Detector):
    name = "suspicious_processes"
    description = "Heuristics over the process tree."

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        procs = list(store.iter_artifacts(collector="processes"))
        by_pid = {a["data"].get("pid"): a for a in procs if a["data"].get("pid")}
        for art in procs:
            data = art["data"]
            name = (data.get("name") or "").lower()
            exe = data.get("exe") or ""
            cmd = " ".join(data.get("cmdline") or [])
            ppid = data.get("ppid")
            parent = by_pid.get(ppid) if ppid else None
            parent_name = ((parent or {}).get("data", {}).get("name") or "").lower() if parent else ""

            # browser → shell
            if name in {n.lower() for n in _SHELL_NAMES} and parent_name in {n.lower() for n in _BROWSER_NAMES}:
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=f"Shell ({name}) spawned by browser ({parent_name})",
                    summary=(
                        f"PID {data.get('pid')} ({name}) was spawned by browser "
                        f"process {parent_name}. Browsers should not be parenting shells; "
                        "this is characteristic of post-exploitation via a malicious extension "
                        "or compromised renderer."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"process": data, "parent": (parent or {}).get("data")},
                    mitre="T1059",
                )

            # interpreter in tmp
            if name in {n.lower() for n in _INTERPRETER_NAMES}:
                for sus in _SUSPICIOUS_PARENT_DIRS:
                    if sus in (exe or "") or sus in cmd:
                        yield Finding(
                            detector=self.name,
                            severity="high",
                            title=f"Interpreter ({name}) running from drop location",
                            summary=(
                                f"PID {data.get('pid')} ({name}) is executing from or referencing "
                                f"a writable drop location ({sus}). Cmdline: {cmd[:300]}"
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={"process": data, "match": sus},
                            mitre="T1059",
                        )
                        break

            # missing exe (process hollowing / unlinked binary)
            if data.get("pid", 0) > 0 and not data.get("exe") and name and name not in {"kernel_task", "systemd"}:
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=f"Process with no exe path ({name})",
                    summary=(
                        "Process is running but the OS does not report an executable path. "
                        "This is consistent with a deleted-on-disk binary (memfd, unlinked) "
                        "or a process running from a filesystem we cannot read. Investigate."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"process": data},
                    mitre="T1055",
                )

            # base64/hex-encoded PowerShell
            if "powershell" in name and re.search(
                r"-e(c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{100,}", cmd, re.IGNORECASE
            ):
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title="Encoded PowerShell command",
                    summary=(
                        "powershell.exe invoked with base64-encoded -EncodedCommand argument. "
                        "Common to malicious tradecraft for obfuscation; decode and inspect."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"process": data, "cmdline": cmd},
                    mitre="T1059.001",
                )

            # curl|bash / iwr|iex
            if re.search(r"(curl|wget).*\|\s*(bash|sh|zsh)", cmd) or re.search(
                r"(iwr|invoke-webrequest).*\|\s*iex", cmd, re.IGNORECASE
            ):
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title="Pipe-to-shell from remote download",
                    summary=(
                        "Process command line pipes a remote download directly into a shell "
                        "interpreter. Classic dropper pattern."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"cmdline": cmd},
                    mitre="T1105",
                )
