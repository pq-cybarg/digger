"""Living-off-the-land binary detection.

Catches process invocations of canonical Windows/macOS/Linux LOLBins +
LOLBAS / GTFOBins style abuse: certutil downloads, bitsadmin transfers,
osascript shells, base64 + xxd round-trips, etc.
"""

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector

# (process basename pattern, cmdline pattern, technique id, description)
_RULES: list[tuple[re.Pattern, re.Pattern, str, str]] = [
    (re.compile(r"^certutil(\.exe)?$", re.I),
     re.compile(r"-urlcache|-encode|-decode|-decodehex", re.I),
     "T1140",
     "certutil used for download/decode (LOLBAS)"),
    (re.compile(r"^bitsadmin(\.exe)?$", re.I),
     re.compile(r"/transfer|/addfile", re.I),
     "T1197",
     "bitsadmin file transfer"),
    (re.compile(r"^mshta(\.exe)?$", re.I),
     re.compile(r"https?://|javascript:", re.I),
     "T1218.005",
     "mshta fetching remote/JS payload"),
    (re.compile(r"^regsvr32(\.exe)?$", re.I),
     re.compile(r"/i:https?://|/s\s+/u", re.I),
     "T1218.010",
     "regsvr32 squiblydoo style"),
    (re.compile(r"^rundll32(\.exe)?$", re.I),
     re.compile(r"javascript:|http", re.I),
     "T1218.011",
     "rundll32 with URL or JS protocol"),
    (re.compile(r"^msbuild(\.exe)?$", re.I),
     re.compile(r"\.xml|\.csproj|\.proj", re.I),
     "T1127.001",
     "msbuild executing inline project"),
    (re.compile(r"^installutil(\.exe)?$", re.I),
     re.compile(r"/logfile=|/u\s", re.I),
     "T1218.004",
     "installutil bypass"),
    (re.compile(r"^osascript$", re.I),
     re.compile(r"-e\s+.*\bdo shell script\b", re.I),
     "T1059.002",
     "osascript bridging to shell"),
    (re.compile(r"^xattr$", re.I),
     re.compile(r"-d\s+com\.apple\.quarantine", re.I),
     "T1553.005",
     "xattr removing quarantine attribute"),
    (re.compile(r"^(curl|wget)$", re.I),
     re.compile(r"https?://[^\s]+\.(?:sh|py|pl|exe|dll|dylib|bin)\b", re.I),
     "T1105",
     "curl/wget fetching executable content"),
    (re.compile(r"^nc(at)?(\.exe)?$", re.I),
     re.compile(r"-e\s|/bin/(sh|bash)|cmd\.exe", re.I),
     "T1059",
     "netcat reverse-shell pattern"),
    (re.compile(r"^socat$", re.I),
     re.compile(r"exec:|tcp:.*:\d+", re.I),
     "T1059",
     "socat redirection / shell"),
    (re.compile(r"^python[23]?$", re.I),
     re.compile(r"socket\.\w+\(\s*socket\.AF_INET|pty\.spawn", re.I),
     "T1059.006",
     "python one-liner reverse shell"),
    (re.compile(r"^bash$", re.I),
     re.compile(r"/dev/tcp/", re.I),
     "T1059.004",
     "bash /dev/tcp reverse shell"),
]


class LolbinDetector(Detector):
    name = "lolbins"
    description = "LOLBAS/GTFOBins-style abuse of trusted binaries."

    def to_sigma_template(self) -> dict:
        return {
            "title": "LOLBin / GTFOBins abuse: trusted binary used for download / execution",
            "id": "digger-lolbins-template",
            "description": (
                "A trusted system binary (certutil, bitsadmin, mshta, "
                "regsvr32, rundll32, msbuild, installutil, osascript, "
                "xattr, curl/wget, netcat/socat, python/bash one-liners) "
                "is invoked in a way that maps to a documented "
                "LOLBAS / GTFOBins technique."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_certutil": {
                    "Image|endswith": ["/certutil.exe", "/certutil"],
                    "CommandLine|contains": ["-urlcache", "-encode", "-decode", "-decodehex"],
                },
                "selection_bitsadmin": {
                    "Image|endswith": "/bitsadmin.exe",
                    "CommandLine|contains": ["/transfer", "/addfile"],
                },
                "selection_mshta": {
                    "Image|endswith": "/mshta.exe",
                    "CommandLine|contains": ["http://", "https://", "javascript:"],
                },
                "selection_regsvr32_squiblydoo": {
                    "Image|endswith": "/regsvr32.exe",
                    "CommandLine|re": r"/i:https?://|/s\s+/u",
                },
                "selection_rundll32_url": {
                    "Image|endswith": "/rundll32.exe",
                    "CommandLine|contains": ["javascript:", "http"],
                },
                "selection_msbuild": {
                    "Image|endswith": "/msbuild.exe",
                    "CommandLine|endswith": [".xml", ".csproj", ".proj"],
                },
                "selection_osascript_shell": {
                    "Image|endswith": "/osascript",
                    "CommandLine|contains|all": ["-e", "do shell script"],
                },
                "selection_xattr_quarantine": {
                    "Image|endswith": "/xattr",
                    "CommandLine|contains|all": ["-d", "com.apple.quarantine"],
                },
                "selection_curl_wget_exec": {
                    "Image|endswith": ["/curl", "/wget"],
                    "CommandLine|re": r"https?://[^\s]+\.(?:sh|py|pl|exe|dll|dylib|bin)\b",
                },
                "selection_netcat_revshell": {
                    "Image|endswith": ["/nc", "/ncat", "/nc.exe", "/ncat.exe"],
                    "CommandLine|re": r"-e\s|/bin/(sh|bash)|cmd\.exe",
                },
                "selection_bash_devtcp": {
                    "Image|endswith": "/bash",
                    "CommandLine|contains": "/dev/tcp/",
                },
                "condition": "1 of selection_*",
            },
            "level": "high",
            "tags": [
                "attack.execution", "attack.defense_evasion",
                "attack.t1140", "attack.t1197", "attack.t1218",
                "attack.t1218.005", "attack.t1218.010", "attack.t1218.011",
                "attack.t1127.001", "attack.t1105", "attack.t1059",
                "attack.t1059.004", "attack.t1059.006",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="processes"):
            data = art["data"]
            name = (data.get("name") or "").strip()
            cmd = " ".join(data.get("cmdline") or [])
            for name_re, cmd_re, mitre, desc in _RULES:
                if name_re.match(name) and cmd_re.search(cmd):
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=f"LOLBin/LOTL abuse: {name}",
                        summary=f"{desc}. Cmdline: {cmd[:300]}",
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"name": name, "cmdline": cmd, "pid": data.get("pid")},
                        mitre=mitre,
                    )
                    break
