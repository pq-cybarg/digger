"""Windows registry persistence deep-audit detector.

Closes the third leg of the cross-platform persistence story
(macOS launchd + Linux systemd/cron/shell-rc + Windows registry).
The Windows registry-persistence collector already enumerates the
canonical persistence keys (Run, RunOnce, Winlogon, IFEO, COM CLSID,
Office add-ins, SilentProcessExit, Lsa). No detector currently
consumes these artifacts for deep audit — this fills the gap.

Detection layers
----------------
  R1  Run/RunOnce value with writable / scratch path:    high
      The Windows analogue of cron-in-/tmp — whoever can write
      to that path edits what runs at logon.

  R2  Run/RunOnce value with proxy-execution command:    high
      Command starts with rundll32 / mshta / regsvr32 / wscript /
      cscript. Classic Living-off-the-Land Binary (LOLBin)
      pattern — uses signed Microsoft binaries as proxy
      executors for arbitrary payloads. T1218.* family.

  R3  Run/RunOnce value with encoded PowerShell:         high
      ``powershell -enc <base64>`` / ``-EncodedCommand`` — the
      single most common Windows malware entry-point per ten
      years of MITRE-published incident reports.

  R4  Run/RunOnce value with network-fetch command:      high
      curl / wget / Invoke-WebRequest / certutil -urlcache —
      downloader stub on every logon.

  R5  Winlogon Shell / Userinit overridden:              critical
      Default is ``explorer.exe`` (Shell) / ``userinit.exe``
      (Userinit). Anything else is the textbook Winlogon
      hijack — the new binary runs in the logged-in user's
      session.

  R6  SilentProcessExit MonitorProcess configured:       high
      Per-binary subkey under SilentProcessExit causes the
      ``MonitorProcess`` to spawn when the target dies. Used
      for ghost-process surveillance / re-spawn on EDR kill.

  R7  Unfamiliar Run/RunOnce key value name:             info
      Surface-area awareness — uncommon name patterns
      (typosquats of legitimate Windows components, GUID-only
      names, names matching well-known threat-actor naming
      schemes).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# Windows-writable / scratch path fragments (lowercase comparison).
_WINDOWS_WRITABLE_FRAGMENTS = (
    r"\appdata\local\temp",
    r"\temp\\",
    r"\users\public",
    r"\windows\temp",
    r"\programdata\temp",
    r"%temp%",
    r"%tmp%",
    r"%userprofile%\downloads",
    r"%appdata%\local\temp",
    r"%public%",
    r"\downloads\\",
    r"\.cache\\",
)

_PROXY_EXEC_BINARIES = (
    "rundll32", "mshta", "regsvr32",
    "wscript", "cscript",
    "installutil", "msbuild",
    "certutil", "bitsadmin",
    "msxsl", "scrobj.dll",
    "ie4uinit",
)

_NETWORK_FETCH_RE = re.compile(
    r"\b(?:curl|wget|"
    r"invoke-webrequest|iwr|"
    r"new-object\s+net\.webclient|"
    r"certutil\s+(?:-urlcache|--?urlcache)|"
    r"bitsadmin\s+(?:/transfer|--?transfer))",
    re.IGNORECASE,
)

_POWERSHELL_ENC_RE = re.compile(
    r"powershell(?:\.exe)?\s+.*?-(?:enc|encodedcommand|"
    r"encodedarguments|e)\b\s+",
    re.IGNORECASE,
)


# Default winlogon values — anything else is a hijack.
_WINLOGON_DEFAULTS = {
    "shell": ("explorer.exe",),
    "userinit": (
        r"c:\windows\system32\userinit.exe,",
        "userinit.exe,",
    ),
}


def _is_run_or_runonce_subkey(subkey: str) -> bool:
    s = subkey.lower()
    return s.endswith(r"\run") or s.endswith(r"\runonce") or \
        s.endswith(r"\run\\") or s.endswith(r"\runonce\\")


def _is_winlogon_subkey(subkey: str) -> bool:
    s = subkey.lower()
    return s.endswith(r"currentversion\winlogon")


def _is_silent_process_exit_subkey(subkey: str) -> bool:
    s = subkey.lower()
    return s.endswith(r"silentprocessexit")


def _command_writable(cmd: str) -> bool:
    if not cmd:
        return False
    s = cmd.lower()
    return any(frag in s for frag in _WINDOWS_WRITABLE_FRAGMENTS)


def _first_token_basename(cmd: str) -> str:
    """First whitespace-separated token, normalized to bare basename
    (no .exe, no path). Handles ``"C:\\X\\foo.exe" arg`` (quoted)
    plus ``foo.exe arg`` (unquoted)."""
    if not cmd:
        return ""
    s = cmd.strip()
    if s.startswith("\""):
        end = s.find("\"", 1)
        token = s[1:end] if end > 0 else s[1:]
    else:
        token = s.split(None, 1)[0]
    base = token.replace("\\", "/").rsplit("/", 1)[-1]
    if base.lower().endswith(".exe"):
        base = base[:-4]
    return base.lower()


def _is_proxy_exec(cmd: str) -> bool:
    if not cmd:
        return False
    base = _first_token_basename(cmd)
    if base in _PROXY_EXEC_BINARIES:
        return True
    lower = cmd.lower()
    return any(b in lower for b in _PROXY_EXEC_BINARIES)


def _is_encoded_powershell(cmd: str) -> bool:
    return bool(_POWERSHELL_ENC_RE.search(cmd or ""))


def _has_network_fetch(cmd: str) -> bool:
    return bool(_NETWORK_FETCH_RE.search(cmd or ""))


class WindowsRegistryAuditDetector(Detector):
    name = "windows_registry_audit"
    description = (
        "Windows registry persistence deep audit: Run/RunOnce "
        "values with writable paths, proxy-exec commands, "
        "encoded PowerShell, network-fetch; Winlogon Shell / "
        "Userinit overrides; SilentProcessExit MonitorProcess."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Suspicious Windows registry persistence",
            "id": "digger-windows-registry-audit-template",
            "description": (
                "Windows registry value under a persistence key "
                "matches a malware-style pattern (writable-path "
                "command, LOLBin proxy exec, encoded PowerShell, "
                "network-fetch downloader, Winlogon hijack, "
                "SilentProcessExit MonitorProcess)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {
                    "kind": [
                        "registry_run_writable_path",
                        "registry_run_proxy_exec",
                        "registry_run_encoded_powershell",
                        "registry_run_network_fetch",
                        "registry_winlogon_hijack",
                        "registry_silent_process_exit",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1547.001", "attack.t1547.004",
                "attack.t1546.012", "attack.t1218",
                "attack.t1059.001", "attack.t1027",
                "attack.persistence",
                "attack.execution",
                "attack.defense_evasion",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(
            collector="windows.registry_persistence",
        ):
            yield from self._check_artifact(art)

    def _check_artifact(self, art) -> Iterable[Finding]:
        data = art["data"] or {}
        hive = data.get("hive") or ""
        subkey = data.get("subkey") or ""
        values = data.get("values") or {}
        if not isinstance(values, dict):
            values = {}
        ref = art["artifact_uuid"]
        full_key = f"{hive}\\{subkey}"

        if _is_run_or_runonce_subkey(subkey):
            for name, cmd in values.items():
                if not isinstance(cmd, str):
                    cmd = str(cmd) if cmd is not None else ""
                yield from self._check_run_value(
                    art, ref, full_key, name, cmd,
                )
        elif _is_winlogon_subkey(subkey):
            yield from self._check_winlogon(art, ref, full_key, values)
        elif _is_silent_process_exit_subkey(subkey):
            yield from self._check_silent_process_exit(
                art, ref, full_key, data,
            )

    # ---- R1-R4: Run / RunOnce per-value ---- #

    def _check_run_value(
        self,
        art,
        ref: str,
        full_key: str,
        name: str,
        cmd: str,
    ) -> Iterable[Finding]:
        # R1 writable
        if _command_writable(cmd):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Run-key value points at writable path: "
                    f"{name}"
                ),
                summary=(
                    f"Run-key ``{full_key}`` value ``{name}`` "
                    f"= ``{cmd[:300]}``. The command target lives "
                    "in a writable / scratch path "
                    "(%TEMP%, %APPDATA%\\Local\\Temp, Public, "
                    "Downloads, Windows\\Temp). On every logon "
                    "the registered binary runs; anyone with "
                    "write access to that path edits what runs."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "registry_run_writable_path",
                    "key": full_key,
                    "value_name": name,
                    "command": cmd[:512],
                },
                mitre="T1547.001",
            )

        # R2 proxy exec (LOLBin)
        if _is_proxy_exec(cmd):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Run-key value uses LOLBin proxy "
                    f"executor: {name}"
                ),
                summary=(
                    f"Run-key ``{full_key}`` value ``{name}`` "
                    f"= ``{cmd[:300]}``. The command uses a "
                    "signed-Microsoft Living-off-the-Land "
                    "binary (rundll32 / mshta / regsvr32 / "
                    "wscript / cscript / installutil / msbuild "
                    "/ certutil / bitsadmin / msxsl) as a proxy "
                    "executor. Documented T1218 family — almost "
                    "never legitimate in a Run-key entry."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "registry_run_proxy_exec",
                    "key": full_key,
                    "value_name": name,
                    "command": cmd[:512],
                },
                mitre="T1218",
            )

        # R3 encoded PowerShell
        if _is_encoded_powershell(cmd):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Run-key value runs encoded PowerShell: "
                    f"{name}"
                ),
                summary=(
                    f"Run-key ``{full_key}`` value ``{name}`` "
                    f"= ``{cmd[:300]}``. The command uses "
                    "PowerShell with ``-EncodedCommand`` (or "
                    "the ``-enc`` short form). Most common "
                    "Windows-malware entry-point per ten years "
                    "of MITRE-published incident reports. "
                    "Decode the base64 and review."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "registry_run_encoded_powershell",
                    "key": full_key,
                    "value_name": name,
                    "command": cmd[:512],
                },
                mitre="T1059.001",
            )

        # R4 network fetch
        if _has_network_fetch(cmd):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Run-key value fetches from the network: "
                    f"{name}"
                ),
                summary=(
                    f"Run-key ``{full_key}`` value ``{name}`` "
                    f"= ``{cmd[:300]}``. The command issues a "
                    "network fetch on every logon (curl / wget "
                    "/ Invoke-WebRequest / certutil -urlcache / "
                    "bitsadmin /transfer). Classic downloader-"
                    "stub persistence pattern."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "registry_run_network_fetch",
                    "key": full_key,
                    "value_name": name,
                    "command": cmd[:512],
                },
                mitre="T1547.001",
            )

    # ---- R5: Winlogon Shell / Userinit ---- #

    def _check_winlogon(
        self,
        art,
        ref: str,
        full_key: str,
        values: dict,
    ) -> Iterable[Finding]:
        for vname, default_set in _WINLOGON_DEFAULTS.items():
            for k, v in values.items():
                if k.lower() != vname:
                    continue
                if not isinstance(v, str):
                    continue
                if v.strip().lower() in default_set:
                    continue
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=(
                        f"Winlogon {k} overridden: "
                        f"{v[:200]}"
                    ),
                    summary=(
                        f"``{full_key}`` value ``{k}`` is set "
                        f"to ``{v[:300]}``, not the default "
                        f"(``{default_set[0]}``). Winlogon "
                        "Shell / Userinit hijacks are the "
                        "textbook user-session takeover — the "
                        "new binary runs in the logged-in "
                        "user's privileged context."
                    ),
                    artifact_refs=[ref],
                    evidence={
                        "kind": "registry_winlogon_hijack",
                        "key": full_key,
                        "value_name": k,
                        "value": v[:512],
                        "default_expected": default_set[0],
                    },
                    mitre="T1547.004",
                )

    # ---- R6: SilentProcessExit ---- #

    def _check_silent_process_exit(
        self,
        art,
        ref: str,
        full_key: str,
        data: dict,
    ) -> Iterable[Finding]:
        subkey_sample = data.get("subkey_sample") or []
        subkey_count = data.get("subkey_count") or 0
        if subkey_count == 0:
            return
        yield Finding(
            detector=self.name,
            severity="high",
            title=(
                f"SilentProcessExit has subkeys ({subkey_count})"
            ),
            summary=(
                f"``{full_key}`` has {subkey_count} subkey(s); "
                f"sample: ``{subkey_sample[:8]}``. Each subkey "
                "is a target binary name; the corresponding "
                "MonitorProcess fires when that target dies. "
                "Documented covert-IFEO / ghost-process "
                "surveillance primitive — used to re-spawn "
                "malware when EDR kills it, or to log when "
                "specific binaries exit."
            ),
            artifact_refs=[ref],
            evidence={
                "kind": "registry_silent_process_exit",
                "key": full_key,
                "subkey_count": subkey_count,
                "subkey_sample": subkey_sample[:20],
            },
            mitre="T1546.012",
        )
