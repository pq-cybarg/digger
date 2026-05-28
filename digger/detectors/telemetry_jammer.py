"""Windows telemetry jammer — detect + emit owner-sovereignty disablers.

The user (machine owner) wants to enumerate the Windows telemetry
surface running on their own hardware and get a copy-pasteable command
set to disable it. Same architecture as ``firewall_audit``: detection
is observation-only; the emitted ``remediation_commands`` block is for
the owner to run themselves at a shell. ``digger`` does not apply
these commands automatically — see the ethical contract's P2
(``assert_user_consent_for_modification``).

Why this exists
---------------
Telemetry collection on a Windows install is opt-in by *Microsoft's*
defaults, not necessarily by the device-owner's choice. Many privacy-
focused users want to neutralize:

  * DiagTrack ("Connected User Experiences and Telemetry")
  * dmwappushservice (push-notification routing for diagnostic data)
  * CompatTelRunner.exe (Application Experience compatibility appraiser)
  * Customer Experience Improvement Program tasks
  * Windows Error Reporting
  * Telemetry hosts: vortex.data.microsoft.com,
    settings-win.data.microsoft.com, telemetry.microsoft.com, watson*

Mainstream privacy tools that do exactly this:
O&O ShutUp10, WPD (Windows Privacy Dashboard), Windows10Privacy,
NoTelemetry. ``digger`` ships the *detection + command set*, not the
applicator.

What this detects
-----------------

  T1  DiagTrack service running / set to auto-start.
  T2  dmwappushservice running / set to auto-start.
  T3  CompatTelRunner / Microsoft Compatibility Appraiser scheduled
      task enabled.
  T4  Windows Error Reporting (WerSvc) running.
  T5  Customer Experience Improvement Program scheduled tasks enabled
      (Consolidator, KernelCeipTask, UsbCeip, etc.).
  T6  Telemetry registry key ``AllowTelemetry`` set above 0 (or
      missing — defaults to "Enhanced").
  T7  Telemetry endpoint DNS resolution observed in DNS history.

Each finding carries severity ``info`` or ``low`` — these are not
attack indicators. They are present-state observations on the user's
own system, with a remediation block they can copy-paste to disable.
"""

# live-first-ok: Telemetry component / service / scheduled-task names
# are stable across Windows releases (DiagTrack, dmwappushservice,
# Microsoft Compatibility Appraiser, etc.). When Microsoft changes
# them, the YAML rules-base would be the right place; no upstream
# live feed publishes this corpus.

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector
from digger.ethics.contract import redact_dangerous_command


# ---- Telemetry component table --------------------------------------- #
# Each entry: (kind, name_pattern, label, mitre-stub, remediation_commands).
# kind: "service" | "process" | "task" | "registry" | "dns"

_SERVICES: list[tuple[str, str, str]] = [
    # (Windows service short name, friendly name, MITRE/T-stub)
    ("DiagTrack",             "Connected User Experiences and Telemetry", "T1059.001"),
    ("dmwappushservice",      "WAP Push Message Routing",                  "T1059.001"),
    ("WerSvc",                "Windows Error Reporting",                   "T1059.001"),
    ("PcaSvc",                "Program Compatibility Assistant",           "T1059.001"),
    ("DPS",                   "Diagnostic Policy Service",                 "T1059.001"),
    ("DiagSvc",               "Diagnostic Execution Service",              "T1059.001"),
    ("WdiServiceHost",        "Diagnostic Service Host",                   "T1059.001"),
    ("WdiSystemHost",         "Diagnostic System Host",                    "T1059.001"),
]

_PROCESSES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bCompatTelRunner\.exe\b", re.I),
     "Microsoft Compatibility Telemetry runner"),
    (re.compile(r"\bMSCompatibilityAppraiser\b", re.I),
     "Compatibility Appraiser scheduled-task host"),
    (re.compile(r"\bWerFault\.exe\b", re.I),
     "Windows Error Reporting fault handler"),
    (re.compile(r"\bDeviceCensus\.exe\b", re.I),
     "Device Census telemetry binary"),
]

_SCHEDULED_TASKS = [
    "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
    "\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
    "\\Microsoft\\Windows\\Application Experience\\StartupAppTask",
    "\\Microsoft\\Windows\\Application Experience\\PcaPatchDbTask",
    "\\Microsoft\\Windows\\Autochk\\Proxy",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
    "\\Microsoft\\Windows\\Feedback\\Siuf\\DmClient",
    "\\Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload",
    "\\Microsoft\\Windows\\Windows Error Reporting\\QueueReporting",
    "\\Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
]

_TELEMETRY_HOSTS = [
    "vortex.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "settings-win.data.microsoft.com",
    "telemetry.microsoft.com",
    "watson.microsoft.com",
    "watson.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com",
    "v10.events.data.microsoft.com",
    "v10c.events.data.microsoft.com",
    "v10.vortex-win.data.microsoft.com",
    "self.events.data.microsoft.com",
    "us.vortex-win.data.microsoft.com",
    "eu.vortex-win.data.microsoft.com",
    "diagnostics.support.microsoft.com",
    "geover-prod.do.dsp.mp.microsoft.com",
]


# ---- Remediation command blocks (copy-pasteable, opt-in) ------------- #

_REMEDIATION_SERVICE = """\
# Stop and disable the {svc_name} service ({friendly}).
# Reversible: Set-Service -StartupType Automatic <name>; Start-Service <name>
Stop-Service -Name '{svc_name}' -Force -ErrorAction SilentlyContinue
Set-Service -Name '{svc_name}' -StartupType Disabled
"""

_REMEDIATION_TASK = """\
# Disable scheduled telemetry task.
# Reversible: Enable-ScheduledTask -TaskPath '<path>' -TaskName '<name>'
Disable-ScheduledTask -TaskPath '{task_path}' -TaskName '{task_name}' -ErrorAction SilentlyContinue
"""

_REMEDIATION_REGISTRY = """\
# Force AllowTelemetry to 0 (Security / off). Pro/Enterprise edition
# honors AllowTelemetry=0; Home edition floors at 1 (Basic).
# Reversible: remove the key with Remove-ItemProperty.
New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
# Also disable the AppCompat / diagnostic-data engines:
Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags' -Name 'AITEnable' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat' -Name 'DisableInventory' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows' -Name 'CEIPEnable' -Type DWord -Value 0
"""

_REMEDIATION_HOSTS = """\
# Block telemetry endpoints at the hosts-file level. Reversible: edit
# C:\\Windows\\System32\\drivers\\etc\\hosts and remove the lines.
$hostsFile = "$env:WINDIR\\System32\\drivers\\etc\\hosts"
$blockList = @(
{host_lines}
)
$existing = Get-Content $hostsFile -ErrorAction SilentlyContinue
$toAdd = $blockList | Where-Object {{ $existing -notcontains $_ }}
if ($toAdd) {{
    Add-Content -Path $hostsFile -Value "`n# digger telemetry-jammer block list" -Force
    $toAdd | ForEach-Object {{ Add-Content -Path $hostsFile -Value $_ -Force }}
}}
"""


def _build_hosts_remediation() -> str:
    lines = ",\n".join(f"    '0.0.0.0 {h}'" for h in _TELEMETRY_HOSTS)
    return _REMEDIATION_HOSTS.format(host_lines=lines)


def _redact_block(block: str) -> str:
    """Run each non-comment line through redact_dangerous_command."""
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


def _cmdline_str(cmdline) -> str:
    if isinstance(cmdline, list):
        return " ".join(str(c) for c in cmdline if c)
    return cmdline or ""


def _service_state_data(art_data: dict) -> tuple[str | None, str | None]:
    """Best-effort extract (service_name, start_type) from a services
    artifact regardless of which Windows collector wrote it."""
    name = (art_data.get("Name") or art_data.get("ServiceName")
            or art_data.get("name") or "")
    start = (art_data.get("StartType") or art_data.get("StartMode")
             or art_data.get("start_type") or art_data.get("startup_type")
             or "")
    return (name or None), (start or None)


class TelemetryJammerDetector(Detector):
    name = "telemetry_jammer"
    description = (
        "Detects active Windows telemetry surface (DiagTrack, "
        "dmwappushservice, CompatTelRunner, CEIP scheduled tasks, "
        "telemetry registry, telemetry-host DNS) on the owner's "
        "machine and emits copy-pasteable PowerShell disable commands. "
        "Observation-only; remediation is opt-in (user runs the "
        "commands themselves, same pattern as firewall_audit)."
    )

    def to_sigma_template(self) -> dict:
        # Not really an attack signature — but ship a Sigma form so
        # SIEM operators who want to alert on telemetry-engine
        # processes running (e.g., to confirm an opt-out worked) have
        # a starting point.
        return {
            "title": "Windows telemetry components running",
            "id": "digger-telemetry-jammer-template",
            "description": (
                "Process or service tied to Windows telemetry "
                "collection is active: CompatTelRunner.exe, "
                "DeviceCensus.exe, WerFault.exe, MSCompatibility"
                "Appraiser, DiagTrack / dmwappushservice / WerSvc / "
                "PcaSvc / DPS services."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_telemetry_proc": {
                    "Image|endswith": [
                        "\\CompatTelRunner.exe",
                        "\\DeviceCensus.exe",
                        "\\WerFault.exe",
                        "\\MSCompatibilityAppraiser.exe",
                    ],
                },
                "selection_telemetry_service_host": {
                    "Image|endswith": "\\svchost.exe",
                    "CommandLine|contains": [
                        "DiagTrack",
                        "dmwappushservice",
                        "WerSvc",
                        "PcaSvc",
                        "DPS",
                    ],
                },
                "condition": "1 of selection_*",
            },
            "level": "informational",
            "tags": [
                "attack.collection",
                "attack.t1059.001",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- T1 / T2 / T4 / etc. — services artifact (Windows) ---- #
        active_svcs: list[tuple[str, str, str]] = []
        for art in store.iter_artifacts(collector="services"):
            name, start = _service_state_data(art["data"] or {})
            if not name:
                continue
            n_lower = name.lower()
            for svc_name, friendly, _mitre in _SERVICES:
                if n_lower == svc_name.lower():
                    is_disabled = (start or "").lower() in {"disabled", "4"}
                    if is_disabled:
                        continue
                    active_svcs.append((svc_name, friendly, start or "Auto"))
                    yield Finding(
                        detector=self.name,
                        severity="low",
                        title=(
                            f"Telemetry service active: {svc_name} "
                            f"({friendly})"
                        ),
                        summary=(
                            f"Windows service ``{svc_name}`` "
                            f"({friendly}) is active with start type "
                            f"``{start or 'Auto'}``. On a machine you "
                            "own, you may want to disable this. The "
                            "``remediation_commands`` block contains "
                            "the Stop-Service + Set-Service "
                            "-StartupType Disabled commands you can "
                            "copy-paste. Reversible."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "telemetry_service",
                            "service": svc_name,
                            "friendly_name": friendly,
                            "start_type": start,
                            "remediation_commands": _redact_block(
                                _REMEDIATION_SERVICE.format(
                                    svc_name=svc_name, friendly=friendly,
                                )
                            ),
                            "reversible": True,
                        },
                        mitre="T1059.001",
                    )
                    break

        # ---- T3 — CompatTelRunner / appraiser in processes ---- #
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            cmd = _cmdline_str(d.get("cmdline"))
            exe = (d.get("exe") or "").lower()
            name = (d.get("name") or "").lower()
            haystack = f"{exe} {name} {cmd}"
            for rx, label in _PROCESSES:
                if not rx.search(haystack):
                    continue
                yield Finding(
                    detector=self.name,
                    severity="info",
                    title=(
                        f"Telemetry process running: {label} "
                        f"(pid {d.get('pid')})"
                    ),
                    summary=(
                        f"Process pid {d.get('pid')} ({d.get('name')}) "
                        f"matches: {label}. Disable via the scheduled-"
                        "task block in remediation_commands."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "telemetry_process",
                        "label": label,
                        "pid": d.get("pid"),
                        "exe": d.get("exe"),
                        "cmdline": cmd[:400],
                        "remediation_commands": _redact_block(
                            "\n".join(
                                _REMEDIATION_TASK.format(
                                    task_path=p.rsplit("\\", 1)[0] + "\\",
                                    task_name=p.rsplit("\\", 1)[1],
                                )
                                for p in _SCHEDULED_TASKS
                            )
                        ),
                        "reversible": True,
                    },
                    mitre="T1059.001",
                )
                break

        # ---- T5 — scheduled tasks artifact ---- #
        # Windows scheduled_tasks collector ships entries via task path.
        seen_tasks: set[str] = set()
        for art in store.iter_artifacts(collector="scheduled_tasks"):
            d = art["data"] or {}
            entries = d.get("entries") or [d]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                tpath = entry.get("TaskPath") or entry.get("path") or ""
                tname = entry.get("TaskName") or entry.get("name") or ""
                full = (tpath.rstrip("\\") + "\\" + tname).lower()
                state = (entry.get("State") or entry.get("status") or "").lower()
                if not full:
                    continue
                if state in {"disabled", "3"}:
                    continue
                for known in _SCHEDULED_TASKS:
                    if known.lower() in full or full in known.lower():
                        if known in seen_tasks:
                            continue
                        seen_tasks.add(known)
                        yield Finding(
                            detector=self.name,
                            severity="info",
                            title=(
                                f"Telemetry scheduled-task enabled: "
                                f"{known.rsplit(chr(92), 1)[1]}"
                            ),
                            summary=(
                                f"Scheduled task ``{known}`` is "
                                f"enabled (state ``{state or 'Ready'}``). "
                                "Disable via the Disable-ScheduledTask "
                                "command in remediation_commands."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "telemetry_task",
                                "task_path": known.rsplit("\\", 1)[0] + "\\",
                                "task_name": known.rsplit("\\", 1)[1],
                                "state": state,
                                "remediation_commands": _redact_block(
                                    _REMEDIATION_TASK.format(
                                        task_path=known.rsplit("\\", 1)[0] + "\\",
                                        task_name=known.rsplit("\\", 1)[1],
                                    )
                                ),
                                "reversible": True,
                            },
                            mitre="T1059.001",
                        )
                        break

        # ---- T6 — registry AllowTelemetry value ---- #
        #
        # The windows.registry_persistence collector emits one
        # Artifact per key with a ``values`` dict (name -> value)
        # plus ``hive`` + ``subkey`` fields. We also accept the
        # legacy flat-shape ``path``/``name``/``value`` artifacts
        # in case an out-of-tree collector emits them.
        for art in store.iter_artifacts(
            collector="windows.registry_persistence",
        ):
            d = art["data"] or {}
            subkey = (d.get("subkey") or "").lower()
            if "datacollection" not in subkey:
                continue
            values = d.get("values") or {}
            if not isinstance(values, dict):
                continue
            value = None
            for n, v in values.items():
                if str(n).lower() == "allowtelemetry":
                    value = v
                    break
            try:
                v_int = int(value) if value is not None else None
            except (TypeError, ValueError):
                v_int = None
            if v_int is None or v_int > 0:
                yield Finding(
                    detector=self.name,
                    severity="low",
                    title=(
                        f"AllowTelemetry registry value is "
                        f"{value if value is not None else 'missing'} "
                        "(≥1 means telemetry on)"
                    ),
                    summary=(
                        f"HKLM\\SOFTWARE\\Policies\\Microsoft\\"
                        f"Windows\\DataCollection\\AllowTelemetry "
                        f"= {value}. Set to 0 (or remove the key) "
                        "via the registry remediation commands. "
                        "Pro/Enterprise honors 0; Home edition "
                        "floors at 1."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "telemetry_registry",
                        "value": value,
                        "remediation_commands": _redact_block(
                            _REMEDIATION_REGISTRY,
                        ),
                        "reversible": True,
                    },
                    mitre="T1059.001",
                )

        # ---- T7 — telemetry DNS history ---- #
        seen_hosts: set[str] = set()
        for art in store.iter_artifacts(collector="dns"):
            d = art["data"] or {}
            host = (d.get("host") or d.get("name") or "").lower()
            entries = d.get("entries") or []
            haystack = [host] + [
                (e.get("host") or e.get("name") or "").lower()
                for e in entries if isinstance(e, dict)
            ]
            for h in haystack:
                if not h:
                    continue
                for tel_host in _TELEMETRY_HOSTS:
                    if tel_host in h and tel_host not in seen_hosts:
                        seen_hosts.add(tel_host)
                        yield Finding(
                            detector=self.name,
                            severity="info",
                            title=(
                                f"Telemetry host resolved: {tel_host}"
                            ),
                            summary=(
                                f"DNS history shows resolution of "
                                f"``{tel_host}``. Block at the hosts "
                                "file via the remediation commands. "
                                "Reversible (edit "
                                "C:\\Windows\\System32\\drivers\\etc\\"
                                "hosts to remove the entries)."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "telemetry_dns",
                                "host": tel_host,
                                "remediation_commands": _redact_block(
                                    _build_hosts_remediation()
                                ),
                                "reversible": True,
                            },
                            mitre="T1059.001",
                        )
                        break
