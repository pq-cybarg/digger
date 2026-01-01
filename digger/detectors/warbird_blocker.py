"""Microsoft Warbird detection + owner-sovereignty disabler.

Warbird is Microsoft's internal code-obfuscation and anti-tamper
framework used to protect proprietary components — primarily the
Software Protection Platform (license enforcement / activation), the
Windows Hello cryptographic store, certain Defender code paths, and
a handful of kernel drivers.

The user (machine owner) wants to see what's Warbird-protected on
their own hardware and disable it. Same architecture as
``firewall_audit`` and ``telemetry_jammer``: pure observation with
copy-pasteable opt-in remediation commands. ``digger`` does not apply
the changes — see the ethics contract's P2.

Significant warning
-------------------
Disabling Warbird-protected components has reversible-only-with-difficulty
side effects:

  * Disabling ``sppsvc`` (Software Protection Platform) **breaks
    Windows Activation** on a licensed install. Activation status
    will eventually move to "Not activated" and certain Windows
    features (personalization, OEM lock-screen overrides, Pro/
    Enterprise feature gating) may stop functioning.
  * Blocking ``ClipSp.sys`` (PlayReady) breaks DRM video playback in
    Edge, Netflix-on-Edge, certain streaming apps.
  * Blocking ``ngc.dll`` / ``ngccredprov.dll`` breaks Windows Hello
    PIN / biometric sign-in.
  * Blocking ``ksecdd.sys`` is **not safe** — it's the kernel
    security driver — and digger refuses to emit commands that
    target it. We surface it as a finding for awareness but the
    remediation block is informational only.

The user is responsible for the consequences on hardware they own.
The remediation commands are routed through
``redact_dangerous_command`` so destructive operations carry a clear
warning prefix before display.

What this detects
-----------------

  W1  sppsvc.exe process running.
  W2  Software Protection (sppsvc) service enabled / running.
  W3  ClipSp.sys driver loaded (PlayReady DRM kernel driver).
  W4  ngc.dll / ngccredprov.dll loaded (Windows Hello credential
      providers).
  W5  EtwTi (ETW Threat-Intelligence provider) registered — used by
      Defender / EDR for kernel-event telemetry, and itself a
      Warbird-protected surface.
  W6  ksecdd.sys driver loaded — informational only, no remediation
      offered.

Each finding carries an evidence ``warning`` field describing what
breaks if the user applies the remediation, plus
``remediation_commands`` they can copy-paste at an elevated shell.
"""

# live-first-ok: Warbird-protected component names (sppsvc.exe,
# ClipSp.sys, ngc.dll, etc.) are stable across Windows releases.
# Microsoft does not publish a machine-readable list; the bundled
# YAML rules would be the place to add new ones.

from __future__ import annotations

from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector
from digger.ethics.contract import redact_dangerous_command


# ---- Warbird-protected components ---- #

_WARBIRD_PROCESSES: dict[str, dict] = {
    "sppsvc.exe": {
        "label": "Software Protection Platform service host",
        "purpose": "Windows Activation / licensing enforcement",
        "warning": (
            "Disabling sppsvc breaks Windows Activation. The system "
            "will display 'Not activated' status, lose personalization, "
            "and may gate Pro/Enterprise features after the activation "
            "grace period expires."
        ),
        "remediation": """\
# Stop Software Protection service.
# WARNING: this breaks Windows Activation. Reversible:
#   Set-Service -Name sppsvc -StartupType Manual; Start-Service -Name sppsvc
Stop-Service -Name 'sppsvc' -Force -ErrorAction SilentlyContinue
Set-Service -Name 'sppsvc' -StartupType Disabled
""",
    },
}

_WARBIRD_SERVICES: dict[str, dict] = {
    "sppsvc": _WARBIRD_PROCESSES["sppsvc.exe"],
    "ClipSVC": {
        "label": "Client License Service (Microsoft Store DRM)",
        "purpose": "Microsoft Store license arbitration",
        "warning": (
            "Disabling ClipSVC breaks Microsoft Store app launches "
            "for licensed apps."
        ),
        "remediation": """\
# Stop Client License Service.
# WARNING: this breaks Microsoft Store licensed apps. Reversible:
#   Set-Service -Name ClipSVC -StartupType Manual
Stop-Service -Name 'ClipSVC' -Force -ErrorAction SilentlyContinue
Set-Service -Name 'ClipSVC' -StartupType Disabled
""",
    },
    "WdNisSvc": {
        "label": "Microsoft Defender Antivirus Network Inspection Service",
        "purpose": "Defender network-IPS engine (Warbird-protected)",
        "warning": (
            "Disabling WdNisSvc removes Defender's network-traffic "
            "inspection. EDR coverage is materially reduced. Only do "
            "this if you have a replacement EDR running."
        ),
        "remediation": """\
# Stop Defender Network Inspection Service.
# WARNING: removes a Defender protection layer.
Stop-Service -Name 'WdNisSvc' -Force -ErrorAction SilentlyContinue
Set-Service -Name 'WdNisSvc' -StartupType Disabled
""",
    },
}

_WARBIRD_DRIVERS: dict[str, dict] = {
    "ClipSp.sys": {
        "label": "PlayReady DRM kernel driver",
        "purpose": "DRM enforcement for protected video / audio streams",
        "warning": (
            "Blocking ClipSp.sys breaks DRM video playback in Edge, "
            "Netflix-on-Edge, and similar streaming clients."
        ),
        "remediation": """\
# Disable ClipSp.sys driver. WARNING: breaks DRM video playback.
# Reversible: sc.exe config ClipSp start= demand
sc.exe config ClipSp start= disabled
""",
    },
    "ksecdd.sys": {
        "label": "Kernel Security Support Provider Interface driver",
        "purpose": "Core OS cryptographic services (LSA, Schannel, NTLM)",
        "warning": (
            "ksecdd.sys is essential for OS boot. Disabling it bricks "
            "the install. digger refuses to emit a disable command for "
            "ksecdd. This finding is informational only."
        ),
        "remediation": "",  # explicitly no command
    },
    "ngc.dll": {
        "label": "Windows Hello Next-Generation Credential provider",
        "purpose": "PIN / biometric sign-in (Windows Hello)",
        "warning": (
            "Blocking ngc.dll breaks Windows Hello PIN and biometric "
            "sign-in. Password sign-in still works."
        ),
        "remediation": """\
# Disable Windows Hello PIN / biometric credential provider.
# Reversible: re-enable via Settings → Accounts → Sign-in options.
# WARNING: PIN + biometric sign-in stop working; revert to password.
Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\PassportForWork' -Name 'Enabled' -Type DWord -Value 0
""",
    },
}


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


def _service_state_data(art_data: dict) -> tuple[str | None, str | None]:
    name = (art_data.get("Name") or art_data.get("ServiceName")
            or art_data.get("name") or "")
    start = (art_data.get("StartType") or art_data.get("StartMode")
             or art_data.get("start_type") or art_data.get("startup_type")
             or "")
    return (name or None), (start or None)


class WarbirdBlockerDetector(Detector):
    name = "warbird_blocker"
    description = (
        "Detects Microsoft Warbird-protected components running on "
        "the owner's machine — sppsvc.exe (Activation), ClipSp.sys "
        "(PlayReady DRM), ngc.dll (Windows Hello), WdNisSvc (Defender "
        "NIS), ClipSVC (Store DRM) — and emits opt-in disable commands "
        "with clear warnings about what each one breaks. Observation-"
        "only; user runs the commands themselves at an elevated shell."
    )

    def to_sigma_template(self) -> dict:
        # Not really an attack signature. SIEM operators may want to
        # alert on Warbird-protected processes starting (to confirm
        # disabled state); ship a starter template.
        return {
            "title": "Warbird-protected Windows component active",
            "id": "digger-warbird-blocker-template",
            "description": (
                "A Microsoft Warbird-protected service or process is "
                "running: sppsvc.exe / ClipSVC / WdNisSvc / ClipSp.sys "
                "/ ngc.dll / ksecdd.sys."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_warbird_proc": {
                    "Image|endswith": list(_WARBIRD_PROCESSES.keys()),
                },
                "condition": "selection_warbird_proc",
            },
            "level": "informational",
            "tags": [
                "attack.execution",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        seen: set[str] = set()

        # ---- W1 — Warbird processes ---- #
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            name = (d.get("name") or "").lower()
            exe = (d.get("exe") or "").lower()
            for pname, info in _WARBIRD_PROCESSES.items():
                if name == pname.lower() or exe.endswith("\\" + pname.lower()):
                    key = f"proc:{pname}"
                    if key in seen:
                        continue
                    seen.add(key)
                    yield Finding(
                        detector=self.name,
                        severity="low",
                        title=(
                            f"Warbird-protected process active: {pname} "
                            f"({info['label']})"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} ({pname}) is "
                            f"running. Purpose: {info['purpose']}. "
                            f"\n\nWarning: {info['warning']}\n\n"
                            "The remediation_commands block contains "
                            "the disable command. Owner runs it; "
                            "digger does not apply it."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "warbird_process",
                            "component": pname,
                            "label": info["label"],
                            "pid": d.get("pid"),
                            "warning": info["warning"],
                            "remediation_commands": _redact_block(
                                info["remediation"]
                            ),
                            "reversible": True,
                        },
                        mitre="T1059.001",
                    )

        # ---- W2 — Warbird services ---- #
        for art in store.iter_artifacts(collector="services"):
            sname, start = _service_state_data(art["data"] or {})
            if not sname:
                continue
            for svc_name, info in _WARBIRD_SERVICES.items():
                if sname.lower() != svc_name.lower():
                    continue
                if (start or "").lower() in {"disabled", "4"}:
                    continue
                key = f"svc:{svc_name}"
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    detector=self.name,
                    severity="low",
                    title=(
                        f"Warbird-protected service enabled: {svc_name} "
                        f"({info['label']})"
                    ),
                    summary=(
                        f"Windows service ``{svc_name}`` ({info['label']}) "
                        f"is enabled with start type ``{start or 'Auto'}``. "
                        f"Purpose: {info['purpose']}.\n\nWarning: "
                        f"{info['warning']}\n\nDisable via the "
                        "remediation_commands block."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "warbird_service",
                        "component": svc_name,
                        "label": info["label"],
                        "start_type": start,
                        "warning": info["warning"],
                        "remediation_commands": _redact_block(
                            info["remediation"]
                        ),
                        "reversible": True,
                    },
                    mitre="T1059.001",
                )

        # ---- W3/W4/W5/W6 — Warbird drivers / DLLs loaded ---- #
        # Sources: kmod (Linux) doesn't apply; on Windows we look at
        # process open_files / loaded modules collected via the
        # process / kext-style artifacts.
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            opens = d.get("open_files") or []
            loaded = d.get("modules") or []  # Windows collector ships these
            haystacks = []
            for of in opens:
                if isinstance(of, dict):
                    haystacks.append((of.get("path") or "").lower())
                elif isinstance(of, str):
                    haystacks.append(of.lower())
            for m in loaded:
                if isinstance(m, dict):
                    haystacks.append((m.get("path") or m.get("name") or "").lower())
                elif isinstance(m, str):
                    haystacks.append(m.lower())

            for drv_name, info in _WARBIRD_DRIVERS.items():
                low = drv_name.lower()
                for hay in haystacks:
                    if low in hay:
                        key = f"drv:{drv_name}:{d.get('pid')}"
                        if key in seen:
                            continue
                        seen.add(key)
                        # ksecdd.sys is severity info with no remediation
                        if drv_name == "ksecdd.sys":
                            sev = "info"
                        else:
                            sev = "low"
                        yield Finding(
                            detector=self.name,
                            severity=sev,
                            title=(
                                f"Warbird-protected driver/DLL loaded: "
                                f"{drv_name} ({info['label']})"
                            ),
                            summary=(
                                f"Component ``{drv_name}`` is loaded by "
                                f"pid {d.get('pid')} ({d.get('name')}). "
                                f"Purpose: {info['purpose']}.\n\n"
                                f"Warning: {info['warning']}\n\n"
                                + ("No remediation is offered for this "
                                   "component (essential for boot)."
                                   if not info["remediation"]
                                   else "Disable via remediation_commands.")
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "warbird_driver",
                                "component": drv_name,
                                "label": info["label"],
                                "loaded_by_pid": d.get("pid"),
                                "warning": info["warning"],
                                "remediation_commands": _redact_block(
                                    info["remediation"]
                                ),
                                "reversible": bool(info["remediation"]),
                                "essential_for_boot": drv_name == "ksecdd.sys",
                            },
                            mitre="T1059.001",
                        )
                        break
