"""Nightmare-Eclipse Windows-Defender exploit-kit campaign detector.

Disclosed by Huntress + Barracuda + Picus Security in mid-2026. A
single disgruntled security researcher ("Nightmare-Eclipse" / "Chaotic
Eclipse" / "Dead Eclipse") released six Windows zero-day proof-of-
concept exploits since 2026-04-03 in a retaliatory campaign against
Microsoft. The exploits have already been weaponized in real-world
intrusions and added to CISA KEV.

Six exploits, only one patched as of disclosure:

  BlueHammer    CVE-2026-33825 — Defender TOCTOU LPE via oplock + NTFS
                                 junction redirection. PATCHED (April
                                 2026 Patch Tuesday; Defender platform
                                 4.18.26050.3011+).
  RedSun        UNPATCHED — Defender cloud-file rollback abuse.
  UnDefend      UNPATCHED — Disables Defender without admin.
  YellowKey     UNPATCHED — BitLocker bypass on TPM-only protectors.
  GreenPlasma   UNPATCHED — Windows LPE primitive.
  MiniPlasma    UNPATCHED — Cloud Files Mini Filter Driver LPE.

Detection layers, in severity order:

  N1  Known exploit-binary hash match
      SHA-256 / SHA-1 / MD5 of the SNEK_BlueWarHammer.exe release and
      the BeigeBurrow agent.exe observed in the Huntress intrusion.
      Critical. T1068 (LPE) or T1572 (tunnel).

  N2  Operator-staged exploit filenames
      FunnyApp.exe / RedSun.exe / undef.exe / z.exe /
      SNEK_BlueWarHammer.exe under any user directory. Filename alone
      isn't dispositive (FunnyApp.exe is operator-named for cover),
      but in combination with N1/N3/N4 it's high signal.

  N3  Operator-cmdline shapes
      ``agent.exe -server <host>:443 -hide`` (BeigeBurrow tunnel,
      dispositive when -hide flag present). ``undef.exe -h`` or the
      misspelled ``-agressive`` flag (operator-observed). ``RedSun
      ...`` invocation.

  N4  C2 / source-IP / Defender-quarantine markers
      ``staybud.dpdns.org`` in any artifact (DNS / processes /
      browser / config). Source-IPs ``78.29.48.29 / 212.232.23.69 /
      179.43.140.214`` in connection tables. Defender quarantine
      strings ``Exploit:Win32/DfndrPEBluHmr*`` / ``DfndrPERdSun`` /
      ``DfndrUnDef`` in any Defender artifact.

Each finding carries:
  - evidence.exploit          which of the six (BlueHammer / RedSun /
                              UnDefend / YellowKey / GreenPlasma /
                              MiniPlasma / BeigeBurrow)
  - evidence.kind             hash / filename / cmdline / c2 / quarantine
  - evidence.mitigation       per-exploit guidance routed through
                              redact_dangerous_command
  - evidence.patch_status     patched / unpatched (only BlueHammer is
                              patched as of disclosure)
  - mitre                     T1068 (LPE) / T1562.001 (Defender disable)
                              / T1572 (tunnel) / T1190 (vuln exploitation)
"""

# live-first-ok: Nightmare-Eclipse IOCs live on vendor blogs (Huntress,
# Barracuda, Picus, RH-ISAC) and in CISA KEV (for CVE-2026-33825). The
# CISA KEV live feed is already wired into SupplyChainDetector; this
# detector's filename/cmdline/hash/C2 IOCs are bundled-only and will
# need a YAML refresh when new Nightmare-Eclipse zero-days drop.

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors._rules_io import load_yaml
from digger.detectors.base import Detector
from digger.ethics.contract import redact_dangerous_command


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


def _basename(path: str) -> str:
    if not path:
        return ""
    if "/" in path:
        path = path.rsplit("/", 1)[1]
    if "\\" in path:
        path = path.rsplit("\\", 1)[1]
    return path


class NightmareEclipseDetector(Detector):
    name = "nightmare_eclipse"
    description = (
        "Nightmare-Eclipse Windows-Defender exploit-kit campaign: "
        "BlueHammer (CVE-2026-33825, patched) and five UNPATCHED zero-"
        "days (RedSun / UnDefend / YellowKey / GreenPlasma / "
        "MiniPlasma). Catches exploit-binary hashes, operator-staged "
        "filenames, BeigeBurrow tunnel cmdline, C2 domain and source "
        "IPs, and Defender quarantine markers."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Nightmare-Eclipse exploit-kit: BlueHammer / RedSun / UnDefend / BeigeBurrow",
            "id": "digger-nightmare-eclipse-template",
            "description": (
                "A process matches the Nightmare-Eclipse campaign by "
                "any of: known SHA-256 / SHA-1 / MD5 of SNEK_BlueWar"
                "Hammer.exe or the BeigeBurrow agent.exe; operator-"
                "staged filename (FunnyApp.exe / RedSun.exe / "
                "undef.exe / z.exe / SNEK_BlueWarHammer.exe / "
                "agent.exe under a user dir); BeigeBurrow tunnel "
                "cmdline (agent.exe -server <host>:443 -hide); undef "
                "help/agressive flag; C2 callout to staybud.dpdns.org "
                "or source-IPs 78.29.48.29 / 212.232.23.69 / "
                "179.43.140.214; Defender quarantine entries naming "
                "Exploit:Win32/DfndrPEBluHmr* / DfndrPERdSun / "
                "DfndrUnDef."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_exploit_filename": {
                    "Image|endswith": [
                        "\\FunnyApp.exe",
                        "\\RedSun.exe",
                        "\\undef.exe",
                        "\\z.exe",
                        "\\SNEK_BlueWarHammer.exe",
                    ],
                },
                "selection_beigeburrow_tunnel": {
                    "Image|endswith": "\\agent.exe",
                    "CommandLine|re": r"-server\s+\S+:443\s+-hide",
                },
                "selection_undef_cmdline": {
                    "CommandLine|re": (
                        r"\bundef(?:end)?(?:\.exe)?\s+-(?:h|help|"
                        r"agressive|aggressive)\b"
                    ),
                },
                "selection_redsun_cmdline": {
                    "CommandLine|re": r"\bRedSun(?:\.exe)?\b",
                },
                "selection_c2_callout": {
                    "CommandLine|contains": [
                        "staybud.dpdns.org",
                        "78.29.48.29",
                        "212.232.23.69",
                        "179.43.140.214",
                    ],
                },
                "selection_defender_quarantine": {
                    "CommandLine|contains": [
                        "Exploit:Win32/DfndrPEBluHmr",
                        "Exploit:Win32/DfndrPERdSun",
                        "Exploit:Win32/DfndrUnDef",
                    ],
                },
                "condition": "1 of selection_*",
            },
            "level": "critical",
            "tags": [
                "attack.t1068",
                "attack.t1190",
                "attack.t1562.001",
                "attack.t1572",
                "attack.privilege_escalation",
                "attack.defense_evasion",
                "attack.command_and_control",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        rules = load_yaml("exploits/nightmare_eclipse.yaml") or {}
        if not rules:
            return

        campaign = rules.get("campaign") or "Nightmare-Eclipse"
        source = rules.get("source") or "huntress.com,barracuda.com"
        disclosed = rules.get("disclosed") or "2026-04-03"
        references = rules.get("references") or []

        # Build IOC tables
        hash_iocs = rules.get("hashes") or []
        sha256_iocs = {h["sha256"].lower(): h for h in hash_iocs
                       if isinstance(h, dict) and h.get("sha256")}
        sha1_iocs = {h["sha1"].lower(): h for h in hash_iocs
                     if isinstance(h, dict) and h.get("sha1")}
        md5_iocs = {h["md5"].lower(): h for h in hash_iocs
                    if isinstance(h, dict) and h.get("md5")}

        exploit_filenames = {n.lower() for n in
                              rules.get("exploit_filenames") or []}
        defender_qnames = [
            n for n in rules.get("defender_quarantine_names") or [] if n
        ]
        c2 = rules.get("c2") or {}
        c2_domains = [d.lower() for d in (c2.get("domains") or []) if d]
        c2_ips = list(c2.get("source_ips") or [])

        cmdline_sigs = rules.get("cmdline_signatures") or {}

        mitigation = rules.get("mitigation") or {}
        mit_patched = _redact_block(mitigation.get("patched_bluehammer", ""))
        mit_unpatched = _redact_block(mitigation.get("unpatched_general", ""))
        mit_yellowkey = _redact_block(mitigation.get("yellowkey_bitlocker", ""))
        mit_hunt = _redact_block(mitigation.get("hunt_for_exploit_binaries", ""))

        common_response = (
            "Nightmare-Eclipse is a campaign of public Windows zero-day "
            "PoCs targeting Defender, BitLocker, and Cloud Files. "
            "Treat host as compromised: rotate credentials accessible to "
            "the user context, check for the BeigeBurrow tunnel "
            "(staybud.dpdns.org:443), inspect Defender quarantine for "
            "Exploit:Win32/DfndrPEBluHmr* markers, and verify Defender "
            "platform is at version 4.18.26050.3011 or later (the "
            f"BlueHammer/CVE-2026-33825 fix). Disclosed by {source} "
            f"starting {disclosed}."
        )

        # ---- N1 hash IOCs in known hash-bearing artifacts ---- #
        # Sources of file hashes in digger:
        #   - processes (exe_sha256)
        #   - signing collector / files table
        # Iterate processes first.

        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            for hash_field, table, label in (
                ("exe_sha256", sha256_iocs, "SHA-256"),
                ("exe_sha1", sha1_iocs, "SHA-1"),
                ("exe_md5", md5_iocs, "MD5"),
            ):
                hv = (d.get(hash_field) or "").lower()
                if hv and hv in table:
                    ioc = table[hv]
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Nightmare-Eclipse exploit binary "
                            f"({ioc.get('family')}): {label} match on "
                            f"pid {d.get('pid')} ({d.get('name')})"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} "
                            f"({d.get('name')}, exe {d.get('exe')}) "
                            f"matches the published {ioc.get('name')} "
                            f"{label} of "
                            f"{ioc.get(label.lower().replace('-', '_'))}."
                            f" Family: {ioc.get('family')}. "
                            f"{common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "hash",
                            "campaign": campaign,
                            "exploit": ioc.get("family"),
                            "hash_algo": label,
                            "hash": hv,
                            "exe": d.get("exe"),
                            "pid": d.get("pid"),
                            "name": d.get("name"),
                            "mitigation_commands": (
                                mit_unpatched if ioc.get("family") != "BlueHammer"
                                else mit_patched
                            ),
                            "patch_status": (
                                "patched (CVE-2026-33825)"
                                if ioc.get("family") == "BlueHammer"
                                else "unpatched"
                            ),
                            "references": references,
                        },
                        mitre=(
                            "T1572" if ioc.get("family") == "BeigeBurrow"
                            else "T1068"
                        ),
                    )

        # Also check the files table for static-file IOCs.
        for art in store.iter_artifacts(category="filesystem"):
            d = art["data"] or {}
            entries = d.get("entries") or ([d] if d.get("path") else [])
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                for hash_field, table, label in (
                    ("sha256", sha256_iocs, "SHA-256"),
                    ("sha1", sha1_iocs, "SHA-1"),
                    ("md5", md5_iocs, "MD5"),
                ):
                    hv = (entry.get(hash_field) or "").lower()
                    if hv and hv in table:
                        ioc = table[hv]
                        yield Finding(
                            detector=self.name,
                            severity="critical",
                            title=(
                                f"Nightmare-Eclipse exploit file on disk: "
                                f"{entry.get('path')} ({label} match)"
                            ),
                            summary=(
                                f"File {entry.get('path')} matches the "
                                f"published {ioc.get('name')} hash. "
                                f"Family: {ioc.get('family')}. "
                                f"{common_response}"
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "hash",
                                "campaign": campaign,
                                "exploit": ioc.get("family"),
                                "hash_algo": label,
                                "hash": hv,
                                "path": entry.get("path"),
                                "mitigation_commands": (
                                    mit_unpatched if ioc.get("family") != "BlueHammer"
                                    else mit_patched
                                ),
                                "patch_status": (
                                    "patched (CVE-2026-33825)"
                                    if ioc.get("family") == "BlueHammer"
                                    else "unpatched"
                                ),
                                "references": references,
                            },
                            mitre="T1068",
                        )

        # ---- N2 operator-staged exploit filenames ---- #
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
                if base in exploit_filenames:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Nightmare-Eclipse exploit-stage filename: "
                            f"{path}"
                        ),
                        summary=(
                            f"File ``{path}`` matches a Nightmare-Eclipse "
                            "operator-staged filename observed in the "
                            "Huntress intrusion (FunnyApp.exe / RedSun.exe "
                            "/ undef.exe / z.exe / SNEK_BlueWarHammer.exe "
                            "/ agent.exe). Filename alone is not "
                            "dispositive (operators rename freely) but "
                            "in combination with hash / cmdline / C2 "
                            f"signals it is high signal. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "filename",
                            "campaign": campaign,
                            "basename": base,
                            "path": path,
                            "mitigation_commands": mit_hunt,
                            "patch_status": "see per-exploit notes",
                            "references": references,
                        },
                        mitre="T1068",
                    )

        # ---- N3 operator cmdline shapes ---- #
        # Compile patterns once
        compiled_sigs = []
        for key, sig in (cmdline_sigs or {}).items():
            if not isinstance(sig, dict):
                continue
            pat = sig.get("pattern")
            if not pat:
                continue
            try:
                compiled_sigs.append((
                    key,
                    re.compile(pat, re.I),
                    sig.get("severity") or "high",
                    sig.get("mitre") or "T1068",
                ))
            except re.error:
                continue

        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            cmd = _cmdline_str(d.get("cmdline"))
            if not cmd:
                continue
            for key, rx, sev, mitre in compiled_sigs:
                if not rx.search(cmd):
                    continue
                # Map sig key → exploit family for evidence/title.
                exploit_name = {
                    "beigeburrow_tunnel": "BeigeBurrow",
                    "undef_help_or_aggressive": "UnDefend",
                    "redsun_invocation": "RedSun",
                    "funnyapp_or_snek": "BlueHammer",
                }.get(key, campaign)
                # YellowKey/GreenPlasma/MiniPlasma have no cmdline form
                # in current rules — they're physical/driver primitives.
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=(
                        f"Nightmare-Eclipse {exploit_name} cmdline shape: "
                        f"pid {d.get('pid')} ({d.get('name')})"
                    ),
                    summary=(
                        f"Process pid {d.get('pid')} ({d.get('name')}) "
                        f"command line matches the {exploit_name} "
                        f"operator-cmdline signature ({key}). "
                        f"{common_response}"
                        f"\n\nCmdline: {cmd[:300]}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "cmdline",
                        "campaign": campaign,
                        "exploit": exploit_name,
                        "signature": key,
                        "pid": d.get("pid"),
                        "name": d.get("name"),
                        "cmdline": cmd[:400],
                        "mitigation_commands": (
                            mit_unpatched if exploit_name != "BlueHammer"
                            else mit_patched
                        ),
                        "patch_status": (
                            "patched (CVE-2026-33825)"
                            if exploit_name == "BlueHammer"
                            else "unpatched"
                        ),
                        "references": references,
                    },
                    mitre=mitre,
                )
                break  # one cmdline finding per process is enough

        # ---- N4a C2 callout in process cmdline + connections ---- #
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            cmd = _cmdline_str(d.get("cmdline")).lower()
            # cmdline domain reference
            for dom in c2_domains:
                if dom in cmd:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Nightmare-Eclipse C2 domain in cmdline: "
                            f"{dom} (pid {d.get('pid')})"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} ({d.get('name')}) "
                            f"command line references known Nightmare-"
                            f"Eclipse C2 domain ``{dom}``. "
                            f"{common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "c2",
                            "campaign": campaign,
                            "domain": dom,
                            "pid": d.get("pid"),
                            "cmdline": cmd[:400],
                            "mitigation_commands": mit_unpatched,
                            "references": references,
                        },
                        mitre="T1572",
                    )
                    break
            # connection table — remote_ip / remote_host match
            for conn in d.get("connections") or []:
                if not isinstance(conn, dict):
                    continue
                rip = (conn.get("raddr") or conn.get("remote_ip") or "").strip()
                if rip and rip in c2_ips:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Nightmare-Eclipse source-IP connection: "
                            f"pid {d.get('pid')} → {rip}"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} ({d.get('name')}) "
                            f"holds a connection to ``{rip}``, a known "
                            "Nightmare-Eclipse VPN source IP. "
                            f"{common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "c2",
                            "campaign": campaign,
                            "remote_ip": rip,
                            "pid": d.get("pid"),
                            "mitigation_commands": mit_unpatched,
                            "references": references,
                        },
                        mitre="T1572",
                    )

        # ---- N4b DNS resolution of C2 domain ---- #
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
                    if dom in hay:
                        yield Finding(
                            detector=self.name,
                            severity="critical",
                            title=(
                                f"Nightmare-Eclipse C2 domain resolved: {dom}"
                            ),
                            summary=(
                                f"DNS history records resolution of "
                                f"Nightmare-Eclipse C2 domain ``{dom}``. "
                                f"{common_response}"
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "c2",
                                "campaign": campaign,
                                "domain": dom,
                                "host_observed": hay,
                                "mitigation_commands": mit_unpatched,
                                "references": references,
                            },
                            mitre="T1572",
                        )
                        return  # one DNS finding is enough

        # ---- N4c Defender quarantine names in any artifact ---- #
        for qname in defender_qnames:
            ql = qname.lower()
            for art in store.iter_artifacts():
                # Quick string check on canonical JSON of the artifact.
                # Defender history / event-log collectors put quarantine
                # text into their data dict; we don't want to know the
                # schema of every Windows event log subtype.
                try:
                    import json as _json
                    text = _json.dumps(art.get("data") or {}, default=str).lower()
                except Exception:
                    continue
                if ql in text:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Defender quarantine entry naming Nightmare-"
                            f"Eclipse exploit: {qname}"
                        ),
                        summary=(
                            f"Artifact from collector {art.get('collector')} "
                            f"contains Microsoft Defender quarantine name "
                            f"``{qname}``, which corresponds to a "
                            "Nightmare-Eclipse exploit family. Quarantine "
                            "alone means Defender caught it once — but "
                            "operators can disable Defender via UnDefend "
                            "afterwards. Hunt for follow-on activity."
                            f"\n\n{common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "defender_quarantine",
                            "campaign": campaign,
                            "quarantine_name": qname,
                            "collector": art.get("collector"),
                            "mitigation_commands": mit_patched,
                            "references": references,
                        },
                        mitre="T1068",
                    )
                    # only one finding per quarantine-name globally
                    break

        # ---- BitLocker YellowKey advisory ---- #
        # YellowKey is physical-bypass — there's no live signal we can
        # observe from a software-side scan. But we can advise when the
        # collected BitLocker artifact shows a TPM-only protector,
        # which is the vulnerable configuration.
        for art in store.iter_artifacts():
            d = art.get("data") or {}
            try:
                import json as _json
                text = _json.dumps(d, default=str).lower()
            except Exception:
                continue
            collector_name = (art.get("collector") or "").lower()
            mentions_bitlocker = (
                "bitlocker" in text or "bitlocker" in collector_name
            )
            # YellowKey targets configurations where the only protector
            # is TPM-only (no PIN). "tpmandpin" is the safe variant
            # (TPM combined with a startup PIN).
            mentions_tpm = "tpm" in text
            has_pin_protector = "tpmandpin" in text or '"pin"' in text
            if mentions_bitlocker and mentions_tpm and not has_pin_protector:
                # Soft signal — only fire once per case
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=(
                        "BitLocker TPM-only protector configuration is "
                        "vulnerable to Nightmare-Eclipse YellowKey "
                        "(unpatched physical bypass)"
                    ),
                    summary=(
                        "BitLocker artifact from collector "
                        f"{art.get('collector')} appears to use a "
                        "TPM-sys-only protector with no startup PIN. "
                        "This configuration is bypassable with physical "
                        "device access via YellowKey (Nightmare-Eclipse, "
                        "UNPATCHED). Mitigation: add a startup PIN "
                        "(manage-bde -protectors -add C: -tpmandpin) "
                        "plus a BIOS/UEFI admin password."
                        f"\n\n{common_response}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "yellowkey_config",
                        "campaign": campaign,
                        "exploit": "YellowKey",
                        "collector": art.get("collector"),
                        "mitigation_commands": mit_yellowkey,
                        "patch_status": "unpatched",
                        "references": references,
                    },
                    mitre="T1006",
                )
                break  # only one YellowKey-config finding per case
