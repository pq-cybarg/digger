"""Counter-Impact: detect destruction / ransomware / recovery-disabling.

Observational. The 12th and final detector in the Decepticon
countermeasure suite — defensive mirror of the Impact phase.

After Reconnaissance → Initial Access → Execution → Persistence →
Privilege Escalation → Defense Evasion → Credential Access →
Discovery → Lateral Movement → Collection → C2 → Exfiltration, the
final attacker action is *Impact* — making the host or the data
unrecoverable. Catching this in the act is the difference between
recoverable and unrecoverable.

Signals:

  I1  Ransomware mass-encrypt pattern (T1486)
      Per-process command lines matching mass-rename / encrypt
      shapes: ``find ... -exec openssl enc``, GnuPG batch on
      directory trees, 7z with password-encryption + recursion,
      Python cryptography one-liners over a directory, PowerShell
      AES streams writing back to source.

  I2  Ransom-note filenames (T1486)
      Files named ``HOW_TO_DECRYPT.txt`` / ``READ_ME_FOR_DECRYPT`` /
      ``DECRYPT_INSTRUCTIONS`` / ``YOUR_FILES_ARE_ENCRYPTED`` /
      ``HOW_TO_RECOVER`` / known family ransom-notes
      (``!!!READ_ME_!!``, ``HELP_DECRYPT``, ``info.hta``) in any
      recent-files / persistence artifact.

  I3  Shadow-copy / system-restore deletion (T1490)
      ``vssadmin delete shadows``, ``wmic shadowcopy delete``,
      ``Get-WmiObject Win32_ShadowCopy | Remove-WmiObject``,
      ``bcdedit /set {default} recoveryenabled No``,
      ``bcdedit /set {default} bootstatuspolicy ignoreallfailures``,
      ``wbadmin delete catalog``, ``Disable-ComputerRestore``,
      ``Reset-ComputerMachinePassword`` chained to recovery
      disablement.

  I4  Security-service stop (T1489)
      ``systemctl stop`` / ``service stop`` / ``net stop`` /
      ``sc stop`` / PowerShell ``Stop-Service`` / launchctl unload
      targeting AV / EDR / firewall services (defender, falcon,
      crwd, sentinelone, esets, sophos, mcafee, kaspersky,
      eppman, AmsiScanBuffer-disabling commands, ``Set-MpPreference
      -DisableRealtimeMonitoring $true``).

  I5  Disk wipe (T1561)
      ``dd if=/dev/zero of=/dev/sd``, ``shred /dev/sd``,
      ``wipefs -af /dev/``, ``mkfs.ext4 -F /dev/sda``,
      ``parted /dev/sd*  mklabel gpt`` against a whole device,
      ``cipher /w:C:\\`` (Windows secure-erase free space),
      ``format C: /q /y``, ``diskpart /s ...`` chained with
      ``clean``.

  I6  System shutdown / forced reboot during incident (T1529)
      ``shutdown -h now`` / ``shutdown /s /t 0`` / ``halt`` /
      ``poweroff`` / ``init 0`` / PowerShell ``Stop-Computer
      -Force`` / ``Restart-Computer -Force`` issued by a non-init
      user is a destructive Impact action.

  I7  Cloud resource destruction (T1485)
      ``aws ec2 terminate-instances`` (any count, especially
      ``--instance-ids`` covering many), ``aws s3 rb --force`` on
      buckets, ``aws rds delete-db-instance --skip-final-snapshot``,
      ``gcloud compute instances delete --quiet``, ``az vm delete
      --yes``, ``kubectl delete --all``, ``terraform destroy
      -auto-approve`` from non-CI users.

  I8  Mass extension change in recent files
      A statistical signal: if the recent_files collector observed
      ≥50 files in a single subtree all sharing a single uncommon
      extension (``.encrypted`` / ``.locked`` / ``.crypt`` /
      ``.crypted`` / ``.crypted!`` / ``.WCRY`` / ``.crypz`` /
      ``.lokd`` etc.), that is the textbook in-progress-ransomware
      footprint.

MITRE: T1485 (Data Destruction), T1486 (Data Encrypted for Impact),
T1489 (Service Stop), T1490 (Inhibit System Recovery), T1529 (System
Shutdown/Reboot), T1561 (Disk Wipe).
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- cmdline patterns ----------------------------------------------------- #

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    # (regex, label, severity, mitre)

    # I1 — ransomware encrypt shape
    (re.compile(r"\bfind\s+\S+[^|]*-exec\s+openssl\s+enc\b", re.I),
     "find ... -exec openssl enc (mass-encrypt shape)",
     "critical", "T1486"),
    (re.compile(r"\bgpg\b[^|]*--batch[^|]*--encrypt\b[^|]*--recursive\b", re.I),
     "gpg --batch --encrypt --recursive (mass-encrypt shape)",
     "critical", "T1486"),
    (re.compile(r"\b7z(?:a|z)?\s+a\s+-p\S+\s+-mhe=on\b[^|]*-r\b", re.I),
     "7z password-encrypted recursive archive (ransomware staging)",
     "high", "T1486"),
    (re.compile(r"\bopenssl\s+enc\s+-aes-?\d+(?:-cbc|-gcm)?\b[^|]*-in\s+\S+\s+-out\s+\S+",
                re.I),
     "openssl enc -aes-* -in/-out single-file encrypt",
     "high", "T1486"),
    (re.compile(r"\bcipher\b\s+/[ew]:\S+", re.I),
     "Windows cipher /e or /w (encrypt / wipe free space)",
     "high", "T1486"),

    # I3 — inhibit system recovery
    (re.compile(r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b", re.I),
     "vssadmin delete shadows (VSS deletion)",
     "critical", "T1490"),
    (re.compile(r"\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b", re.I),
     "wmic shadowcopy delete",
     "critical", "T1490"),
    (re.compile(r"\bGet-WmiObject\s+Win32_ShadowCopy\b[^|]*Remove-WmiObject", re.I),
     "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject",
     "critical", "T1490"),
    (re.compile(r"\bbcdedit(?:\.exe)?\s+/set\s+\{?default\}?\s+recoveryenabled\s+(?:no|0)\b",
                re.I),
     "bcdedit recoveryenabled No",
     "critical", "T1490"),
    (re.compile(r"\bbcdedit(?:\.exe)?\s+/set\s+\{?default\}?\s+bootstatuspolicy\s+ignoreallfailures\b",
                re.I),
     "bcdedit bootstatuspolicy ignoreallfailures",
     "high", "T1490"),
    (re.compile(r"\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|backup|systemstatebackup)\b",
                re.I),
     "wbadmin delete catalog/backup",
     "critical", "T1490"),
    (re.compile(r"\bDisable-ComputerRestore\b", re.I),
     "PowerShell Disable-ComputerRestore",
     "high", "T1490"),

    # I4 — security-service stop / EDR-tamper
    (re.compile(
        r"\b(?:systemctl|service)\s+(?:stop|disable|mask)\s+"
        r"(?:falcon-sensor|crowdstrike|sentinelone|esets?|sophos|mcafee|"
        r"clamav|carbonblack|cylancesvc|defender|wdavdaemon|"
        r"esets_daemon|symantec|kaspersky)",
        re.I),
     "systemctl stop/disable security service",
     "critical", "T1489"),
    (re.compile(
        r"\b(?:net|sc)(?:\.exe)?\s+stop\s+"
        r"(?:windefend|wuauserv|wscsvc|sense|mpssvc|csagent|csfalconsvc|"
        r"sentinelagent|trendmicro|symantec|mcafee|sophos|kaspersky|"
        r"cyvera|cylancesvc|sysmon|sysmon64)",
        re.I),
     "Windows net/sc stop on security service",
     "critical", "T1489"),
    (re.compile(r"\bStop-Service\s+(?:-Name\s+)?['\"]?"
                r"(?:WinDefend|Sense|MpsSvc|wuauserv|csagent|CSFalconSvc|"
                r"SentinelAgent|TmCCSF|TrendMicroSso|Sysmon|Sysmon64)",
                re.I),
     "PowerShell Stop-Service on security service",
     "critical", "T1489"),
    (re.compile(r"\bSet-MpPreference\b[^|]*-DisableRealtimeMonitoring\s+\$?(?:true|1)\b",
                re.I),
     "Set-MpPreference -DisableRealtimeMonitoring (Defender off)",
     "critical", "T1562.001"),
    (re.compile(r"\bSet-MpPreference\b[^|]*-DisableScriptScanning\s+\$?(?:true|1)\b",
                re.I),
     "Set-MpPreference -DisableScriptScanning",
     "high", "T1562.001"),
    (re.compile(r"\bAdd-MpPreference\b[^|]*-ExclusionPath\s+", re.I),
     "Add-MpPreference -ExclusionPath (Defender allow-list bypass)",
     "high", "T1562.001"),
    (re.compile(r"\blaunchctl\s+(?:unload|disable)\s+\S*"
                r"(?:Falcon|CrowdStrike|SentinelOne|Carbon|"
                r"Sophos|Symantec|McAfee|Kaspersky|com\.malwarebytes)",
                re.I),
     "launchctl unload/disable on macOS security agent",
     "critical", "T1489"),

    # I5 — disk wipe
    (re.compile(r"\bdd\s+if=/dev/(?:zero|urandom|random)\s+of=/dev/(?:sd[a-z]|nvme|xvd[a-z]|hd[a-z])",
                re.I),
     "dd if=/dev/zero of=/dev/sdX (whole-disk wipe)",
     "critical", "T1561"),
    (re.compile(r"\bshred\b[^|]*\s/dev/(?:sd[a-z]|nvme|xvd[a-z]|hd[a-z])",
                re.I),
     "shred /dev/sdX",
     "critical", "T1561"),
    (re.compile(r"\bwipefs\s+-a\S*\s+/dev/", re.I),
     "wipefs -af /dev/...",
     "critical", "T1561"),
    (re.compile(r"\bmkfs\.\S+\s+-F\s+/dev/(?:sd[a-z]|nvme|xvd[a-z]|hd[a-z])", re.I),
     "mkfs -F /dev/sdX (forced reformat)",
     "critical", "T1561"),
    (re.compile(r"\bparted\s+/dev/(?:sd[a-z]|nvme|xvd[a-z])[^|]*\bmklabel\s+\S+", re.I),
     "parted mklabel on whole device",
     "high", "T1561"),
    (re.compile(r"\bdiskpart\b[^|]*\bclean\b", re.I),
     "diskpart clean (partition-table wipe)",
     "critical", "T1561"),
    (re.compile(r"\bformat\s+[A-Z]:\s+/q\s+/y\b", re.I),
     "Windows format C: /q /y",
     "critical", "T1561"),

    # I6 — system shutdown / reboot
    (re.compile(r"\bshutdown\s+(?:-h\s+now|-r\s+now|/s\s+/t\s*0|/r\s+/t\s*0|-P\s+now)",
                re.I),
     "shutdown immediate",
     "high", "T1529"),
    (re.compile(r"\b(?:halt|poweroff|init\s+0|init\s+6)\b", re.I),
     "halt / poweroff / init 0|6",
     "medium", "T1529"),
    (re.compile(r"\bStop-Computer\s+(?:-Force|-ComputerName)", re.I),
     "PowerShell Stop-Computer -Force",
     "high", "T1529"),
    (re.compile(r"\bRestart-Computer\s+-Force\b", re.I),
     "PowerShell Restart-Computer -Force",
     "medium", "T1529"),

    # I7 — cloud resource destruction
    (re.compile(r"\baws\s+ec2\s+terminate-instances\b", re.I),
     "aws ec2 terminate-instances",
     "high", "T1485"),
    (re.compile(r"\baws\s+s3\s+rb\s+\S+\s+--force\b", re.I),
     "aws s3 rb --force (bucket destruction)",
     "critical", "T1485"),
    (re.compile(r"\baws\s+rds\s+delete-db-instance\b[^|]*--skip-final-snapshot",
                re.I),
     "aws rds delete-db-instance --skip-final-snapshot",
     "critical", "T1485"),
    (re.compile(r"\baws\s+cloudtrail\s+(?:delete-trail|stop-logging|put-event-selectors)",
                re.I),
     "aws cloudtrail delete-trail / stop-logging",
     "critical", "T1562.008"),
    (re.compile(r"\bgcloud\s+compute\s+instances\s+delete\s+\S+\s+--quiet\b", re.I),
     "gcloud compute instances delete --quiet",
     "high", "T1485"),
    (re.compile(r"\baz\s+vm\s+delete\s+[^|]*--yes\b", re.I),
     "az vm delete --yes",
     "high", "T1485"),
    (re.compile(r"\bkubectl\s+delete\s+(?:--all|-A)\b", re.I),
     "kubectl delete --all/-A",
     "high", "T1485"),
    (re.compile(r"\bterraform\s+destroy\s+-auto-approve\b", re.I),
     "terraform destroy -auto-approve",
     "high", "T1485"),
    (re.compile(r"\bdocker\s+volume\s+(?:rm|prune)\s+(?:-f|--force)", re.I),
     "docker volume rm -f / prune --force",
     "medium", "T1485"),
]

# ---- Ransom-note filename hints ----------------------------------------- #

_RANSOM_NOTE_FILENAMES = {
    # Generic
    "how_to_decrypt.txt", "how_to_decrypt.html", "how_to_decrypt.hta",
    "how_to_recover.txt", "how_to_recover_files.txt",
    "read_me.txt", "read_me_for_decrypt.txt",
    "decrypt_instructions.txt", "decrypt_instructions.html",
    "your_files_are_encrypted.txt", "your_files_are_encrypted.html",
    "all_your_files_encrypted.txt",
    # Known families
    "_readme.txt",                       # STOP/Djvu
    "!!!read_me_!!.txt",                 # GandCrab / variants
    "info.hta",                          # Ryuk / Conti
    "ryukreadme.txt", "ryukreadme.html",
    "contireadme.txt", "readme_to_decrypt.txt",
    "_decrypt_my_files.txt",             # Locky family
    "help_decrypt.txt", "help_decrypt.html",
    "restore_files.txt",                 # CryptoWall
    "decryptmyfiles.txt",
    "lockbit-decryptor.txt",
    "akira_readme.txt",
    "alpha_readme.txt",
    "play_readme.txt",
    "rhysida.pdf",                       # Rhysida drops a PDF note
}

# Extensions that mass-rename ransomware uses. Conservative set —
# common-but-legit ones like `.bak` excluded.
_RANSOM_EXTENSIONS = {
    ".encrypted", ".locked", ".lock", ".crypt", ".crypted", ".crypted!",
    ".wcry", ".wncry", ".wncryt", ".crypz", ".cryp1", ".enc",
    ".lokd", ".clop", ".rhysida", ".djvu", ".akira", ".play",
    ".ryk", ".ryuk", ".conti", ".lockbit", ".lcrypt", ".kraken",
    ".rhk", ".babyk", ".cuba", ".pysa",
}

_MASS_RENAME_MIN_COUNT = 50


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


def _extension(path: str) -> str:
    """Return the last dotted suffix of a basename, lowercased, with the
    leading dot included. Returns '' for no extension."""
    name = _basename(path)
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[1].lower()


class ImpactDetector(Detector):
    name = "impact"
    description = (
        "Counter-impact: ransomware encrypt-shape commands, ransom-note "
        "filenames, mass-rename to ransomware extensions, shadow-copy "
        "deletion, security-service stop / EDR-tamper, disk wipe, "
        "system shutdown, cloud-resource destruction."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Impact tradecraft: ransomware / VSS-delete / EDR-stop / wipe / cloud-destroy",
            "id": "digger-impact-template",
            "description": (
                "A process invokes any of the canonical Impact-phase "
                "primitives: mass-encrypt (find -exec openssl, gpg "
                "--batch --encrypt --recursive, 7z -p -mhe -r), shadow-"
                "copy / system-restore deletion (vssadmin delete shadows, "
                "wmic shadowcopy delete, bcdedit recoveryenabled No, "
                "wbadmin delete catalog), security-service stop "
                "(systemctl stop falcon-sensor/sentinelone/etc.; net "
                "stop windefend; Set-MpPreference -DisableRealtimeMon "
                "$true), disk wipe (dd if=/dev/zero of=/dev/sdX, shred "
                "/dev/sdX, wipefs -af, diskpart clean, format C: /q), "
                "destructive shutdown (shutdown -h now, Stop-Computer "
                "-Force), or cloud destruction (aws ec2 terminate-"
                "instances, aws s3 rb --force, aws rds delete-db-"
                "instance --skip-final-snapshot, gcloud compute "
                "instances delete --quiet, kubectl delete --all, "
                "terraform destroy -auto-approve)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_ransomware_encrypt": {
                    "CommandLine|re": (
                        r"(?:find\s+\S+[^|]*-exec\s+openssl\s+enc|"
                        r"gpg[^|]*--batch[^|]*--encrypt[^|]*--recursive|"
                        r"7z[az]?\s+a\s+-p\S+\s+-mhe=on[^|]*-r|"
                        r"cipher\s+/[ew]:)"
                    ),
                },
                "selection_inhibit_recovery": {
                    "CommandLine|contains": [
                        "vssadmin delete shadows",
                        "wmic shadowcopy delete",
                        "bcdedit /set {default} recoveryenabled No",
                        "bcdedit /set {default} bootstatuspolicy",
                        "wbadmin delete catalog",
                        "Disable-ComputerRestore",
                    ],
                },
                "selection_security_service_stop": {
                    "CommandLine|re": (
                        r"(?:systemctl|service)\s+(?:stop|disable|mask)\s+"
                        r"(?:falcon-sensor|crowdstrike|sentinelone|sophos|"
                        r"mcafee|defender|wdavdaemon|symantec|kaspersky)|"
                        r"(?:net|sc)\s+stop\s+(?:windefend|sense|mpssvc|"
                        r"csagent|csfalconsvc|sentinelagent|sysmon)|"
                        r"Stop-Service\s+['\"]?(?:WinDefend|Sense|MpsSvc|"
                        r"CSFalconSvc|SentinelAgent|Sysmon)|"
                        r"Set-MpPreference[^|]*-DisableRealtimeMonitoring\s+\$?(?:true|1)"
                    ),
                },
                "selection_disk_wipe": {
                    "Image|endswith": ["/dd", "/shred", "/wipefs",
                                         "/mkfs.ext4", "/mkfs.xfs",
                                         "/parted", "/diskpart.exe"],
                    "CommandLine|contains": [
                        "of=/dev/sd", "of=/dev/nvme",
                        "/dev/sda", "/dev/nvme",
                        "format C:", "diskpart", "clean",
                    ],
                },
                "selection_shutdown": {
                    "CommandLine|re": (
                        r"(?:shutdown\s+(?:-h\s+now|-r\s+now|/s\s+/t\s*0|/r\s+/t\s*0)|"
                        r"(?:halt|poweroff|init\s+0|init\s+6)\b|"
                        r"Stop-Computer\s+-Force|"
                        r"Restart-Computer\s+-Force)"
                    ),
                },
                "selection_cloud_destruction": {
                    "CommandLine|re": (
                        r"(?:aws\s+ec2\s+terminate-instances|"
                        r"aws\s+s3\s+rb\s+\S+\s+--force|"
                        r"aws\s+rds\s+delete-db-instance[^|]*--skip-final-snapshot|"
                        r"gcloud\s+compute\s+instances\s+delete\s+\S+\s+--quiet|"
                        r"az\s+vm\s+delete[^|]*--yes|"
                        r"kubectl\s+delete\s+(?:--all|-A)|"
                        r"terraform\s+destroy\s+-auto-approve)"
                    ),
                },
                "condition": "1 of selection_*",
            },
            "level": "critical",
            "tags": [
                "attack.t1485",
                "attack.t1486",
                "attack.t1489",
                "attack.t1490",
                "attack.t1529",
                "attack.t1561",
                "attack.t1562.001",
                "attack.impact",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- I1/I3/I4/I5/I6/I7 — cmdline-driven primitives ---- #
        seen: set[tuple[int, str]] = set()
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            pid = d.get("pid")
            name = (d.get("name") or "").lower()
            base = (_basename(d.get("exe") or "") or name).lower()
            cmd = _cmdline_str(d.get("cmdline"))
            if not cmd:
                continue
            for rx, label, sev, mitre in _PATTERNS:
                if not rx.search(cmd):
                    continue
                key = (pid, label)
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=(
                        f"Impact-phase activity in pid {pid} ({base}): "
                        f"{label}"
                    ),
                    summary=(
                        f"Process {base} (pid {pid}, user "
                        f"{d.get('username')}) command line matches: "
                        f"{label}. Impact-phase primitives have very "
                        "few legitimate non-admin uses; correlate with "
                        "the user, parent, and time window to "
                        "distinguish authorized maintenance from "
                        "destructive activity. If this is in-progress "
                        "ransomware, every minute counts — disconnect "
                        "the host from the network and preserve a "
                        f"memory image.\n\nCmdline: {cmd[:300]}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "impact_cmdline",
                        "pid": pid,
                        "name": base,
                        "pattern": label,
                        "username": d.get("username"),
                        "cmdline": cmd[:400],
                    },
                    mitre=mitre,
                )
                break  # one finding per process is enough

        # ---- I2 — ransom-note filename in recent files ---- #
        for art in store.iter_artifacts(collector="recent_files"):
            d = art["data"] or {}
            entries = d.get("entries") or ([d] if d.get("path") else [])
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path") or ""
                if not path:
                    continue
                base = _basename(path).lower()
                if base in _RANSOM_NOTE_FILENAMES:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"Ransom-note filename present: {path}",
                        summary=(
                            f"File ``{path}`` matches a known ransomware "
                            "ransom-note filename. The host has likely "
                            "been encrypted by ransomware. Preserve "
                            "evidence (do not pay), isolate the host, "
                            "and check for shadow-copy deletion (a "
                            "separate critical finding will fire if "
                            "present)."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "ransom_note_file",
                            "path": path,
                            "basename": base,
                        },
                        mitre="T1486",
                    )

        # ---- I8 — mass-extension change footprint in recent files ---- #
        # Count files-per-extension within each recent_files artifact.
        # We trigger when ≥ _MASS_RENAME_MIN_COUNT files share a single
        # known-ransomware extension. This is statistical, not a single
        # cmdline match — different signal class.
        for art in store.iter_artifacts(collector="recent_files"):
            d = art["data"] or {}
            entries = d.get("entries") or []
            if not entries:
                continue
            counts = Counter()
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path") or ""
                if not path:
                    continue
                ext = _extension(path)
                if ext in _RANSOM_EXTENSIONS:
                    counts[ext] += 1
            for ext, count in counts.items():
                if count < _MASS_RENAME_MIN_COUNT:
                    continue
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=(
                        f"Mass-rename to ransomware extension: {count} "
                        f"files with {ext} under {d.get('location')}"
                    ),
                    summary=(
                        f"The recent-files collector observed {count} "
                        f"files with the ``{ext}`` extension under "
                        f"``{d.get('location')}``. ``{ext}`` is a "
                        "known ransomware mass-rename suffix. The host "
                        "is likely actively encrypted by ransomware. "
                        "Disconnect from the network and preserve a "
                        "memory image before further action."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "mass_rename",
                        "extension": ext,
                        "count": count,
                        "location": d.get("location"),
                    },
                    mitre="T1486",
                )
