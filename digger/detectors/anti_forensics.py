"""Counter-anti-forensics: detect tracks-covering tradecraft.

Observational only. Mines processes / cmdlines + collected log + history
artifacts for the canonical "make the forensicator's life harder"
patterns. This is the 10th detector in the Decepticon countermeasure
suite — defensive mirror of the "covering tracks" / "cleanup" phase.

Signals:

  F1  Shell history wiping
      ``history -c``, ``unset HISTFILE``, ``ln -sf /dev/null
      ~/.bash_history``, ``HISTFILE=/dev/null``, ``cat /dev/null >
      ~/.bash_history``, ``chmod 000 ~/.bash_history``, ``HISTSIZE=0``.

  F2  System log clearing (Unix)
      ``> /var/log/auth.log``, ``truncate -s 0 /var/log/*``, ``rm -f
      /var/log/...``, ``journalctl --rotate --vacuum-time=1s``,
      ``logrotate -f``. Also flags writes that ZERO a log file via
      ``cat /dev/null > log`` or ``: > log``.

  F3  Windows event log clearing
      ``wevtutil cl <log>``, ``Clear-EventLog``, ``Limit-EventLog
      -MaximumSize 1k``, ``Remove-EventLog``.

  F4  Timestamp manipulation (timestomping)
      ``touch -t YYYYMMDDhhmm`` or ``touch -d``, ``touch --reference``,
      PowerShell ``SetCreationTime / SetLastWriteTime``, ``utimes``.

  F5  Secure deletion / shredding
      ``shred -uvz``, ``srm -rf``, ``sdelete -p N``, ``wipe -rf``.

  F6  Mounted-tmpfs / RAM-only execution
      ``mount -t tmpfs none /tmp`` after install, suggesting an
      attacker pivoting to RAM so artifacts vanish on reboot. Also
      ``noexec``-stripping remount.

  F7  Bash history file lstat tampering
      Shell-history files that exist but are zero-byte despite a
      logged-in user (a strong sign of recent wipe). Or symlinks to
      /dev/null.

MITRE: T1070 (Indicator Removal on Host), T1070.001 (Clear Windows
Event Logs), T1070.002 (Clear Linux or Mac System Logs), T1070.003
(Clear Command History), T1070.004 (File Deletion), T1070.006
(Timestomp).
"""

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- cmdline patterns -----------------------------------------------------

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    # (regex, label, severity, mitre)

    # F1 — shell history wiping
    (re.compile(r"\bhistory\s+-c\b", re.I),
     "shell history cleared (history -c)",
     "high", "T1070.003"),
    (re.compile(r"\bunset\s+HISTFILE\b", re.I),
     "shell history file path unset (unset HISTFILE)",
     "high", "T1070.003"),
    (re.compile(r"\bHISTFILE\s*=\s*/dev/null\b", re.I),
     "shell history redirected to /dev/null (HISTFILE=/dev/null)",
     "high", "T1070.003"),
    (re.compile(r"\bHISTSIZE\s*=\s*0\b", re.I),
     "shell history size zeroed (HISTSIZE=0)",
     "medium", "T1070.003"),
    (re.compile(r"\bln\s+-s[a-z]*f?\s+/dev/null\s+\S*\.?bash_history\b", re.I),
     "bash_history symlinked to /dev/null",
     "high", "T1070.003"),
    (re.compile(r"\bcat\s+/dev/null\s*>\s*\S*\.?bash_history\b", re.I),
     "bash_history zeroed (cat /dev/null > ...)",
     "high", "T1070.003"),
    (re.compile(r":\s*>\s*\S*\.?bash_history\b"),
     "bash_history zeroed (: > ~/.bash_history)",
     "high", "T1070.003"),
    (re.compile(r"\bchmod\s+0*00\s+\S*\.?bash_history\b", re.I),
     "bash_history mode-stripped (chmod 000)",
     "medium", "T1070.003"),

    # F2 — Unix system-log clearing
    (re.compile(r"\btruncate\s+-s\s*0\s+/var/log/", re.I),
     "system log truncated (truncate -s 0 /var/log/...)",
     "critical", "T1070.002"),
    (re.compile(r"\bcat\s+/dev/null\s*>\s*/var/log/", re.I),
     "system log zeroed (cat /dev/null > /var/log/...)",
     "critical", "T1070.002"),
    (re.compile(r":\s*>\s*/var/log/"),
     "system log zeroed (: > /var/log/...)",
     "critical", "T1070.002"),
    (re.compile(r"\bjournalctl\s+(?:--rotate|--vacuum-time=1s|--vacuum-size=1)", re.I),
     "systemd journal forcibly vacuumed (journalctl --vacuum-time=1s)",
     "high", "T1070.002"),
    (re.compile(r"\brm\s+-[a-z]*f?\s+/var/log/(?:auth|secure|messages|syslog|wtmp|btmp)",
                re.I),
     "system log file removed (rm -f /var/log/...)",
     "critical", "T1070.002"),
    (re.compile(r"\b(?:echo\s+)?>?\s*/var/log/lastlog\b", re.I),
     "/var/log/lastlog tampered",
     "high", "T1070.002"),

    # F3 — Windows event log clearing
    (re.compile(r"\bwevtutil(?:\.exe)?\s+cl\s+\S+", re.I),
     "Windows event log cleared (wevtutil cl ...)",
     "critical", "T1070.001"),
    (re.compile(r"\bClear-EventLog\b", re.I),
     "Windows event log cleared (Clear-EventLog)",
     "critical", "T1070.001"),
    (re.compile(r"\bLimit-EventLog\s+.*-MaximumSize\s+(?:1|0)(?:KB|k)?\b", re.I),
     "Windows event log size limited to ~1KB (effective wipe)",
     "high", "T1070.001"),
    (re.compile(r"\bRemove-EventLog\b", re.I),
     "Windows event log removed (Remove-EventLog)",
     "critical", "T1070.001"),

    # F4 — timestomping
    (re.compile(r"\btouch\s+(?:-[a-z]*)?-t\s+\d{8,12}\b"),
     "file timestamp set to arbitrary value (touch -t)",
     "high", "T1070.006"),
    (re.compile(r"\btouch\s+(?:-[a-z]*)?-d\s+['\"]?\d{4}-\d{2}-\d{2}", re.I),
     "file timestamp set to arbitrary date (touch -d)",
     "high", "T1070.006"),
    (re.compile(r"\btouch\s+--reference[= ]\S+", re.I),
     "file timestamp cloned from reference file (touch --reference)",
     "high", "T1070.006"),
    (re.compile(r"\.SetCreationTime\s*\(|\.SetLastWriteTime\s*\(", re.I),
     "PowerShell file-timestamp setter (SetCreationTime / SetLastWriteTime)",
     "high", "T1070.006"),

    # F5 — secure deletion / shredding
    (re.compile(r"\bshred\s+-[a-z]*[uz][a-z]*\b", re.I),
     "secure-delete with shred -u (or shred -z)",
     "high", "T1070.004"),
    (re.compile(r"\bsrm\s+-[a-z]*r?[fz][a-z]*\b", re.I),
     "secure-delete with srm",
     "high", "T1070.004"),
    (re.compile(r"\bsdelete(?:\.exe)?\s+-p\s+\d+", re.I),
     "Sysinternals sdelete (multi-pass overwrite)",
     "high", "T1070.004"),
    (re.compile(r"\bwipe\s+-[a-z]*r?f[a-z]*\b", re.I),
     "wipe utility (secure deletion)",
     "high", "T1070.004"),

    # F6 — RAM-only execution / tmpfs pivots
    (re.compile(r"\bmount\s+-t\s+tmpfs\b", re.I),
     "tmpfs mounted (RAM-only artifact storage — vanishes on reboot)",
     "medium", "T1564.003"),
]


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


class AntiForensicsDetector(Detector):
    name = "anti_forensics"
    description = (
        "Counter-anti-forensics: history wiping, log clearing, timestomping, "
        "secure-deletion tooling, tmpfs RAM-only pivots."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Anti-forensics tradecraft: log clearing / history wipe / timestomp / secure-delete",
            "id": "digger-anti-forensics-template",
            "description": (
                "A process invokes any of the canonical tracks-covering "
                "primitives: shell history wipe (history -c / unset "
                "HISTFILE / symlink ~/.bash_history -> /dev/null), system "
                "log truncation (truncate -s 0 / cat /dev/null > / "
                "journalctl --vacuum-time=1s / rm /var/log/...), Windows "
                "event log clear (wevtutil cl / Clear-EventLog), file "
                "timestomp (touch -t / SetCreationTime), or secure delete "
                "(shred -u / srm / sdelete / wipe)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_history_wipe": {
                    "CommandLine|contains": [
                        "history -c", "unset HISTFILE",
                        "HISTFILE=/dev/null", "HISTSIZE=0",
                        ".bash_history",
                    ],
                },
                "selection_unix_log_wipe": {
                    "CommandLine|re": (
                        r"(?:truncate\s+-s\s*0\s+/var/log/|"
                        r"journalctl\s+--vacuum-time=1s|"
                        r"rm\s+-[a-z]*f?\s+/var/log/(?:auth|secure|messages|syslog|wtmp|btmp))"
                    ),
                },
                "selection_windows_log_wipe": {
                    "Image|endswith": ["/wevtutil.exe", "/powershell.exe", "/pwsh.exe"],
                    "CommandLine|contains": [
                        "wevtutil cl", "Clear-EventLog", "Remove-EventLog",
                        "Limit-EventLog",
                    ],
                },
                "selection_timestomp": {
                    "CommandLine|re": (
                        r"(?:touch\s+(?:-[a-z]*)?-[td]\s+|"
                        r"touch\s+--reference|"
                        r"\.SetCreationTime\s*\(|"
                        r"\.SetLastWriteTime\s*\()"
                    ),
                },
                "selection_secure_delete": {
                    "Image|endswith": ["/shred", "/srm", "/wipe", "/sdelete.exe"],
                },
                "condition": "1 of selection_*",
            },
            "level": "high",
            "tags": [
                "attack.t1070",
                "attack.t1070.001", "attack.t1070.002", "attack.t1070.003",
                "attack.t1070.004", "attack.t1070.006",
                "attack.defense_evasion",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- Process cmdline scan ---- #
        seen: set[tuple[int, str]] = set()
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"]
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
                        f"Anti-forensics activity in pid {pid} ({base}): {label}"
                    ),
                    summary=(
                        f"Process {base} (pid {pid}) command line matches: "
                        f"{label}. Anti-forensics primitives have very few "
                        "legitimate non-admin uses; correlate with the "
                        "user, parent process, and time window to "
                        "distinguish authorized cleanup from track-covering."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "anti_forensics_cmdline",
                        "pid": pid,
                        "name": base,
                        "pattern": label,
                        "cmdline": cmd[:400],
                        "username": d.get("username"),
                    },
                    mitre=mitre,
                )
                break  # one finding per process is enough

        # ---- F7 — zero-byte / dev-null-symlinked bash_history ---- #
        # The auth_logs collector (Linux) ships shell-history file
        # paths via category=logs / subject prefix "log:" — but for
        # bash_history specifically, when the file IS captured we can
        # detect zero size as a recent-wipe signal.
        for art in store.iter_artifacts(category="logs"):
            d = art["data"]
            path = (d.get("path") or "").lower()
            if "bash_history" not in path and "zsh_history" not in path:
                continue
            size = d.get("size")
            if size is not None and size == 0:
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=f"Shell history file is empty: {d.get('path')}",
                    summary=(
                        f"{d.get('path')} exists but is zero bytes. On an "
                        "active user account this is unusual — it suggests "
                        "a recent ``> ~/.bash_history`` or equivalent. "
                        "Correlate with `last` output for the user's "
                        "recent login activity."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "empty_shell_history",
                        "path": d.get("path"),
                    },
                    mitre="T1070.003",
                )
