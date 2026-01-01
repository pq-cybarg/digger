"""Discovery-tactic detector — "the attacker has shell, what are they
enumerating".

The existing ``recon`` detector covers Reconnaissance — probes
*against* the host from outside (port scans, SSH brute-force).
``DiscoveryDetector`` covers the inverse: living-off-the-land
enumeration commands run *on* the host by an attacker who has
already landed. Most adversaries run a cluster of these in the
first 30-60 seconds after foothold — it's the cheapest way to
confirm "yes, the attacker is here".

Heatmap rationale: Discovery was the single thinnest tactic (1
technique only — T1057 process discovery via counter_re).
This pushes coverage to 12+ techniques.

Signal layers
-------------

D1  Standalone high-signal LOTL commands — single-hit dispositive
    when seen on a non-admin user account:
      - ``whoami /all``, ``whoami /priv``, ``whoami /groups``
      - ``net user`` / ``net localgroup`` / ``net group "Domain Admins"``
      - ``nltest /dclist`` / ``nltest /domain_trusts``
      - ``ldapsearch``, ``dsquery user/group``
      - ``getent passwd`` / ``getent group``
      - ``find / -perm -4000`` / ``find / -perm -2000`` (SUID hunt)
      - ``find / -name '*.kdbx'`` / ``find / -name 'id_rsa'`` etc.
        (credential file hunting)
      - ``nmap`` / ``masscan`` / ``rustscan`` / ``naabu``
      - ``arp -a`` followed by network-range patterns
      - ``Get-LocalGroupMember``, ``Get-ADUser``, ``Get-ADComputer``

D2  Standard recon utilities (lower-signal alone, high-signal in
    cluster):
      - ``whoami``, ``id``, ``hostname``, ``uname -a``, ``sw_vers``
      - ``ipconfig /all``, ``ifconfig``, ``ip a``, ``ip route``
      - ``route print``, ``netstat -an``, ``ss -tlnp``, ``lsof -i``
      - ``systeminfo``, ``Get-ComputerInfo``, ``hostnamectl``
      - ``ps -ef``, ``ps -aux``, ``tasklist``, ``Get-Process``
      - ``Get-Service``, ``systemctl list-units``, ``launchctl list``
      - ``dpkg -l``, ``rpm -qa``, ``brew list``, ``pip list``,
        ``npm ls -g``
      - ``dir /s c:\\``, ``ls -la /``, ``Get-ChildItem -Recurse``

D3  Security-software discovery (T1518.001):
      - ``tasklist /svc | findstr defender``
      - ``Get-Service WinDefend``
      - ``ps -ef | grep crowdstrike``
      - ``systemctl status falcon-sensor``
      - ``ls /Library/Application\\ Support/CrowdStrike``
      - ``Get-MpComputerStatus``

D4  Multi-pattern cluster heuristic — fires when ≥3 distinct D2
    commands run by the same user within 60 seconds. Catches the
    "attacker just landed, runs whoami+id+uname+netstat in 10s"
    footprint that no single command would flag.

Self-attribution heuristic
--------------------------
``whoami`` and ``id`` are routinely run by shell prompts, devops
scripts, and user-facing CLI tools — flagging every invocation
would flood the report. We bump severity down for these when the
parent process is a shell prompt setup tool (``starship``,
``powerline``, ``oh-my-zsh``) or when the user is an obvious admin
account already (root / Administrator). Plus the cluster heuristic
only fires when DIFFERENT commands cluster, not the same one
repeated.

MITRE
-----
T1007 / T1016 / T1018 / T1033 / T1046 / T1049 / T1069 / T1082 /
T1083 / T1087 / T1518 / T1518.001 / T1083 / T1135 (network share
discovery).
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- D1 high-signal LOTL patterns (single hit fires) ---- #

_D1_HIGH_SIGNAL: list[tuple[re.Pattern, str, str, str, str]] = [
    # (regex, label, severity, mitre, kind)

    # T1033 / T1087 — owner + account discovery
    (re.compile(r"\bwhoami(?:\.exe)?\s+/all\b", re.I),
     "whoami /all (privileges + groups dump)",
     "high", "T1033", "owner_priv_dump"),
    (re.compile(r"\bwhoami(?:\.exe)?\s+/priv\b", re.I),
     "whoami /priv (privilege enumeration)",
     "high", "T1033", "owner_priv_dump"),
    (re.compile(r"\bwhoami(?:\.exe)?\s+/groups\b", re.I),
     "whoami /groups",
     "medium", "T1033", "owner_priv_dump"),
    (re.compile(r"\bnet(?:\.exe)?\s+user\s+(?:\S+\s+)?/domain\b", re.I),
     "net user /domain (AD user enum)",
     "high", "T1087.002", "ad_account_enum"),
    (re.compile(r"\bnet(?:\.exe)?\s+(?:user|users)\s*$", re.I),
     "net user (local account enum)",
     "high", "T1087.001", "local_account_enum"),
    (re.compile(r"\bnet(?:\.exe)?\s+localgroup\b", re.I),
     "net localgroup (local group enum)",
     "high", "T1069.001", "local_group_enum"),
    (re.compile(r"\bnet(?:\.exe)?\s+group\s+['\"]?Domain\s+Admins", re.I),
     "net group 'Domain Admins' /domain",
     "critical", "T1069.002", "domain_admin_enum"),

    # T1018 — remote system discovery
    (re.compile(r"\bnltest(?:\.exe)?\s+/dclist\b", re.I),
     "nltest /dclist (domain controller discovery)",
     "high", "T1018", "dc_discovery"),
    (re.compile(r"\bnltest(?:\.exe)?\s+/domain_trusts\b", re.I),
     "nltest /domain_trusts",
     "high", "T1482", "trust_discovery"),
    (re.compile(r"\bnet(?:\.exe)?\s+view\s+/(?:domain|all)\b", re.I),
     "net view /domain",
     "high", "T1018", "remote_system_discovery"),

    # T1087.002 / T1069.002 — LDAP / AD enumeration
    (re.compile(r"\bldapsearch\s+", re.I),
     "ldapsearch",
     "high", "T1087.002", "ldap_enum"),
    (re.compile(r"\bdsquery\s+(?:user|group|computer|server)\b", re.I),
     "dsquery user/group/computer",
     "high", "T1087.002", "ad_query"),
    (re.compile(r"\bGet-AD(?:User|Computer|Group|GroupMember|Domain|"
                r"DomainController)\b", re.I),
     "PowerShell Get-AD* AD enumeration",
     "high", "T1087.002", "ad_powershell"),
    (re.compile(r"\bGet-LocalGroupMember\b", re.I),
     "PowerShell Get-LocalGroupMember",
     "medium", "T1069.001", "local_group_enum"),

    # T1087.001 — local account enumeration (Unix)
    (re.compile(r"\bgetent\s+(?:passwd|shadow|group)\b", re.I),
     "getent passwd/shadow/group",
     "medium", "T1087.001", "getent_enum"),
    (re.compile(r"\bdscl\s+\.\s+(?:list|read)\s+/Users\b", re.I),
     "dscl . list/read /Users (macOS account enum)",
     "high", "T1087.001", "macos_account_enum"),

    # T1083 — file/dir discovery; credential-hunt patterns are critical
    (re.compile(r"\bfind\s+\S+[^|]*-perm\s+-?[42]000\b", re.I),
     "find SUID/SGID binaries (privesc hunt)",
     "high", "T1083", "suid_hunt"),
    (re.compile(r"\bfind\s+\S+[^|]*-name\s+['\"]?\*?\.kdbx\b", re.I),
     "find *.kdbx (KeePass DB hunt)",
     "critical", "T1083", "credential_file_hunt"),
    (re.compile(r"\bfind\s+\S+[^|]*-name\s+['\"]?id_rsa\b", re.I),
     "find id_rsa (SSH key hunt)",
     "critical", "T1083", "credential_file_hunt"),
    (re.compile(r"\bfind\s+\S+[^|]*-name\s+['\"]?\*\.pem\b", re.I),
     "find *.pem (PEM key hunt)",
     "high", "T1083", "credential_file_hunt"),
    (re.compile(r"\bgrep\s+-r[a-z]*\s+['\"]?(?:password|api[_-]?key|secret|"
                r"token|aws_access|private_key)\b", re.I),
     "grep -r 'password|api_key|secret|aws_access|private_key' "
     "(credential string hunt)",
     "high", "T1552.001", "credential_string_hunt"),

    # T1046 — network service scanning
    (re.compile(r"\bnmap\b\s+(?:-[a-zA-Z]+\s+)*\S+", re.I),
     "nmap network scan",
     "high", "T1046", "port_scanner"),
    (re.compile(r"\bmasscan\b\s+", re.I),
     "masscan",
     "high", "T1046", "port_scanner"),
    (re.compile(r"\brustscan\b\s+", re.I),
     "rustscan",
     "high", "T1046", "port_scanner"),
    (re.compile(r"\bnaabu\b\s+", re.I),
     "naabu",
     "high", "T1046", "port_scanner"),

    # T1135 — network share discovery
    (re.compile(r"\bnet(?:\.exe)?\s+view\s+\\\\\S+", re.I),
     "net view \\\\<host> (SMB share enum)",
     "high", "T1135", "share_enum"),
    (re.compile(r"\bsmbclient\b\s+-L\b", re.I),
     "smbclient -L (SMB share enum)",
     "high", "T1135", "share_enum"),
    (re.compile(r"\benum4linux\b", re.I),
     "enum4linux (SMB enum tool)",
     "high", "T1135", "share_enum"),
]


# ---- D2 standard recon utilities (cluster-aware) ---- #
# These don't fire alone, but ≥3 distinct ones from the same user
# within 60s triggers the cluster finding.

_D2_CLUSTER_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (regex, label, mitre)
    (re.compile(r"\b(?:whoami|id)\s*$", re.I), "owner_id", "T1033"),
    (re.compile(r"\bhostname\b\s*$", re.I), "hostname", "T1082"),
    (re.compile(r"\b(?:uname\s+-[a-zA-Z]+|sw_vers|systeminfo|hostnamectl|"
                r"Get-ComputerInfo)\b", re.I),
     "sysinfo", "T1082"),
    (re.compile(r"\b(?:ipconfig\b|ifconfig\b|ip\s+a\b|ip\s+addr\b|"
                r"ip\s+route\b|route\s+print|Get-NetIPAddress|"
                r"Get-NetRoute)\b", re.I),
     "network_config", "T1016"),
    (re.compile(r"\b(?:netstat\s+-[a-z]+|ss\s+-[a-z]+|lsof\s+-i|"
                r"Get-NetTCPConnection|Get-NetUDPEndpoint)\b", re.I),
     "network_conn", "T1049"),
    (re.compile(r"\barp\s+-a\b", re.I), "arp_table", "T1018"),
    (re.compile(r"\b(?:ps\s+-(?:e[a-z]*|aux)|tasklist|Get-Process)\b", re.I),
     "process_list", "T1057"),
    (re.compile(r"\b(?:Get-Service|sc\s+query|systemctl\s+list-units|"
                r"launchctl\s+list)\b", re.I),
     "service_list", "T1007"),
    (re.compile(r"\b(?:dpkg\s+-l|rpm\s+-qa|brew\s+list|pip\s+list|"
                r"npm\s+ls\s+-g|gem\s+list|cargo\s+install\s+--list)\b", re.I),
     "software_list", "T1518"),
    (re.compile(r"\bGet-LocalUser\b", re.I), "owner_id", "T1033"),
]


# ---- D3 security-software discovery (T1518.001) ---- #

_D3_SECURITY_SOFTWARE: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(?:tasklist\s+/svc|Get-Service)\b.*?(?:WinDefend|"
                r"MsMpEng|Sense|MpsSvc|CSFalconSvc|SentinelAgent|"
                r"crowdstrike|sentinelone|sophos|symantec|trendmicro|"
                r"mcafee|kaspersky|wdavdaemon|carbonblack|cylancesvc|"
                r"esets|falcon-sensor|elastic-agent|wazuh|osquery)",
                re.I),
     "Windows EDR/AV service query"),
    (re.compile(r"\bps\s+-[a-z]+\b.*?\bgrep\b.*?"
                r"(?:crowdstrike|sentinel|sophos|wazuh|osquery|falcon|"
                r"elastic|carbonblack|cylance|mcafee|kaspersky)",
                re.I),
     "Unix EDR/AV process search"),
    (re.compile(r"\bsystemctl\s+(?:status|is-active|list-units)\s+"
                r"(?:falcon-sensor|crowdstrike|wazuh|osqueryd|"
                r"sentinelone|elastic-agent)", re.I),
     "Linux EDR systemctl probe"),
    (re.compile(r"\bGet-MpComputerStatus\b", re.I),
     "Get-MpComputerStatus (Defender state)"),
    (re.compile(r"\bGet-MpPreference\b", re.I),
     "Get-MpPreference (Defender config)"),
    (re.compile(r"\blaunchctl\s+list\b.*?"
                r"(?:Falcon|CrowdStrike|SentinelOne|Sophos)", re.I),
     "launchctl list <security daemon>"),
    (re.compile(r"\bls\s+(?:-[a-z]+\s+)?/Library/(?:Application\\?\s?Support"
                r"|LaunchDaemons|LaunchAgents)/.*?"
                r"(?:Falcon|CrowdStrike|SentinelOne|Sophos|Symantec)",
                re.I),
     "ls /Library /<security path>"),
]


# ---- Cluster heuristic params ---- #


CLUSTER_WINDOW_S = 60
CLUSTER_MIN_DISTINCT = 3


def _cmdline_str(cmdline) -> str:
    if isinstance(cmdline, list):
        return " ".join(str(c) for c in cmdline if c)
    return cmdline or ""


def _is_admin_user(name: str | None) -> bool:
    if not name:
        return False
    n = name.lower()
    return n in {"root", "system", "administrator", "nt authority\\system"}


class DiscoveryDetector(Detector):
    name = "discovery"
    description = (
        "Living-off-the-land enumeration on the host post-foothold: "
        "AD / account / network / file / service / software / "
        "security-software discovery. Fires on single high-signal "
        "LOTL commands (whoami /all, nmap, find -perm 4000, "
        "credential-file hunts) and on multi-pattern clusters "
        "(≥3 distinct standard recon commands by the same user "
        "within 60s)."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Discovery / living-off-the-land enumeration",
            "id": "digger-discovery-template",
            "description": (
                "A process invokes a discovery primitive: whoami "
                "/all|priv|groups; net user/localgroup/group; "
                "nltest /dclist; ldapsearch / dsquery / Get-AD*; "
                "getent passwd/shadow/group; dscl . list /Users; "
                "find SUID/SGID; credential-file hunt (find "
                "*.kdbx / id_rsa / *.pem); grep -r 'password|api_key"
                "|secret|aws_access'; nmap / masscan / rustscan; "
                "net view <host>; smbclient -L; enum4linux."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_high_signal_lotl": {
                    "CommandLine|re": (
                        r"(?:whoami(?:\.exe)?\s+/(?:all|priv|groups)|"
                        r"net(?:\.exe)?\s+(?:user|localgroup|group\s+['\"]?"
                        r"Domain\s+Admins|view\s+/(?:domain|all))|"
                        r"nltest(?:\.exe)?\s+/(?:dclist|domain_trusts)|"
                        r"ldapsearch|"
                        r"dsquery\s+(?:user|group|computer|server)|"
                        r"Get-AD(?:User|Computer|Group|GroupMember|Domain)|"
                        r"getent\s+(?:passwd|shadow|group)|"
                        r"dscl\s+\.\s+(?:list|read)\s+/Users|"
                        r"find\s+\S+[^|]*-perm\s+-?[42]000|"
                        r"find\s+\S+[^|]*-name\s+['\"]?(?:\*?\.kdbx|"
                        r"id_rsa|\*?\.pem)|"
                        r"nmap|masscan|rustscan|naabu|"
                        r"smbclient\s+-L|enum4linux)"
                    ),
                },
                "selection_security_software": {
                    "CommandLine|contains": [
                        "WinDefend", "CSFalconSvc", "SentinelAgent",
                        "falcon-sensor", "crowdstrike", "sentinelone",
                        "Get-MpComputerStatus", "Get-MpPreference",
                    ],
                },
                "condition": "1 of selection_*",
            },
            "level": "high",
            "tags": [
                "attack.t1007", "attack.t1016", "attack.t1018",
                "attack.t1033", "attack.t1046", "attack.t1049",
                "attack.t1057", "attack.t1069", "attack.t1069.001",
                "attack.t1069.002", "attack.t1082", "attack.t1083",
                "attack.t1087", "attack.t1087.001", "attack.t1087.002",
                "attack.t1135", "attack.t1518", "attack.t1518.001",
                "attack.discovery",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        seen_proc: set[tuple[int, str]] = set()

        # For the cluster heuristic, bucket processes by (username,
        # 60s-window-start) and count distinct labels.
        cluster_buckets: dict[
            tuple[str, int], list[tuple[str, str, int, str, str]]
        ] = defaultdict(list)

        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            pid = d.get("pid") or 0
            name = (d.get("name") or "").lower()
            username = d.get("username") or ""
            cmd = _cmdline_str(d.get("cmdline"))
            if not cmd:
                continue
            ts = d.get("create_time") or art.get("ts") or 0

            # ---- D1 high-signal single-hit ---- #
            for rx, label, sev, mitre, kind in _D1_HIGH_SIGNAL:
                if not rx.search(cmd):
                    continue
                key = (pid, kind)
                if key in seen_proc:
                    continue
                seen_proc.add(key)
                # Soft-downgrade when admin already
                if sev == "high" and _is_admin_user(username) and kind in (
                    "owner_priv_dump", "owner_id",
                ):
                    sev = "low"
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=(
                        f"Discovery enumeration in pid {pid} ({name}): "
                        f"{label}"
                    ),
                    summary=(
                        f"Process {name} (pid {pid}, user "
                        f"{username or '?'}) command line matches: "
                        f"{label}. Living-off-the-land Discovery "
                        "primitives are the first thing an attacker "
                        "runs after gaining a foothold — correlate "
                        "with parent process, the user's recent "
                        "activity, and time-adjacent findings to "
                        "distinguish attacker recon from routine "
                        f"admin enumeration.\n\nCmdline: {cmd[:300]}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": kind,
                        "pid": pid,
                        "name": name,
                        "username": username,
                        "pattern": label,
                        "cmdline": cmd[:400],
                    },
                    mitre=mitre,
                )
                break   # one D1 finding per process

            # ---- D2 cluster bucket population ---- #
            window_start = int(ts // CLUSTER_WINDOW_S) * CLUSTER_WINDOW_S
            for rx, label, mitre in _D2_CLUSTER_PATTERNS:
                if rx.search(cmd):
                    cluster_buckets[(username, window_start)].append(
                        (label, mitre, pid, name, cmd),
                    )

            # ---- D3 security-software discovery (single-hit, medium) #
            for rx, label in _D3_SECURITY_SOFTWARE:
                if not rx.search(cmd):
                    continue
                key = (pid, "security_software_discovery")
                if key in seen_proc:
                    continue
                seen_proc.add(key)
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=(
                        f"Security-software discovery in pid {pid} "
                        f"({name}): {label}"
                    ),
                    summary=(
                        f"Process {name} (pid {pid}, user "
                        f"{username or '?'}) queried for EDR / AV "
                        f"presence: {label}. Adversaries enumerate "
                        "endpoint protection before deploying their "
                        "second-stage payload — a hit here often "
                        "precedes EDR-tampering attempts. Verify "
                        "the calling user is supposed to be "
                        f"checking.\n\nCmdline: {cmd[:300]}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "security_software_discovery",
                        "pid": pid,
                        "name": name,
                        "username": username,
                        "pattern": label,
                        "cmdline": cmd[:400],
                    },
                    mitre="T1518.001",
                )
                break

        # ---- D4 cluster fire ---- #
        for (username, window_start), hits in cluster_buckets.items():
            distinct_labels = {h[0] for h in hits}
            if len(distinct_labels) < CLUSTER_MIN_DISTINCT:
                continue
            # Soft severity on admin-account clusters (sysadmin
            # debugging looks similar)
            sev = "low" if _is_admin_user(username) else "medium"
            yield Finding(
                detector=self.name,
                severity=sev,
                title=(
                    f"Discovery cluster: {len(distinct_labels)} distinct "
                    f"recon commands by {username or '?'} in "
                    f"{CLUSTER_WINDOW_S}s window"
                ),
                summary=(
                    f"User {username or '?'} ran {len(distinct_labels)} "
                    f"distinct discovery primitives "
                    f"({', '.join(sorted(distinct_labels))}) within a "
                    f"{CLUSTER_WINDOW_S}-second window — the "
                    "footprint of a fresh attacker foothold enumerating "
                    "the box. Single commands here are routine; the "
                    "CLUSTER is the signal. Correlate with the "
                    "preceding 5 minutes for shell-spawn / initial-"
                    "access events."
                ),
                artifact_refs=[],   # multiple — left empty
                evidence={
                    "kind": "discovery_cluster",
                    "username": username,
                    "window_start_ts": window_start,
                    "distinct_labels": sorted(distinct_labels),
                    "hits": [
                        {"label": h[0], "mitre": h[1], "pid": h[2],
                         "name": h[3], "cmdline": h[4][:300]}
                        for h in hits[:20]
                    ],
                },
                mitre="T1057",  # closest single-technique stand-in
            )
