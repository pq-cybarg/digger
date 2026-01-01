"""Counter-lateral-movement: detect outbound-to-internal lateral activity.

Observational. We mine processes + the connection-table snapshot + auth
logs / event logs for patterns of lateral movement *from this host* —
"someone is using this box as a pivot."

Signals:

  L1  Outbound SMB / SSH / WinRM / RDP / VNC to RFC1918
      A non-administrative user process connecting to TCP 22/445/3389/
      5985/5986/5900 of another internal host is the classic lateral
      pivot. We flag anything matching that pattern that isn't from a
      well-known admin tool path.

  L2  Credential-dumping tool signatures in process cmdline
      mimikatz, Rubeus, SafetyKatz, hashcat, secretsdump, mimipenguin,
      kerbeus, certipy, lazagne — strings in cmdline or exe path.

  L3  Impacket / lateral-toolkit process names
      psexec.py / smbexec.py / wmiexec.py / dcomexec.py / atexec.py /
      lookupsid.py / GetUserSPNs.py / GetNPUsers.py — these are the
      Impacket Python scripts. evil-winrm / crackmapexec / netexec /
      bloodhound-python — same idea.

  L4  SSH ProxyJump chains
      ``ssh -J host1,host2,host3 target`` or ``-o ProxyCommand=ssh ...``
      in a cmdline is a pivot chain.

  L5  Pass-the-hash markers in Windows event logs
      Event 4624 LogonType 3 (Network) with AuthenticationPackage NTLM
      and a workstation name that's empty / "ANONYMOUS LOGON" is the
      classic PtH signature.

MITRE: T1021 (Remote Services), T1021.002 (SMB/Admin Shares),
T1021.004 (SSH), T1021.006 (WinRM), T1550.002 (PtH), T1570 (Lateral
Tool Transfer).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# port -> (proto, service, mitre_subtechnique)
_LATERAL_PORTS = {
    22:   ("tcp", "ssh",   "T1021.004"),
    445:  ("tcp", "smb",   "T1021.002"),
    139:  ("tcp", "smb",   "T1021.002"),
    3389: ("tcp", "rdp",   "T1021.001"),
    5985: ("tcp", "winrm", "T1021.006"),
    5986: ("tcp", "winrm-https", "T1021.006"),
    5900: ("tcp", "vnc",   "T1021.005"),
    5938: ("tcp", "teamviewer", "T1021.005"),
}

# Well-known admin/dev tooling paths whose lateral-port connections are
# routine (saves the operator from a flood of "git pull from gitea" noise).
_ADMIN_TOOL_PATH_HINTS = (
    "/usr/bin/git", "/usr/local/bin/git",
    "/usr/bin/ssh", "/usr/local/bin/ssh",
    "/usr/bin/scp", "/usr/bin/sftp", "/usr/bin/rsync",
    "/usr/local/bin/code",          # vscode remote
    "/usr/libexec/ssh",
    "/opt/homebrew/bin/git", "/opt/homebrew/bin/ssh",
)

# Credential-dumping / lateral toolkit signatures (regex hits)
_CRED_DUMP_PATTERNS = [
    (re.compile(r"\bmimikatz(\.exe)?\b|sekurlsa|kerberos::list", re.I),
     "mimikatz"),
    (re.compile(r"\bsafetykatz\.exe\b|SafetyKatz", re.I),
     "SafetyKatz"),
    (re.compile(r"\bRubeus(\.exe)?\b|asktgt|asreproast|kerberoast", re.I),
     "Rubeus / Kerberoast"),
    (re.compile(r"\bsecretsdump(\.py)?\b|dcsync|NTDS\.dit", re.I),
     "secretsdump / impacket DCSync"),
    (re.compile(r"\bmimipenguin\.py\b|mimipenguin", re.I),
     "mimipenguin"),
    (re.compile(r"\blazagne(\.exe)?\b", re.I),
     "LaZagne"),
    (re.compile(r"\bcertipy(\.py)?\b|\bcertify\.exe\b", re.I),
     "Certipy / Certify (AD CS abuse)"),
    (re.compile(r"\bhashcat\b|\bjohn\b\s+-w|--wordlist", re.I),
     "hashcat / john offline crackers"),
    (re.compile(r"\b(?:pwdump|pwdumpx|fgdump|gsecdump)\b", re.I),
     "Windows password dumpers"),
]

_IMPACKET_NAMES = {
    "psexec.py", "smbexec.py", "wmiexec.py", "dcomexec.py", "atexec.py",
    "ntlmrelayx.py", "secretsdump.py", "GetUserSPNs.py", "GetNPUsers.py",
    "lookupsid.py", "rpcdump.py", "samrdump.py", "smbpasswd.py",
    "smbserver.py", "ticketer.py", "getST.py", "getTGT.py",
    "evil-winrm", "crackmapexec", "cme", "netexec", "nxc",
    "bloodhound-python", "kerbrute", "ldapdomaindump",
    "responder", "responder.py", "mitm6",
}


def _is_rfc1918(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_private and not ip.is_loopback
    except (ValueError, TypeError):
        return False


def _raddr_ip_port(raddr) -> tuple[str | None, int | None]:
    if not raddr:
        return None, None
    if isinstance(raddr, (list, tuple)) and len(raddr) >= 2:
        ip = raddr[0]
        try:
            port = int(raddr[1])
        except (TypeError, ValueError):
            port = None
        return ip, port
    if isinstance(raddr, str) and ":" in raddr:
        host, _, p = raddr.rpartition(":")
        try:
            return host, int(p)
        except ValueError:
            return host, None
    return None, None


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


def _is_admin_tool(exe: str | None) -> bool:
    if not exe:
        return False
    return any(exe.startswith(p) for p in _ADMIN_TOOL_PATH_HINTS)


def _collect_processes(store: EvidenceStore) -> dict[int, dict]:
    procs: dict[int, dict] = {}
    for art in store.iter_artifacts(collector="processes"):
        d = art["data"]
        pid = d.get("pid")
        if pid is None:
            continue
        procs[pid] = {
            "pid": pid,
            "ppid": d.get("ppid"),
            "name": (d.get("name") or "").lower(),
            "exe": d.get("exe") or "",
            "cmdline": _cmdline_str(d.get("cmdline")),
            "username": d.get("username") or "",
            "connections": d.get("connections") or [],
            "artifact_uuid": art["artifact_uuid"],
        }
    return procs


class LateralMovementDetector(Detector):
    name = "lateral"
    description = (
        "Counter-lateral-movement: outbound-to-internal lateral protocols, "
        "credential-dumping tool signatures, Impacket toolkit detection, "
        "SSH ProxyJump pivots, pass-the-hash markers."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Lateral movement: outbound SMB/SSH/WinRM/RDP to internal IP",
            "id": "digger-lateral-template",
            "description": (
                "Outbound connection on a lateral-movement protocol port "
                "(22 / 139 / 445 / 3389 / 5985 / 5986 / 5900) to an "
                "RFC1918 address from a non-admin process."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "network_connection"},
            "detection": {
                "selection": {
                    "Initiated": "true",
                    "DestinationPort": [22, 139, 445, 3389, 5985, 5986, 5900],
                    "DestinationIp|cidr": [
                        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                    ],
                },
                "filter_admin_tools": {
                    "Image|endswith": [
                        "/ssh", "/scp", "/sftp", "/rsync", "/git",
                    ],
                },
                "condition": "selection and not filter_admin_tools",
            },
            "level": "high",
            "tags": ["attack.t1021", "attack.t1550", "attack.t1570",
                    "attack.lateral_movement"],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        procs = _collect_processes(store)

        # ---- L1: outbound lateral protocols to RFC1918 ----
        for p in procs.values():
            exe = p.get("exe") or ""
            if _is_admin_tool(exe):
                continue
            for conn in p.get("connections") or []:
                rip, rport = _raddr_ip_port(conn.get("raddr"))
                if not rip or rport is None:
                    continue
                if rport not in _LATERAL_PORTS:
                    continue
                if not _is_rfc1918(rip):
                    continue
                if (conn.get("status") or "") not in ("ESTABLISHED", "SYN_SENT"):
                    continue
                proto, svc, mitre = _LATERAL_PORTS[rport]
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=f"Lateral {svc} to {rip}:{rport} from pid {p['pid']} ({p['name']})",
                    summary=(
                        f"Process {p['name']} (pid {p['pid']}, exe={exe or '?'}) "
                        f"has an outbound {svc} connection to RFC1918 host "
                        f"{rip}:{rport}. Lateral-protocol connections from "
                        "non-admin processes are the classic pivot pattern."
                    ),
                    artifact_refs=[p["artifact_uuid"]],
                    evidence={
                        "kind": "lateral_outbound",
                        "service": svc,
                        "remote_ip": rip,
                        "remote_port": rport,
                        "pid": p["pid"],
                        "name": p["name"],
                        "exe": exe,
                        "username": p["username"],
                        "cmdline": p["cmdline"][:300],
                    },
                    mitre=mitre,
                )

        # ---- L2: credential-dumping tool signatures ----
        seen_cred_in_pid: set[int] = set()
        for p in procs.values():
            blob = p["cmdline"] + " " + (p.get("exe") or "") + " " + p["name"]
            for rx, label in _CRED_DUMP_PATTERNS:
                if rx.search(blob):
                    if p["pid"] in seen_cred_in_pid:
                        break
                    seen_cred_in_pid.add(p["pid"])
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"Credential-dumping tool in pid {p['pid']}: {label}",
                        summary=(
                            f"Process {p['name']} (pid {p['pid']}) shows the "
                            f"signature of {label} in its command line or exe "
                            "path. These tools have no legitimate non-admin use "
                            "and are characteristic of post-foothold credential "
                            "harvesting."
                        ),
                        artifact_refs=[p["artifact_uuid"]],
                        evidence={
                            "kind": "credential_dumper",
                            "tool": label,
                            "pid": p["pid"],
                            "name": p["name"],
                            "exe": p["exe"],
                            "cmdline": p["cmdline"][:400],
                            "username": p["username"],
                        },
                        mitre="T1003",
                    )
                    break

        # ---- L3: Impacket / lateral toolkit by name ----
        for p in procs.values():
            base = _basename(p["exe"]) or p["name"]
            if base in _IMPACKET_NAMES:
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=f"Lateral-movement toolkit present: {base} (pid {p['pid']})",
                    summary=(
                        f"Running process {base} (pid {p['pid']}) matches a "
                        "known lateral-movement / AD-recon tool name "
                        "(Impacket / CrackMapExec / NetExec / evil-winrm / "
                        "Responder / kerbrute family). Sometimes a pentest "
                        "engagement, sometimes a real intrusion."
                    ),
                    artifact_refs=[p["artifact_uuid"]],
                    evidence={
                        "kind": "lateral_toolkit",
                        "tool": base,
                        "pid": p["pid"],
                        "exe": p["exe"],
                        "cmdline": p["cmdline"][:300],
                        "username": p["username"],
                    },
                    mitre="T1570",
                )

        # ---- L4: SSH ProxyJump pivot chains ----
        for p in procs.values():
            cmd = p["cmdline"]
            if not cmd or "ssh" not in cmd.lower():
                continue
            # -J host1,host2  OR  ProxyJump=...  OR  ProxyCommand=ssh ...
            mj = re.search(r"(?:^|\s)(?:-J\s+\S+|ProxyJump=\S+|ProxyCommand=ssh\s+)",
                           cmd, re.I)
            if not mj:
                continue
            yield Finding(
                detector=self.name,
                severity="medium",
                title=f"SSH ProxyJump pivot chain in pid {p['pid']}",
                summary=(
                    f"Process {p['name']} (pid {p['pid']}) is using SSH "
                    "ProxyJump / ProxyCommand to chain through one or more "
                    "intermediate hosts. Legitimate bastion usage looks like "
                    "this; an attacker using your host as a stepping-stone "
                    "looks the same."
                ),
                artifact_refs=[p["artifact_uuid"]],
                evidence={
                    "kind": "ssh_proxyjump",
                    "pid": p["pid"],
                    "name": p["name"],
                    "cmdline": cmd[:400],
                    "username": p["username"],
                },
                mitre="T1021.004",
            )

        # ---- L5: pass-the-hash markers in Windows event logs ----
        for art in store.iter_artifacts(collector="windows.event_logs"):
            d = art["data"]
            raw = d.get("raw") or ""
            if not isinstance(raw, str) or "4624" not in raw:
                continue
            # Look for the textbook PtH 4624: LogonType=3, AuthPkg=NTLM,
            # Workstation Name field empty/anonymous, source IP RFC1918.
            # We use a heuristic line-level regex; this is best-effort and the
            # operator can correlate full event XML if needed.
            for m in re.finditer(
                r"4624[^\n]{0,400}LogonType[\":\s]+3[^\n]{0,400}"
                r"AuthenticationPackageName[\":\s]+NTLM[^\n]{0,400}",
                raw, re.I,
            ):
                snippet = m.group(0)
                if not re.search(
                    r"WorkstationName[\":\s]+(?:-|ANONYMOUS|NULL|LOGON|\"\")",
                    snippet, re.I,
                ):
                    continue
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title="Pass-the-hash marker in Windows event 4624",
                    summary=(
                        "Windows Security event 4624 shows a Network logon "
                        "(LogonType=3) using the NTLM authentication package "
                        "with an empty or anonymous workstation name. This is "
                        "the textbook pass-the-hash signature — a hash, not "
                        "a password, was presented for authentication."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "pass_the_hash_marker",
                        "snippet": snippet[:500],
                    },
                    mitre="T1550.002",
                )
                # Cap one finding per event-log artifact so we don't
                # snowball — the operator can pull full data from the raw log.
                break
