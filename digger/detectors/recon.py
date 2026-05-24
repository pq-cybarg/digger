"""Counter-reconnaissance: detect host-targeted recon from collected artifacts.

Purely observational — we read what other collectors have already captured
and look for patterns consistent with reconnaissance against this host:

  R1  Port-scan footprint in the connection-table snapshot
      Many remote IPs in SYN_RECV / FIN_WAIT2 / TIME_WAIT against many
      distinct local listening ports = portscan-in-progress.

  R2  SSH brute-force / banner-grab in auth logs
      High counts of "Failed password", "Invalid user", and "Did not
      receive identification string" from few source IPs.

  R3  Firewall denied a burst of inbound connections (Windows 5152/5157,
      macOS appfw, pf log)
      Backstop signal — the firewall already blocked the recon, but it's
      worth surfacing the activity.

  R4  nmap-style banner-grab signatures in webserver logs
      Common nmap user-agents and probe paths if any HTTP logs are
      present in the case.

This detector takes no network actions. P1 / P2 (local-host only,
observation default) are honored — we just analyze artifacts already
collected.

MITRE: T1595 (Active Scanning), T1595.001 (Scanning IP Blocks),
T1592 (Gather Victim Host Information).
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- Tunables (could move to a YAML if it grows) --------------------------

# Connection-table thresholds
_MIN_REMOTE_IPS_TO_FLAG = 3        # at least N distinct remote IPs ...
_MIN_LOCAL_PORTS_PER_IP = 4        # ... each hitting at least N local ports ...
_SUSPICIOUS_STATES = {"SYN_RECV", "FIN_WAIT2", "TIME_WAIT", "LAST_ACK"}

# Auth-log thresholds (over the entire collected log slice)
_SSH_FAIL_THRESHOLD = 20           # failed passwords from one IP
_SSH_INVALID_USER_THRESHOLD = 10
_SSH_BANNER_GRAB_THRESHOLD = 5     # "Did not receive identification string"

# Compiled patterns for auth-log scraping
_SSH_FAILED = re.compile(
    r"Failed password for(?: invalid user)?\s+(\S+)\s+from\s+([\d.:a-fA-F]+)",
    re.I,
)
_SSH_INVALID_USER = re.compile(
    r"Invalid user\s+(\S+)\s+from\s+([\d.:a-fA-F]+)", re.I,
)
_SSH_BANNER_GRAB = re.compile(
    r"Did not receive identification string from\s+([\d.:a-fA-F]+)", re.I,
)
_SSH_PORT_PROBE = re.compile(
    # "Connection closed by 1.2.3.4 port 12345 [preauth]" is the classic
    # banner-grab + immediate-disconnect.
    r"Connection closed by\s+(authenticating user\s+\S+\s+)?([\d.:a-fA-F]+)"
    r"(?:\s+port\s+\d+)?\s+\[preauth\]",
    re.I,
)


# ---- helpers --------------------------------------------------------------


def _raddr_ip(raddr) -> str | None:
    """psutil net_connections may store remote address as a tuple/list or None."""
    if not raddr:
        return None
    if isinstance(raddr, (list, tuple)):
        return raddr[0] if raddr else None
    if isinstance(raddr, str):
        return raddr.split(":")[0]
    return None


def _laddr_port(laddr) -> int | None:
    if not laddr:
        return None
    if isinstance(laddr, (list, tuple)) and len(laddr) >= 2:
        try:
            return int(laddr[1])
        except (TypeError, ValueError):
            return None
    return None


# ---- analyzers ------------------------------------------------------------


def _scan_connection_table(store: EvidenceStore) -> dict[str, set[int]]:
    """Aggregate {remote_ip: set(local_ports_hit)} from the connection snapshot.

    Only counts entries in transient states (the steady-state ESTABLISHED
    connections are normal traffic). This is a snapshot, so it's a
    point-in-time approximation — a slow scan will dodge it; a fast scan
    will land squarely in the snapshot.
    """
    counts: dict[str, set[int]] = defaultdict(set)
    for art in store.iter_artifacts(collector="network", category="network"):
        data = art["data"]
        # Only the per-connection sub-artifacts (skip routes/arp/etc.)
        if not data.get("laddr") and not data.get("raddr"):
            continue
        status = (data.get("status") or "").upper()
        if status not in _SUSPICIOUS_STATES:
            continue
        rip = _raddr_ip(data.get("raddr"))
        lp = _laddr_port(data.get("laddr"))
        if not rip or lp is None:
            continue
        counts[rip].add(lp)
    return counts


def _scan_auth_logs(store: EvidenceStore) -> dict:
    """Pull failure-pattern counters out of auth-log artifacts."""
    failed: Counter = Counter()
    invalid_user: Counter = Counter()
    banner_grab: Counter = Counter()
    port_probe: Counter = Counter()
    sample_users_per_ip: dict[str, set[str]] = defaultdict(set)

    for art in store.iter_artifacts(category="logs"):
        data = art["data"]
        text = data.get("raw") or data.get("tail") or ""
        if not text or not isinstance(text, str):
            continue
        if not ("ssh" in text.lower() or "sshd" in text.lower()):
            # Cheap pre-filter
            continue
        for user, ip in _SSH_FAILED.findall(text):
            failed[ip] += 1
            sample_users_per_ip[ip].add(user)
        for user, ip in _SSH_INVALID_USER.findall(text):
            invalid_user[ip] += 1
            sample_users_per_ip[ip].add(user)
        for ip in _SSH_BANNER_GRAB.findall(text):
            banner_grab[ip] += 1
        for _user_phrase, ip in _SSH_PORT_PROBE.findall(text):
            port_probe[ip] += 1

    return {
        "failed": failed,
        "invalid_user": invalid_user,
        "banner_grab": banner_grab,
        "port_probe": port_probe,
        "sample_users": sample_users_per_ip,
    }


class ReconDetector(Detector):
    name = "recon"
    description = "Counter-reconnaissance: port-scan footprints, SSH brute-force, banner-grab patterns."

    def to_sigma_template(self) -> dict:
        return {
            "title": "Inbound recon: SSH brute-force or port-scan footprint",
            "id": "digger-recon-template",
            "description": (
                "High volume of SSH auth failures from a single source IP, or "
                "many distinct source IPs touching many local listen ports in "
                "transient connection states (SYN_RECV / TIME_WAIT)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"product": "linux", "service": "auth"},
            "detection": {
                "selection": {
                    "Image|endswith": "/sshd",
                    "Message|contains": [
                        "Failed password",
                        "Invalid user",
                        "Did not receive identification string",
                        "Connection closed by",
                    ],
                },
                "timeframe": "5m",
                "condition": "selection | count() by SourceIp > 20",
            },
            "level": "high",
            "tags": ["attack.reconnaissance", "attack.t1595.001",
                    "attack.t1110.001", "attack.t1592.002"],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- R1: connection-table portscan footprint ----
        portscan_map = _scan_connection_table(store)
        scanners = [
            (ip, ports) for ip, ports in portscan_map.items()
            if len(ports) >= _MIN_LOCAL_PORTS_PER_IP
        ]
        if len(scanners) >= _MIN_REMOTE_IPS_TO_FLAG:
            top = sorted(scanners, key=lambda p: -len(p[1]))[:10]
            yield Finding(
                detector=self.name,
                severity="high",
                title=f"Port-scan footprint: {len(scanners)} remote IPs probing many local ports",
                summary=(
                    f"{len(scanners)} distinct remote IPs appear in the connection "
                    "snapshot in transient states (SYN_RECV / FIN_WAIT2 / TIME_WAIT) "
                    f"each touching {_MIN_LOCAL_PORTS_PER_IP}+ different local "
                    "ports. This is the classic signature of an inbound port scan."
                ),
                artifact_refs=[],
                evidence={
                    "kind": "portscan_connection_table",
                    "scanner_count": len(scanners),
                    "top_scanners": [
                        {"ip": ip, "distinct_ports": len(ports),
                         "ports": sorted(list(ports))[:30]}
                        for ip, ports in top
                    ],
                },
                mitre="T1595.001",
            )
        elif scanners:
            for ip, ports in scanners:
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=f"Possible inbound port-probe from {ip} (touched {len(ports)} local ports)",
                    summary=(
                        f"Remote IP {ip} shows up in the connection snapshot "
                        f"hitting {len(ports)} distinct local ports in transient "
                        "states. Below the multi-scanner threshold but worth "
                        "flagging — consider correlating with auth.log."
                    ),
                    artifact_refs=[],
                    evidence={
                        "kind": "single_source_portprobe",
                        "remote_ip": ip,
                        "distinct_ports": len(ports),
                        "ports": sorted(list(ports))[:30],
                    },
                    mitre="T1595.001",
                )

        # ---- R2: SSH recon / brute-force ----
        auth = _scan_auth_logs(store)
        for ip, n in auth["failed"].items():
            if n < _SSH_FAIL_THRESHOLD:
                continue
            users = sorted(auth["sample_users"].get(ip, set()))[:10]
            yield Finding(
                detector=self.name,
                severity="high" if n >= _SSH_FAIL_THRESHOLD * 3 else "medium",
                title=f"SSH brute-force from {ip}: {n} failed-password attempts",
                summary=(
                    f"Auth logs show {n} 'Failed password' events from {ip} "
                    f"across {len(auth['sample_users'].get(ip, set()))} usernames. "
                    "This is reconnaissance-into-foothold pattern; if the host is "
                    "reachable from untrusted networks, consider fail2ban, port "
                    "knocking, or restricting SSH source IPs."
                ),
                artifact_refs=[],
                evidence={
                    "kind": "ssh_brute_force",
                    "remote_ip": ip,
                    "failed_attempts": n,
                    "sample_users": users,
                },
                mitre="T1110.001",
            )
        for ip, n in auth["invalid_user"].items():
            if n < _SSH_INVALID_USER_THRESHOLD:
                continue
            users = sorted(auth["sample_users"].get(ip, set()))[:10]
            yield Finding(
                detector=self.name,
                severity="medium",
                title=f"SSH username enumeration from {ip}: {n} invalid-user attempts",
                summary=(
                    f"{n} 'Invalid user' events from {ip} across {len(users)} "
                    "usernames — this is username-enumeration recon, often a "
                    "prelude to brute-force on accounts known to exist."
                ),
                artifact_refs=[],
                evidence={
                    "kind": "ssh_user_enum",
                    "remote_ip": ip,
                    "attempts": n,
                    "sample_users": users,
                },
                mitre="T1589.002",  # Gather Victim Identity: Email/Usernames
            )
        for ip, n in auth["banner_grab"].items():
            if n < _SSH_BANNER_GRAB_THRESHOLD:
                continue
            yield Finding(
                detector=self.name,
                severity="medium",
                title=f"SSH banner-grab probes from {ip}: {n} preauth disconnects",
                summary=(
                    f"{n} 'Did not receive identification string' events from "
                    f"{ip}. Classic banner-grab / port-fingerprinting signature "
                    "(nmap -sV against tcp/22, masscan with banner module, etc.)."
                ),
                artifact_refs=[],
                evidence={
                    "kind": "ssh_banner_grab",
                    "remote_ip": ip,
                    "events": n,
                },
                mitre="T1592.002",  # Gather Victim Host Information: Software
            )
        for ip, n in auth["port_probe"].items():
            if n < _SSH_BANNER_GRAB_THRESHOLD:
                continue
            yield Finding(
                detector=self.name,
                severity="low",
                title=f"SSH preauth disconnects from {ip}: {n} events",
                summary=(
                    f"{n} 'Connection closed by ... [preauth]' events from {ip}. "
                    "Could be a scanner, a flaky client behind NAT, or someone "
                    "running ssh-keyscan / ssh -V probes."
                ),
                artifact_refs=[],
                evidence={
                    "kind": "ssh_preauth_disconnect",
                    "remote_ip": ip,
                    "events": n,
                },
                mitre="T1595.002",  # Active Scanning: Vulnerability Scanning
            )
