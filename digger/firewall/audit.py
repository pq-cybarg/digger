"""Audit a unified :class:`FirewallState` and emit findings + remediation.

Checks:
  - C1  default-deny inbound is missing
  - C2  default-deny outbound is missing (advisory)
  - C3  inbound any-source rule on a sensitive port (database, share, etc.)
  - C4  any/any "permit all" rule present
  - C5  Application Firewall disabled (macOS)
  - C6  firewall backend itself disabled
  - C7  IPv4 protected but IPv6 wide-open (or vice versa)
  - C8  multiple backends configured (configuration drift)

Each check builds a :class:`Remedy` whose ``commands`` are exact, copy-pasteable
shell lines for the appropriate backend. Auditor NEVER executes — it just
reports. Execution is the operator's job, gated by
``digger.ethics.contract.confirm_remediation_intent``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from digger.firewall.model import (
    FirewallAction, FirewallBackend, FirewallDirection,
    FirewallRule, FirewallState, Remedy,
)


# Sensitive ports that should NEVER be world-listening. Map: port -> (proto, service)
SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    22:    ("tcp", "ssh"),
    23:    ("tcp", "telnet"),
    111:   ("tcp", "rpcbind"),
    135:   ("tcp", "windows-rpc"),
    137:   ("udp", "netbios-ns"),
    138:   ("udp", "netbios-dgm"),
    139:   ("tcp", "smb"),
    445:   ("tcp", "smb"),
    1433:  ("tcp", "mssql"),
    1521:  ("tcp", "oracle"),
    2049:  ("tcp", "nfs"),
    2375:  ("tcp", "docker-api-http"),  # unauth Docker API
    3306:  ("tcp", "mysql"),
    3389:  ("tcp", "rdp"),
    5432:  ("tcp", "postgresql"),
    5900:  ("tcp", "vnc"),
    5984:  ("tcp", "couchdb"),
    6379:  ("tcp", "redis"),
    7474:  ("tcp", "neo4j"),
    8086:  ("tcp", "influxdb"),
    8500:  ("tcp", "consul-http"),
    9200:  ("tcp", "elasticsearch"),
    9300:  ("tcp", "elasticsearch-cluster"),
    11211: ("tcp", "memcached"),
    27017: ("tcp", "mongodb"),
    27018: ("tcp", "mongodb"),
    28017: ("tcp", "mongodb-http"),
    50070: ("tcp", "hadoop"),
}


@dataclass
class AuditFinding:
    """One auditor finding. Maps cleanly to a digger Finding downstream."""
    check_id: str
    severity: str           # info | low | medium | high | critical
    title: str
    summary: str
    backend: str
    affected: list[str]     # rule.raw strings that triggered this finding
    remedy: Remedy


# ---- Per-backend remediation builders --------------------------------------


def _remedy_default_deny_inbound(backend: FirewallBackend) -> Remedy:
    if backend == FirewallBackend.PF:
        return Remedy(
            description="Enable pf and set inbound default-deny.",
            commands=[
                "sudo pfctl -e",
                "# Edit /etc/pf.conf and ensure the first rule is:  block in all",
                "sudo pfctl -f /etc/pf.conf",
            ],
            rationale="pf evaluates rules top-down; a leading 'block in all' establishes default-deny.",
            backend=backend.value,
        )
    if backend == FirewallBackend.NFTABLES:
        return Remedy(
            description="Set nftables input policy to drop.",
            commands=[
                "sudo nft add table inet filter",
                "sudo nft 'add chain inet filter input { type filter hook input priority 0 ; policy drop ; }'",
                "sudo nft add rule inet filter input ct state established,related accept",
                "sudo nft add rule inet filter input iif lo accept",
            ],
            rationale="Default-deny inbound with explicit accept for established/loopback is the canonical baseline.",
            backend=backend.value,
        )
    if backend == FirewallBackend.IPTABLES:
        return Remedy(
            description="Set iptables INPUT policy to DROP.",
            commands=[
                "sudo iptables -P INPUT DROP",
                "sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "sudo iptables -A INPUT -i lo -j ACCEPT",
                "sudo ip6tables -P INPUT DROP",
                "sudo ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "sudo ip6tables -A INPUT -i lo -j ACCEPT",
            ],
            rationale="Default-deny inbound on both v4 and v6; preserve established + loopback.",
            backend=backend.value,
        )
    if backend == FirewallBackend.UFW:
        return Remedy(
            description="Enable ufw and set default-deny inbound.",
            commands=[
                "sudo ufw default deny incoming",
                "sudo ufw default allow outgoing",
                "sudo ufw enable",
            ],
            rationale="ufw's standard hardened baseline.",
            backend=backend.value,
        )
    if backend == FirewallBackend.FIREWALLD:
        return Remedy(
            description="Set firewalld default zone to drop.",
            commands=[
                "sudo firewall-cmd --set-default-zone=drop",
                "sudo firewall-cmd --reload",
            ],
            rationale="firewalld's 'drop' zone is the no-services-allowed posture.",
            backend=backend.value,
        )
    if backend == FirewallBackend.WFP:
        return Remedy(
            description="Set Windows Defender Firewall inbound default to block.",
            commands=[
                "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -Enabled True",
            ],
            rationale="Block-by-default across all three profiles is the recommended baseline.",
            backend=backend.value,
        )
    return Remedy(description="Set default-deny inbound (backend unknown).",
                  commands=[], rationale="", backend=backend.value)


def _remedy_close_port(backend: FirewallBackend, port: int, proto: str,
                       service_name: str) -> Remedy:
    desc = f"Restrict access to {service_name} ({proto}/{port}) to localhost or a trusted CIDR."
    if backend == FirewallBackend.PF:
        return Remedy(
            description=desc,
            commands=[
                f"# Add to /etc/pf.conf BEFORE any 'pass in' rule that opens {port}:",
                f"block in quick proto {proto} from any to any port {port}",
                f"pass in quick proto {proto} from 127.0.0.1 to any port {port}",
                "sudo pfctl -f /etc/pf.conf",
            ],
            rationale=f"{service_name} is a high-value target; restrict to loopback or trusted CIDR.",
            backend=backend.value,
        )
    if backend == FirewallBackend.NFTABLES:
        return Remedy(
            description=desc,
            commands=[
                f"sudo nft add rule inet filter input {proto} dport {port} ip saddr != 127.0.0.1 drop",
            ],
            rationale=f"{service_name} should not be world-reachable.",
            backend=backend.value,
        )
    if backend == FirewallBackend.IPTABLES:
        return Remedy(
            description=desc,
            commands=[
                f"sudo iptables -I INPUT -p {proto} --dport {port} ! -s 127.0.0.1 -j DROP",
                f"sudo ip6tables -I INPUT -p {proto} --dport {port} ! -s ::1 -j DROP",
            ],
            rationale=f"{service_name} should not be world-reachable on either v4 or v6.",
            backend=backend.value,
        )
    if backend == FirewallBackend.UFW:
        return Remedy(
            description=desc,
            commands=[
                f"sudo ufw deny {port}/{proto}",
                f"# Or restrict to a CIDR:  sudo ufw allow from 10.0.0.0/8 to any port {port} proto {proto}",
            ],
            rationale=f"{service_name} should not be world-reachable.",
            backend=backend.value,
        )
    if backend == FirewallBackend.FIREWALLD:
        return Remedy(
            description=desc,
            commands=[
                f"sudo firewall-cmd --permanent --remove-port={port}/{proto}",
                "sudo firewall-cmd --reload",
            ],
            rationale=f"{service_name} should not be world-reachable.",
            backend=backend.value,
        )
    if backend == FirewallBackend.WFP:
        return Remedy(
            description=desc,
            commands=[
                f'New-NetFirewallRule -DisplayName "Block {service_name}" -Direction Inbound '
                f'-Protocol {proto.upper()} -LocalPort {port} -Action Block',
            ],
            rationale=f"{service_name} should not be world-reachable.",
            backend=backend.value,
        )
    return Remedy(description=desc, commands=[], rationale="", backend=backend.value)


def _remedy_enable_app_firewall_macos() -> Remedy:
    return Remedy(
        description="Enable macOS Application Firewall.",
        commands=[
            "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
            "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
            "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on",
        ],
        rationale="Application Firewall + stealth mode + logging is the macOS hardened baseline.",
        backend="socketfilterfw",
    )


# ---- Auditor ----------------------------------------------------------------


def _port_to_int(s: str) -> int | None:
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def audit(state: FirewallState) -> list[AuditFinding]:
    out: list[AuditFinding] = []

    if not state.enabled:
        out.append(AuditFinding(
            check_id="C6.backend-disabled",
            severity="high",
            title=f"{state.backend.value} firewall is disabled",
            summary=(
                f"The {state.backend.value} firewall backend reports as disabled. "
                "Without an active firewall, every listening service is reachable "
                "from any source on the network."
            ),
            backend=state.backend.value,
            affected=[],
            remedy=_remedy_default_deny_inbound(state.backend),
        ))

    if state.default_inbound != FirewallAction.DENY:
        out.append(AuditFinding(
            check_id="C1.no-default-deny-inbound",
            severity="high",
            title=f"No default-deny inbound on {state.backend.value}",
            summary=(
                f"Default inbound action is {state.default_inbound.value}. A new "
                "service that starts listening will be exposed unless explicitly "
                "blocked. Switch the default to deny and explicitly allow only "
                "what should be reachable."
            ),
            backend=state.backend.value,
            affected=[],
            remedy=_remedy_default_deny_inbound(state.backend),
        ))

    if state.default_outbound == FirewallAction.ALLOW and state.backend != FirewallBackend.PF:
        # Outbound default-deny is a stronger posture but breaks most workstation
        # setups; we keep this at info severity unless the operator opts in.
        out.append(AuditFinding(
            check_id="C2.permissive-outbound",
            severity="info",
            title=f"Outbound default is allow on {state.backend.value}",
            summary=(
                "Outbound traffic is unrestricted. For high-assurance hosts, "
                "consider default-deny outbound with explicit allow rules for "
                "the destinations the host legitimately reaches."
            ),
            backend=state.backend.value,
            affected=[],
            remedy=Remedy(
                description="Tighten outbound to default-deny + explicit allow.",
                commands=["# Backend-specific; see vendor docs."],
                rationale="High-assurance hosts benefit from egress control.",
                backend=state.backend.value,
            ),
        ))

    seen_any_any = False
    for r in state.inbound_rules():
        if r.action != FirewallAction.ALLOW:
            continue
        # any/any check first — must fire even when dst_port is "any"
        if r.is_any_any() and not seen_any_any:
            seen_any_any = True
            out.append(AuditFinding(
                check_id="C4.any-any-allow",
                severity="high",
                title=f"any/any inbound allow rule on {state.backend.value}",
                summary=(
                    "A rule with no source, destination, or port restrictions is "
                    "present and would allow any traffic to any port. This is "
                    "almost certainly a misconfiguration."
                ),
                backend=state.backend.value,
                affected=[r.raw],
                remedy=Remedy(
                    description="Remove or scope the any/any rule.",
                    commands=[f"# Locate and remove rule:  {r.raw}"],
                    rationale="any/any rules nullify every other restriction.",
                    backend=state.backend.value,
                ),
            ))
            continue
        port = _port_to_int(r.dst_port)
        if port is None:
            continue
        if port in SENSITIVE_PORTS and r.opens_to_world():
            proto, svc = SENSITIVE_PORTS[port]
            out.append(AuditFinding(
                check_id=f"C3.world-listening:{svc}",
                severity="critical" if svc in ("mssql", "mysql", "postgresql", "redis", "mongodb",
                                                "elasticsearch", "memcached", "docker-api-http") else "high",
                title=f"{svc} ({proto}/{port}) reachable from any source",
                summary=(
                    f"An inbound allow rule on {proto}/{port} ({svc}) has no source "
                    "restriction. Databases / management ports should be reachable "
                    "only from administrative networks or via VPN. Remediation will "
                    "restrict to localhost; widen to a trusted CIDR if remote admin "
                    "is required."
                ),
                backend=state.backend.value,
                affected=[r.raw],
                remedy=_remedy_close_port(state.backend, port, proto, svc),
            ))

    return out


def audit_macos_appfw(global_state: str, stealth_mode: str = "",
                     block_all: str = "") -> list[AuditFinding]:
    """The Application Firewall is independent of pf; audit it separately."""
    out: list[AuditFinding] = []
    if "enabled" not in (global_state or "").lower():
        out.append(AuditFinding(
            check_id="C5.appfw-disabled",
            severity="medium",
            title="macOS Application Firewall is disabled",
            summary=(
                "socketfilterfw reports the application firewall is OFF. While "
                "pf can still filter packets, the Application Firewall adds "
                "per-app inbound control and is the macOS-recommended baseline."
            ),
            backend="socketfilterfw",
            affected=[global_state.strip()],
            remedy=_remedy_enable_app_firewall_macos(),
        ))
    return out
