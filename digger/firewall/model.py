"""Unified, backend-agnostic firewall rule model.

Backends:
  - pf       (macOS, OpenBSD)
  - nftables (modern Linux)
  - iptables (legacy Linux)
  - ufw      (Ubuntu's frontend over iptables/nftables)
  - firewalld (RHEL/Fedora frontend)
  - wfp      (Windows Defender Firewall / Windows Filtering Platform)

Each backend has its own DSL, but at the high level a rule is:

    direction action proto src_addr:src_port -> dst_addr:dst_port [iface]

This module owns the cross-cutting types. Parsers in
:mod:`digger.firewall.parsers` convert backend-specific output to this
model; the auditor in :mod:`digger.firewall.audit` reasons over it.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class FirewallBackend(str, enum.Enum):
    PF = "pf"
    NFTABLES = "nftables"
    IPTABLES = "iptables"
    UFW = "ufw"
    FIREWALLD = "firewalld"
    WFP = "wfp"
    UNKNOWN = "unknown"


class FirewallDirection(str, enum.Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    FORWARD = "forward"
    ANY = "any"


class FirewallAction(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    LOG = "log"
    UNKNOWN = "unknown"


@dataclass
class FirewallRule:
    """One normalized firewall rule."""
    direction: FirewallDirection
    action: FirewallAction
    protocol: str = "any"        # tcp / udp / icmp / any
    src_addr: str = "any"        # CIDR or "any"
    src_port: str = "any"        # int, range, or "any"
    dst_addr: str = "any"
    dst_port: str = "any"
    interface: str = ""
    rule_id: str = ""            # backend-native identifier when available
    raw: str = ""                # original line for audit transparency

    def is_any_any(self) -> bool:
        """Match-everything rule (typical default-deny target)."""
        return (
            self.src_addr in ("any", "0.0.0.0/0", "::/0", "*")
            and self.dst_addr in ("any", "0.0.0.0/0", "::/0", "*")
            and self.src_port == "any"
            and self.dst_port == "any"
        )

    def opens_to_world(self) -> bool:
        """Inbound allow with no source restriction."""
        return (
            self.direction == FirewallDirection.INBOUND
            and self.action == FirewallAction.ALLOW
            and self.src_addr in ("any", "0.0.0.0/0", "::/0", "*")
        )


@dataclass
class Remedy:
    """Platform-specific fix commands for a finding.

    ``commands`` is the canonical list (shell-ready). ``rationale`` is a
    one-line explanation of *why* the command is the right fix. The
    auditor never executes these — they go to the report so the operator
    can review and apply (or refuse).
    """
    description: str
    commands: list[str] = field(default_factory=list)
    rationale: str = ""
    requires_root: bool = True
    backend: str = ""

    def annotated(self) -> list[tuple[str, bool]]:
        """Return [(command, is_dangerous)] with destructive ones flagged."""
        from digger.ethics.contract import redact_dangerous_command
        out = []
        for cmd in self.commands:
            _annotated, dangerous = redact_dangerous_command(cmd)
            out.append((cmd, dangerous))
        return out


@dataclass
class FirewallState:
    """Snapshot of the host's firewall."""
    backend: FirewallBackend
    enabled: bool
    default_inbound: FirewallAction = FirewallAction.UNKNOWN
    default_outbound: FirewallAction = FirewallAction.UNKNOWN
    rules: list[FirewallRule] = field(default_factory=list)
    raw_status: str = ""
    detected_at: float = 0.0
    notes: list[str] = field(default_factory=list)

    def inbound_rules(self) -> list[FirewallRule]:
        return [
            r for r in self.rules
            if r.direction in (FirewallDirection.INBOUND, FirewallDirection.ANY)
        ]

    def to_dict(self) -> dict:
        return {
            "backend": self.backend.value,
            "enabled": self.enabled,
            "default_inbound": self.default_inbound.value,
            "default_outbound": self.default_outbound.value,
            "rules": [r.__dict__ for r in self.rules],
            "raw_status": self.raw_status,
            "detected_at": self.detected_at,
            "notes": self.notes,
        }
