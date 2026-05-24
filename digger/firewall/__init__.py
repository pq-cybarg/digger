"""Unified firewall model, parsers, and auditor.

The collectors in ``digger.collectors.{macos,linux,windows}.firewall``
capture raw output from whatever backend the host is using (pf,
nftables, iptables, ufw, firewalld, Windows Defender Firewall). The
parsers in ``digger.firewall.parsers`` normalize that output to a
single :class:`FirewallState` containing a list of :class:`FirewallRule`
entries. The auditor in :mod:`digger.firewall.audit` runs platform-agnostic
checks against the unified model and emits findings whose ``evidence.remedy``
field carries platform-specific fix commands.

Every fix command routes through
:func:`digger.ethics.contract.redact_dangerous_command` before being
shown, and execution is gated by
:func:`digger.ethics.contract.confirm_remediation_intent`. The auditor
NEVER applies changes itself — it prints commands and tells the user
how to run them.
"""

from digger.firewall.model import (
    FirewallAction, FirewallBackend, FirewallDirection,
    FirewallRule, FirewallState, Remedy,
)

__all__ = [
    "FirewallAction", "FirewallBackend", "FirewallDirection",
    "FirewallRule", "FirewallState", "Remedy",
]
