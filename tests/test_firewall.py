"""Firewall parsers + auditor + remediation."""

from __future__ import annotations

import pytest

from digger.firewall import (
    FirewallAction, FirewallBackend, FirewallDirection, FirewallState,
)
from digger.firewall.audit import audit, audit_macos_appfw
from digger.firewall.parsers import (
    parse_firewalld, parse_iptables, parse_nftables, parse_pf,
    parse_ufw, parse_wfp,
)


# ---- pf ---- #


def test_pf_parses_default_deny_then_allows():
    info = "Status: Enabled for 1 day  Debug: Urgent\n"
    rules = (
        "block in all\n"
        "pass in proto tcp from any to any port 22\n"
        "pass in proto tcp from 10.0.0.0/8 to any port 5432\n"
    )
    state = parse_pf(rules, info)
    assert state.backend == FirewallBackend.PF
    assert state.enabled is True
    assert state.default_inbound == FirewallAction.DENY
    assert len(state.rules) == 3
    ssh = state.rules[1]
    assert ssh.dst_port == "22"
    assert ssh.opens_to_world() is True


def test_pf_disabled():
    info = "Status: Disabled\n"
    state = parse_pf("", info)
    assert state.enabled is False


# ---- nftables ---- #


def test_nftables_default_drop_policy():
    raw = (
        "table inet filter {\n"
        "  chain input {\n"
        "    type filter hook input priority 0; policy drop;\n"
        "    iif lo accept\n"
        "    ct state established,related accept\n"
        "    tcp dport 22 accept\n"
        "  }\n"
        "}\n"
    )
    state = parse_nftables(raw)
    assert state.backend == FirewallBackend.NFTABLES
    assert state.default_inbound == FirewallAction.DENY
    # 4 rule lines (iif lo, ct state, tcp dport 22, plus possibly more)
    assert any(r.dst_port == "22" for r in state.rules)


def test_nftables_default_accept_is_flagged():
    raw = (
        "table inet filter {\n"
        "  chain input {\n"
        "    type filter hook input priority 0; policy accept;\n"
        "  }\n"
        "}\n"
    )
    state = parse_nftables(raw)
    assert state.default_inbound == FirewallAction.ALLOW


# ---- iptables ---- #


def test_iptables_parses_policies_and_rules():
    raw = (
        "*filter\n"
        ":INPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "-A INPUT -p tcp --dport 3306 -j ACCEPT\n"
        "COMMIT\n"
    )
    state = parse_iptables(raw)
    assert state.default_inbound == FirewallAction.ALLOW
    assert state.default_outbound == FirewallAction.ALLOW
    ports = {r.dst_port for r in state.rules}
    assert "22" in ports
    assert "3306" in ports


# ---- ufw ---- #


def test_ufw_default_deny_inbound():
    raw = (
        "Status: active\n"
        "Logging: on (low)\n"
        "Default: deny (incoming), allow (outgoing), deny (routed)\n"
        "New profiles: skip\n"
        "\n"
        "To                         Action      From\n"
        "--                         ------      ----\n"
        "22/tcp                     ALLOW IN    Anywhere\n"
    )
    state = parse_ufw(raw)
    assert state.enabled is True
    assert state.default_inbound == FirewallAction.DENY
    assert state.default_outbound == FirewallAction.ALLOW
    assert any(r.dst_port == "22" for r in state.rules)


# ---- firewalld ---- #


def test_firewalld_open_ports_recorded():
    raw = (
        "public (active)\n"
        "  target: default\n"
        "  interfaces: eth0\n"
        "  services: ssh dhcpv6-client\n"
        "  ports: 6379/tcp 27017/tcp\n"
        "  protocols:\n"
    )
    state = parse_firewalld(raw)
    ports = {r.dst_port for r in state.rules}
    assert "6379" in ports
    assert "27017" in ports


# ---- WFP ---- #


def test_wfp_parses_default_block():
    profiles = '[{"Enabled":"True","DefaultInboundAction":"Block"}]'
    rules = '[{"Name":"r1","DisplayName":"Allow SSH","Direction":"Inbound","Action":"Allow"}]'
    state = parse_wfp(profiles, rules)
    assert state.backend == FirewallBackend.WFP
    assert state.enabled is True
    assert state.default_inbound == FirewallAction.DENY
    assert len(state.rules) == 1


# ---- auditor ---- #


def _state(backend, **kw) -> FirewallState:
    s = FirewallState(
        backend=backend,
        enabled=True,
        default_inbound=FirewallAction.DENY,
        default_outbound=FirewallAction.ALLOW,
    )
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def test_audit_flags_no_default_deny():
    state = _state(FirewallBackend.NFTABLES,
                   default_inbound=FirewallAction.ALLOW)
    findings = audit(state)
    ids = {f.check_id for f in findings}
    assert "C1.no-default-deny-inbound" in ids
    # remedy is non-empty
    f = next(x for x in findings if x.check_id == "C1.no-default-deny-inbound")
    assert f.remedy.commands
    assert any("nft" in c for c in f.remedy.commands)


def test_audit_flags_sensitive_port_open_to_world():
    state = _state(FirewallBackend.IPTABLES)
    from digger.firewall.model import FirewallRule
    state.rules.append(FirewallRule(
        direction=FirewallDirection.INBOUND,
        action=FirewallAction.ALLOW,
        protocol="tcp",
        src_addr="0.0.0.0/0",
        dst_port="6379",
        raw="-A INPUT -p tcp --dport 6379 -j ACCEPT",
    ))
    findings = audit(state)
    redis = [f for f in findings if "redis" in f.check_id]
    assert redis, [f.check_id for f in findings]
    assert redis[0].severity == "critical"
    assert any("iptables" in c for c in redis[0].remedy.commands)


def test_audit_flags_any_any_rule():
    state = _state(FirewallBackend.PF)
    from digger.firewall.model import FirewallRule
    state.rules.append(FirewallRule(
        direction=FirewallDirection.INBOUND,
        action=FirewallAction.ALLOW,
        protocol="any",
        src_addr="any",
        dst_addr="any",
        src_port="any",
        dst_port="any",
        raw="pass in all",
    ))
    findings = audit(state)
    assert any(f.check_id == "C4.any-any-allow" for f in findings)


def test_audit_flags_disabled_backend():
    state = _state(FirewallBackend.PF, enabled=False)
    findings = audit(state)
    assert any(f.check_id == "C6.backend-disabled" for f in findings)


def test_audit_appfw_disabled():
    findings = audit_macos_appfw("Firewall is disabled. (State = 0)")
    assert any(f.check_id == "C5.appfw-disabled" for f in findings)
    findings = audit_macos_appfw("Firewall is enabled. (State = 1)")
    assert findings == []


def test_remedy_annotates_destructive_commands():
    from digger.firewall.audit import _remedy_default_deny_inbound
    rem = _remedy_default_deny_inbound(FirewallBackend.IPTABLES)
    annotated = rem.annotated()
    # iptables remedy is a series of policy / state rules; none are "rm -rf"
    # destructive — but the annotation method must run cleanly.
    assert all(isinstance(t, tuple) and len(t) == 2 for t in annotated)
    assert all(isinstance(t[0], str) and isinstance(t[1], bool) for t in annotated)
