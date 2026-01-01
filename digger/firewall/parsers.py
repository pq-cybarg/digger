"""Backend-specific parsers that produce a normalized :class:`FirewallState`.

Each parser takes the raw textual output of the respective firewall
inspection command and produces a single ``FirewallState``. Parsers
degrade gracefully: malformed lines are recorded in ``notes`` rather
than raising.
"""

from __future__ import annotations

import json
import re
import time

from digger.firewall.model import (
    FirewallAction, FirewallBackend, FirewallDirection,
    FirewallRule, FirewallState,
)


# ---- pf (macOS, OpenBSD) ----------------------------------------------------


_PF_LINE = re.compile(
    r"^(?P<action>pass|block|match|drop|reject|allow)"
    r"(?:\s+(?P<dir>in|out))?"
    r"(?:\s+log)?"
    r"(?:\s+on\s+(?P<iface>\S+))?"
    r"(?:\s+proto\s+(?P<proto>\S+))?"
    r"(?:\s+from\s+(?P<src>\S+(?:\s+port\s+\S+)?))?"
    r"(?:\s+to\s+(?P<dst>\S+(?:\s+port\s+\S+)?))?",
    re.I,
)


def _pf_action(a: str) -> FirewallAction:
    a = a.lower()
    if a in ("pass", "allow", "match"):
        return FirewallAction.ALLOW
    if a in ("block", "drop"):
        return FirewallAction.DENY
    if a == "reject":
        return FirewallAction.REJECT
    return FirewallAction.UNKNOWN


def _pf_split_addr_port(s: str | None) -> tuple[str, str]:
    if not s:
        return ("any", "any")
    s = s.strip()
    m = re.match(r"^(.*?)\s+port\s+(\S+)$", s)
    if m:
        return (m.group(1), m.group(2))
    return (s, "any")


def parse_pf(raw: str, info_raw: str = "") -> FirewallState:
    """Parse ``pfctl -sr`` (rules) plus optional ``pfctl -s info``."""
    state = FirewallState(
        backend=FirewallBackend.PF,
        enabled=False,
        raw_status=info_raw,
        detected_at=time.time(),
    )
    if info_raw:
        if re.search(r"Status:\s+Enabled", info_raw):
            state.enabled = True
        elif re.search(r"Status:\s+Disabled", info_raw):
            state.enabled = False

    seen_default_inbound = False
    for line in (raw or "").splitlines():
        ln = line.strip()
        if not ln or ln.startswith("#"):
            continue
        m = _PF_LINE.match(ln)
        if not m:
            state.notes.append(f"pf: unparsed: {ln[:120]}")
            continue
        d = m.group("dir")
        direction = (
            FirewallDirection.INBOUND if (d and d.lower() == "in") else
            FirewallDirection.OUTBOUND if (d and d.lower() == "out") else
            FirewallDirection.ANY
        )
        action = _pf_action(m.group("action"))
        src_addr, src_port = _pf_split_addr_port(m.group("src"))
        dst_addr, dst_port = _pf_split_addr_port(m.group("dst"))
        rule = FirewallRule(
            direction=direction,
            action=action,
            protocol=(m.group("proto") or "any").lower(),
            src_addr=src_addr,
            src_port=src_port,
            dst_addr=dst_addr,
            dst_port=dst_port,
            interface=m.group("iface") or "",
            raw=ln,
        )
        state.rules.append(rule)
        if (rule.direction == FirewallDirection.INBOUND
                and rule.is_any_any() and not seen_default_inbound):
            state.default_inbound = action
            seen_default_inbound = True

    if not seen_default_inbound and state.rules:
        # pf default is pass when no "block all" present (operator-set rules).
        state.default_inbound = FirewallAction.ALLOW
    return state


# ---- nftables ---------------------------------------------------------------

# nft list ruleset gives us a structured DSL. We only parse what we need.


_NFT_CHAIN = re.compile(
    r"^\s*chain\s+(\S+)\s*\{", re.M
)
_NFT_POLICY = re.compile(r"policy\s+(\w+)", re.I)
_NFT_HOOK = re.compile(r"hook\s+(\w+)", re.I)


def _nft_action(verb: str) -> FirewallAction:
    v = verb.lower()
    if v == "accept": return FirewallAction.ALLOW
    if v == "drop":   return FirewallAction.DENY
    if v == "reject": return FirewallAction.REJECT
    if v == "log":    return FirewallAction.LOG
    return FirewallAction.UNKNOWN


def parse_nftables(raw: str) -> FirewallState:
    """Best-effort parser for ``nft list ruleset`` output."""
    state = FirewallState(
        backend=FirewallBackend.NFTABLES,
        enabled=bool(raw and raw.strip()),
        raw_status=raw,
        detected_at=time.time(),
    )
    if not raw:
        return state

    # Walk chains so we can attach default policies per direction.
    cur_chain = ""
    cur_hook = ""
    cur_policy = FirewallAction.UNKNOWN
    direction_for_hook = {
        "input": FirewallDirection.INBOUND,
        "output": FirewallDirection.OUTBOUND,
        "forward": FirewallDirection.FORWARD,
    }
    for raw_line in raw.splitlines():
        ln = raw_line.strip()
        if not ln or ln.startswith("#"):
            continue
        m = _NFT_CHAIN.match(raw_line)
        if m:
            cur_chain = m.group(1)
            cur_hook = ""
            cur_policy = FirewallAction.UNKNOWN
            continue
        if "hook" in ln:
            mh = _NFT_HOOK.search(ln)
            if mh:
                cur_hook = mh.group(1).lower()
        if "policy" in ln:
            mp = _NFT_POLICY.search(ln)
            if mp:
                cur_policy = _nft_action(mp.group(1))
                if cur_hook == "input":
                    state.default_inbound = cur_policy
                elif cur_hook == "output":
                    state.default_outbound = cur_policy
            continue
        # Match rule lines (anything ending in an action verb)
        m_verb = re.search(r"\b(accept|drop|reject|log)\b\s*$", ln)
        if not m_verb:
            continue
        action = _nft_action(m_verb.group(1))
        direction = direction_for_hook.get(cur_hook, FirewallDirection.ANY)
        proto = "any"
        for p in ("tcp", "udp", "icmp", "icmpv6"):
            if re.search(rf"\bip6?\s+protocol\s+{p}\b|\bmeta\s+l4proto\s+{p}\b|\b{p}\s+dport\b", ln):
                proto = p
                break
        dst_port = "any"
        mdp = re.search(r"dport\s+([\w{},-]+)", ln)
        if mdp:
            dst_port = mdp.group(1)
        src_addr = "any"
        msa = re.search(r"ip6?\s+saddr\s+(\S+)", ln)
        if msa:
            src_addr = msa.group(1)
        state.rules.append(FirewallRule(
            direction=direction,
            action=action,
            protocol=proto,
            src_addr=src_addr,
            dst_port=dst_port,
            raw=ln,
        ))
    return state


# ---- iptables ---------------------------------------------------------------

_IPT_CHAIN_POLICY = re.compile(
    r"^:(\w+)\s+(\w+)", re.M
)
_IPT_RULE = re.compile(r"^-A\s+(\S+)\s+(.+)", re.M)


def _ipt_action(target: str) -> FirewallAction:
    t = target.upper()
    if t == "ACCEPT": return FirewallAction.ALLOW
    if t == "DROP":   return FirewallAction.DENY
    if t == "REJECT": return FirewallAction.REJECT
    if t == "LOG":    return FirewallAction.LOG
    return FirewallAction.UNKNOWN


def parse_iptables(raw: str) -> FirewallState:
    """Parse ``iptables-save`` / ``ip6tables-save`` output."""
    state = FirewallState(
        backend=FirewallBackend.IPTABLES,
        enabled=bool(raw and raw.strip()),
        raw_status=raw,
        detected_at=time.time(),
    )
    if not raw:
        return state
    for chain, policy in _IPT_CHAIN_POLICY.findall(raw):
        c = chain.upper()
        action = _ipt_action(policy)
        if c == "INPUT":
            state.default_inbound = action
        elif c == "OUTPUT":
            state.default_outbound = action
    direction_for_chain = {
        "INPUT": FirewallDirection.INBOUND,
        "OUTPUT": FirewallDirection.OUTBOUND,
        "FORWARD": FirewallDirection.FORWARD,
    }
    for chain, body in _IPT_RULE.findall(raw):
        c = chain.upper()
        direction = direction_for_chain.get(c, FirewallDirection.ANY)
        # Extract target via -j
        mt = re.search(r"-j\s+(\S+)", body)
        action = _ipt_action(mt.group(1)) if mt else FirewallAction.UNKNOWN
        proto = "any"
        mp = re.search(r"-p\s+(\S+)", body)
        if mp:
            proto = mp.group(1)
        src_addr = "any"
        ms = re.search(r"-s\s+(\S+)", body)
        if ms:
            src_addr = ms.group(1)
        dst_port = "any"
        mdp = re.search(r"--dport\s+(\S+)", body)
        if mdp:
            dst_port = mdp.group(1)
        state.rules.append(FirewallRule(
            direction=direction,
            action=action,
            protocol=proto,
            src_addr=src_addr,
            dst_port=dst_port,
            raw=f"-A {chain} {body}",
        ))
    return state


# ---- ufw --------------------------------------------------------------------


def parse_ufw(raw: str) -> FirewallState:
    """Parse ``ufw status verbose`` output."""
    state = FirewallState(
        backend=FirewallBackend.UFW,
        enabled=False,
        raw_status=raw,
        detected_at=time.time(),
    )
    if not raw:
        return state
    if re.search(r"Status:\s+active", raw, re.I):
        state.enabled = True
    md = re.search(r"Default:\s+(\w+)\s+\(incoming\),\s+(\w+)\s+\(outgoing\)", raw, re.I)
    if md:
        state.default_inbound = {
            "deny": FirewallAction.DENY,
            "allow": FirewallAction.ALLOW,
            "reject": FirewallAction.REJECT,
        }.get(md.group(1).lower(), FirewallAction.UNKNOWN)
        state.default_outbound = {
            "deny": FirewallAction.DENY,
            "allow": FirewallAction.ALLOW,
            "reject": FirewallAction.REJECT,
        }.get(md.group(2).lower(), FirewallAction.UNKNOWN)
    # Parse "To  Action  From"
    in_table = False
    for ln in raw.splitlines():
        s = ln.strip()
        # ufw's separator can be "----" or "--" depending on column width
        if s and set(s.replace(" ", "")) <= set("-"):
            in_table = True
            continue
        if not in_table or not s:
            continue
        parts = re.split(r"\s{2,}", s)
        if len(parts) < 3:
            continue
        to, action_str, frm = parts[0], parts[1], parts[2]
        action = (
            FirewallAction.ALLOW if "ALLOW" in action_str.upper()
            else FirewallAction.DENY if "DENY" in action_str.upper()
            else FirewallAction.REJECT if "REJECT" in action_str.upper()
            else FirewallAction.UNKNOWN
        )
        # "Anywhere" → any
        src = "any" if frm.lower() in ("anywhere", "any") else frm
        dst_port = "any"
        proto = "any"
        # "22/tcp"
        mt = re.match(r"(\d+|\S+)/(tcp|udp)$", to)
        if mt:
            dst_port = mt.group(1)
            proto = mt.group(2)
        state.rules.append(FirewallRule(
            direction=FirewallDirection.INBOUND,
            action=action,
            protocol=proto,
            src_addr=src,
            dst_port=dst_port,
            raw=s,
        ))
    return state


# ---- firewalld --------------------------------------------------------------


def parse_firewalld(raw: str) -> FirewallState:
    """Parse ``firewall-cmd --list-all-zones`` output (best effort)."""
    state = FirewallState(
        backend=FirewallBackend.FIREWALLD,
        enabled=bool(raw and raw.strip()),
        raw_status=raw,
        detected_at=time.time(),
    )
    if not raw:
        return state
    cur_zone = ""
    cur_target = FirewallAction.UNKNOWN
    for raw_line in raw.splitlines():
        m_zone = re.match(r"^(\S+)(?:\s+\(active\))?$", raw_line.strip())
        if m_zone and not raw_line.startswith(" ") and not raw_line.startswith("\t"):
            cur_zone = m_zone.group(1)
            cur_target = FirewallAction.UNKNOWN
            continue
        m_target = re.search(r"target:\s+(\w+)", raw_line)
        if m_target:
            t = m_target.group(1).upper()
            cur_target = (
                FirewallAction.ALLOW if t == "ACCEPT"
                else FirewallAction.DENY if t in ("DROP", "%%REJECT%%", "REJECT")
                else FirewallAction.UNKNOWN
            )
            if cur_zone in ("public", "external", "drop", "block"):
                state.default_inbound = cur_target
            continue
        m_svc = re.search(r"services:\s+(.+)", raw_line)
        if m_svc:
            for svc in m_svc.group(1).split():
                state.rules.append(FirewallRule(
                    direction=FirewallDirection.INBOUND,
                    action=FirewallAction.ALLOW,
                    protocol="tcp",
                    dst_port=svc,  # firewalld uses named services (ssh, https)
                    raw=f"zone={cur_zone} service={svc}",
                ))
        m_port = re.search(r"ports:\s+(.+)", raw_line)
        if m_port:
            for p in m_port.group(1).split():
                mp = re.match(r"(\d+)/(tcp|udp)", p)
                if mp:
                    state.rules.append(FirewallRule(
                        direction=FirewallDirection.INBOUND,
                        action=FirewallAction.ALLOW,
                        protocol=mp.group(2),
                        dst_port=mp.group(1),
                        raw=f"zone={cur_zone} port={p}",
                    ))
    return state


# ---- Windows Defender Firewall ---------------------------------------------


def parse_wfp(profiles_json: str, rules_json: str) -> FirewallState:
    """Parse the Get-NetFirewallProfile + Get-NetFirewallRule JSON our
    Windows collector captures."""
    state = FirewallState(
        backend=FirewallBackend.WFP,
        enabled=False,
        raw_status=profiles_json,
        detected_at=time.time(),
    )
    try:
        profiles = json.loads(profiles_json or "[]")
        if isinstance(profiles, dict):
            profiles = [profiles]
    except json.JSONDecodeError:
        profiles = []
    enabled_count = 0
    for p in profiles:
        if str(p.get("Enabled")).lower() in ("true", "1"):
            enabled_count += 1
        action = (p.get("DefaultInboundAction") or "").lower()
        if action == "block":
            state.default_inbound = FirewallAction.DENY
        elif action == "allow":
            state.default_inbound = FirewallAction.ALLOW
    state.enabled = enabled_count >= 1

    try:
        rules = json.loads(rules_json or "[]")
        if isinstance(rules, dict):
            rules = [rules]
    except json.JSONDecodeError:
        rules = []
    for r in rules:
        direction = (
            FirewallDirection.INBOUND if r.get("Direction") == "Inbound"
            else FirewallDirection.OUTBOUND if r.get("Direction") == "Outbound"
            else FirewallDirection.ANY
        )
        action = (
            FirewallAction.ALLOW if r.get("Action") == "Allow"
            else FirewallAction.DENY if r.get("Action") == "Block"
            else FirewallAction.UNKNOWN
        )
        state.rules.append(FirewallRule(
            direction=direction,
            action=action,
            rule_id=r.get("Name") or "",
            raw=r.get("DisplayName") or r.get("Name") or "",
        ))
    return state
