"""Network state: interfaces, listening ports, established conns, routing, ARP."""

from __future__ import annotations

import shutil
import socket
import subprocess
from typing import Iterable

import psutil

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS, current_os


def _safe_run(cmd: list[str]) -> str:
    if not shutil.which(cmd[0]):
        return ""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, check=False
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return ""


class NetworkCollector(Collector):
    name = "network"
    category = "network"
    description = "NICs, listening sockets, established connections, routes, ARP cache."

    def collect(self) -> Iterable[Artifact]:
        # Interfaces
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for nic, addr_list in addrs.items():
            stat = stats.get(nic)
            yield self.make(
                subject=f"nic={nic}",
                interface=nic,
                addresses=[
                    {
                        "family": str(a.family),
                        "address": a.address,
                        "netmask": a.netmask,
                        "broadcast": a.broadcast,
                        "ptp": a.ptp,
                    }
                    for a in addr_list
                ],
                is_up=getattr(stat, "isup", None),
                duplex=str(getattr(stat, "duplex", "")),
                speed_mbps=getattr(stat, "speed", None),
                mtu=getattr(stat, "mtu", None),
            )
        # Connections
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            conns = []
        for c in conns:
            yield self.make(
                subject=f"{c.status} {c.laddr}->{c.raddr or '-'}",
                fd=c.fd,
                pid=c.pid,
                family=str(c.family),
                type=str(c.type),
                laddr=list(c.laddr) if c.laddr else None,
                raddr=list(c.raddr) if c.raddr else None,
                status=c.status,
            )
        # Routes + ARP via OS-specific commands
        os_ = current_os()
        if os_ == OS.WINDOWS:
            yield self.make(subject="routes", raw=_safe_run(["route", "print"]))
            yield self.make(subject="arp", raw=_safe_run(["arp", "-a"]))
            yield self.make(subject="netstat-ano", raw=_safe_run(["netstat", "-ano"]))
            yield self.make(subject="ipconfig-all", raw=_safe_run(["ipconfig", "/all"]))
        elif os_ == OS.MACOS:
            yield self.make(subject="routes", raw=_safe_run(["netstat", "-rn"]))
            yield self.make(subject="arp", raw=_safe_run(["arp", "-a"]))
            yield self.make(subject="pf-rules", raw=_safe_run(["pfctl", "-sr"]))
            yield self.make(subject="ifconfig", raw=_safe_run(["ifconfig", "-a"]))
        elif os_ == OS.LINUX:
            yield self.make(subject="routes", raw=_safe_run(["ip", "route", "show"]))
            yield self.make(subject="arp", raw=_safe_run(["ip", "neigh", "show"]))
            yield self.make(subject="iptables", raw=_safe_run(["iptables-save"]))
            yield self.make(subject="nftables", raw=_safe_run(["nft", "list", "ruleset"]))
            yield self.make(subject="ss-tunap", raw=_safe_run(["ss", "-tunap"]))
        yield self.make(subject="hostname", hostname=socket.gethostname(), fqdn=socket.getfqdn())
