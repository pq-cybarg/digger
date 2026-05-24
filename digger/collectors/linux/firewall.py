"""Linux firewall posture: try nftables → iptables → ufw → firewalld.

We collect from every backend that's installed (not just the active one),
because multiple frontends can be configured simultaneously and audit
should warn when that happens.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


def _run(cmd: list[str], timeout: int = 15) -> str:
    if not shutil.which(cmd[0]):
        return ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return r.stdout or r.stderr or ""
    except (subprocess.SubprocessError, OSError):
        return ""


class LinuxFirewallCollector(Collector):
    name = "linux.firewall"
    category = "security_posture"
    supported_os = (OS.LINUX,)
    description = "nftables ruleset, iptables/ip6tables-save, ufw status, firewalld zones."

    def collect(self) -> Iterable[Artifact]:
        nft = _run(["nft", "list", "ruleset"])
        if nft:
            yield self.make(
                subject="nftables-ruleset",
                backend="nftables",
                raw=nft,
            )

        ipt = _run(["iptables-save"])
        if ipt:
            yield self.make(
                subject="iptables-save",
                backend="iptables",
                raw=ipt,
            )

        ip6 = _run(["ip6tables-save"])
        if ip6:
            yield self.make(
                subject="ip6tables-save",
                backend="iptables",
                raw=ip6,
            )

        ufw = _run(["ufw", "status", "verbose"])
        if ufw:
            yield self.make(
                subject="ufw-status",
                backend="ufw",
                raw=ufw,
            )

        fwd = _run(["firewall-cmd", "--list-all-zones"])
        if fwd:
            yield self.make(
                subject="firewalld-zones",
                backend="firewalld",
                raw=fwd,
            )
