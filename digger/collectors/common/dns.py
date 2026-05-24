"""DNS cache + hosts file."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS, current_os


class DnsCollector(Collector):
    name = "dns"
    category = "network"
    description = "Resolver state: /etc/hosts, DNS cache, configured resolvers."

    def collect(self) -> Iterable[Artifact]:
        os_ = current_os()
        # /etc/hosts (or Windows equivalent)
        hosts_paths = [
            Path("/etc/hosts"),
            Path("C:/Windows/System32/drivers/etc/hosts"),
        ]
        for hp in hosts_paths:
            if hp.exists():
                try:
                    yield self.make(
                        subject=f"hosts:{hp}",
                        path=str(hp),
                        contents=hp.read_text(encoding="utf-8", errors="replace"),
                    )
                except (PermissionError, OSError):
                    pass
        # /etc/resolv.conf on Unix
        rc = Path("/etc/resolv.conf")
        if rc.exists():
            try:
                yield self.make(subject="resolv.conf", contents=rc.read_text(errors="replace"))
            except (PermissionError, OSError):
                pass
        # cache snapshots
        if os_ == OS.WINDOWS and shutil.which("ipconfig"):
            try:
                out = subprocess.run(
                    ["ipconfig", "/displaydns"],
                    capture_output=True, text=True, timeout=15, check=False,
                ).stdout
                yield self.make(subject="dns-cache", raw=out)
            except Exception:
                pass
        elif os_ == OS.MACOS and shutil.which("scutil"):
            try:
                out = subprocess.run(
                    ["scutil", "--dns"],
                    capture_output=True, text=True, timeout=15, check=False,
                ).stdout
                yield self.make(subject="dns-config", raw=out)
            except Exception:
                pass
        elif os_ == OS.LINUX and shutil.which("resolvectl"):
            try:
                out = subprocess.run(
                    ["resolvectl", "status"],
                    capture_output=True, text=True, timeout=15, check=False,
                ).stdout
                yield self.make(subject="dns-config", raw=out)
            except Exception:
                pass
