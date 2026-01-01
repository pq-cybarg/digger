"""Host fingerprint, boot time, uptime, mounted filesystems, sensors."""

from __future__ import annotations

import platform
import time
from typing import Iterable

import psutil

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import host_fingerprint


class SystemInfoCollector(Collector):
    name = "system"
    category = "host"
    description = "Host identity, boot time, uptime, filesystems, hardware summary."

    def collect(self) -> Iterable[Artifact]:
        yield self.make(subject="host", **host_fingerprint())
        boot = psutil.boot_time()
        yield self.make(
            subject="boot",
            boot_time=boot,
            uptime_seconds=time.time() - boot,
        )
        try:
            partitions = []
            for p in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(p.mountpoint)
                    partitions.append({
                        "device": p.device,
                        "mountpoint": p.mountpoint,
                        "fstype": p.fstype,
                        "opts": p.opts,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                    })
                except (PermissionError, OSError):
                    partitions.append({
                        "device": p.device,
                        "mountpoint": p.mountpoint,
                        "fstype": p.fstype,
                        "opts": p.opts,
                    })
            yield self.make(subject="filesystems", count=len(partitions), entries=partitions)
        except Exception:
            pass
        try:
            yield self.make(
                subject="cpu",
                logical=psutil.cpu_count(),
                physical=psutil.cpu_count(logical=False),
                processor=platform.processor(),
                arch=platform.machine(),
            )
            mem = psutil.virtual_memory()
            yield self.make(
                subject="memory",
                total=mem.total,
                available=mem.available,
                percent=mem.percent,
            )
        except Exception:
            pass
