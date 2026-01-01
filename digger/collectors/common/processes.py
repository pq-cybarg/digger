"""Snapshot of every running process: cmdline, parent, user, exe hash, open files."""

from __future__ import annotations

import hashlib
import os
from typing import Iterable

import psutil

from digger.core.collector import Collector
from digger.core.evidence import Artifact

# Limit per-process hash work so a 4GB binary doesn't stall collection.
_MAX_HASH_BYTES = 200 * 1024 * 1024


def _hash_exe(path: str | None) -> str | None:
    if not path or not os.path.isfile(path):
        return None
    try:
        if os.path.getsize(path) > _MAX_HASH_BYTES:
            return f"skipped-large-file:{os.path.getsize(path)}"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                buf = f.read(1 << 20)
                if not buf:
                    break
                h.update(buf)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None


class ProcessCollector(Collector):
    name = "processes"
    category = "process"
    description = "Live process tree with cmdline, parents, exe hash, open files, connections."

    def collect(self) -> Iterable[Artifact]:
        attrs = [
            "pid", "ppid", "name", "exe", "cmdline", "username",
            "create_time", "status", "cwd", "uids", "gids",
            "num_threads", "nice", "terminal",
        ]
        for proc in psutil.process_iter(attrs=attrs):
            info = proc.info
            try:
                conns = [
                    {
                        "fd": c.fd,
                        "family": str(c.family),
                        "type": str(c.type),
                        "laddr": list(c.laddr) if c.laddr else None,
                        "raddr": list(c.raddr) if c.raddr else None,
                        "status": c.status,
                    }
                    for c in proc.net_connections(kind="inet")
                ]
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                conns = []
            try:
                open_files = [f.path for f in proc.open_files()][:200]
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                open_files = []
            try:
                env = dict(list(proc.environ().items())[:50])
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                env = {}
            yield self.make(
                subject=f"pid={info.get('pid')} {info.get('name')}",
                pid=info.get("pid"),
                ppid=info.get("ppid"),
                name=info.get("name"),
                exe=info.get("exe"),
                exe_sha256=_hash_exe(info.get("exe")),
                cmdline=info.get("cmdline"),
                username=info.get("username"),
                create_time=info.get("create_time"),
                status=info.get("status"),
                cwd=info.get("cwd"),
                num_threads=info.get("num_threads"),
                nice=info.get("nice"),
                terminal=info.get("terminal"),
                connections=conns,
                open_files=open_files,
                env_sample=env,
            )
