"""User accounts and active sessions."""

from __future__ import annotations

import getpass
import os
from typing import Iterable

import psutil

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS, current_os


class UserCollector(Collector):
    name = "users"
    category = "identity"
    description = "Local accounts, current sessions, sudo group membership."

    def collect(self) -> Iterable[Artifact]:
        yield self.make(
            subject="current-user",
            user=getpass.getuser(),
            uid=os.getuid() if hasattr(os, "getuid") else None,
            gid=os.getgid() if hasattr(os, "getgid") else None,
            home=os.path.expanduser("~"),
        )
        for u in psutil.users():
            yield self.make(
                subject=f"session={u.name}@{u.host or u.terminal}",
                name=u.name,
                terminal=u.terminal,
                host=u.host,
                started=u.started,
                pid=u.pid,
            )
        os_ = current_os()
        if os_ in (OS.MACOS, OS.LINUX):
            try:
                import pwd
                for entry in pwd.getpwall():
                    yield self.make(
                        subject=f"account={entry.pw_name}",
                        user=entry.pw_name,
                        uid=entry.pw_uid,
                        gid=entry.pw_gid,
                        gecos=entry.pw_gecos,
                        home=entry.pw_dir,
                        shell=entry.pw_shell,
                    )
            except Exception:
                pass
            try:
                import grp
                for g in grp.getgrall():
                    if g.gr_name in {"sudo", "wheel", "admin", "_admin"}:
                        yield self.make(
                            subject=f"privgroup={g.gr_name}",
                            group=g.gr_name,
                            gid=g.gr_gid,
                            members=list(g.gr_mem),
                        )
            except Exception:
                pass
