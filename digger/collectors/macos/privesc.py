"""macOS privesc surface: setuid/setgid binaries outside expected paths.

macOS ships its own setuid binaries (most live under ``/usr/bin``,
``/usr/sbin``, ``/usr/libexec``, ``/sbin``, ``/System/``). A setuid
binary outside those is suspicious — admin/developer-built tooling
exists, but it should be reviewed.

We deliberately don't walk ``/System`` because SIP makes those
binaries immutable anyway, and the walk would be slow + noisy.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


_SYSTEM_BIN_DIRS = [
    "/usr/bin", "/usr/sbin", "/usr/libexec",
    "/bin", "/sbin",
    "/opt/homebrew/bin", "/opt/homebrew/sbin",
    "/usr/local/bin", "/usr/local/sbin",
]

_SCRATCH_DIRS = ["/tmp", "/private/tmp", "/var/tmp", "/Users/Shared"]


def _walk_one(root: str, max_files: int = 20000) -> Iterable[Path]:
    seen = 0
    try:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Skip into /System/Volumes/Data (the user-data side) but not
            # into VM-snapshot trees.
            for skip in ("Cryptexes", ".Trashes", "Library/Caches"):
                if skip in dirnames:
                    dirnames.remove(skip)
            for fn in filenames:
                p = Path(dirpath) / fn
                yield p
                seen += 1
                if seen >= max_files:
                    return
    except (PermissionError, OSError):
        return


class MacPrivescSurfaceCollector(Collector):
    name = "macos.privesc"
    category = "privesc_surface"
    supported_os = (OS.MACOS,)
    description = "setuid/setgid binaries inside /usr/ and outside (/tmp, /Users/Shared, /Users/*/, /opt/)."

    def collect(self) -> Iterable[Artifact]:
        for root_dir in _SYSTEM_BIN_DIRS + _SCRATCH_DIRS + ["/Users", "/private/var/root"]:
            if not os.path.isdir(root_dir):
                continue
            for p in _walk_one(root_dir):
                try:
                    st = p.stat()
                except (PermissionError, OSError, FileNotFoundError):
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                mode = st.st_mode
                is_setuid = bool(mode & stat.S_ISUID)
                is_setgid = bool(mode & stat.S_ISGID)
                if not (is_setuid or is_setgid):
                    continue
                world_writable = bool(mode & stat.S_IWOTH)
                yield self.make(
                    subject=f"suid:{p}",
                    path=str(p),
                    owner_uid=st.st_uid,
                    owner_gid=st.st_gid,
                    mode=oct(mode & 0o7777),
                    is_setuid=is_setuid,
                    is_setgid=is_setgid,
                    world_writable=world_writable,
                    size=st.st_size,
                    mtime=st.st_mtime,
                    in_system_dir=any(str(p).startswith(d + "/") for d in _SYSTEM_BIN_DIRS),
                )
