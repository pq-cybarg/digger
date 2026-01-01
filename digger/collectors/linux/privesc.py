"""Linux privesc surface: setuid/setgid binaries + capabilities + kernel taint.

Walks a curated set of directories looking for files with the setuid /
setgid mode bits and reports them. Also captures Linux file
capabilities (``getcap -r``) and kernel taint state.

We deliberately do NOT walk the whole filesystem — that's slow and
noisy. We focus on:

  - System bin dirs (/usr/bin, /usr/sbin, /bin, /sbin, /usr/local/bin, ...)
  - User-writable scratch dirs (/tmp, /var/tmp, /dev/shm)
  - User home directories under /home and /root

A setuid binary outside the system dirs is almost always either a
hand-built admin utility or a planted privesc primitive.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


_SYSTEM_BIN_DIRS = [
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/local/bin", "/usr/local/sbin",
    "/opt",
]

# Scan these for "shouldn't have setuid binaries here" hits.
_SCRATCH_DIRS = ["/tmp", "/var/tmp", "/dev/shm"]


def _walk_one(root: str, max_files: int = 20000) -> Iterable[Path]:
    """Walk ``root`` non-recursively-too-deep, capping at ``max_files``.

    Symlinks are followed for the top level but not chased recursively.
    Failures (perm, gone) are silently skipped.
    """
    seen = 0
    try:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for fn in filenames:
                p = Path(dirpath) / fn
                yield p
                seen += 1
                if seen >= max_files:
                    return
    except (PermissionError, OSError):
        return


class PrivescSurfaceCollector(Collector):
    name = "linux.privesc"
    category = "privesc_surface"
    supported_os = (OS.LINUX,)
    description = "setuid/setgid binaries, file capabilities, kernel taint state."

    def collect(self) -> Iterable[Artifact]:
        # ---- setuid / setgid binaries ----
        for root_dir in _SYSTEM_BIN_DIRS + _SCRATCH_DIRS + ["/home", "/root"]:
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
                # World-writable + setuid = certain privesc primitive
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

        # ---- file capabilities ----
        if shutil.which("getcap"):
            for root_dir in _SYSTEM_BIN_DIRS + ["/home", "/root"]:
                if not os.path.isdir(root_dir):
                    continue
                try:
                    out = subprocess.run(
                        ["getcap", "-r", root_dir],
                        capture_output=True, text=True, timeout=60, check=False,
                    ).stdout
                    if out.strip():
                        yield self.make(
                            subject=f"getcap:{root_dir}",
                            root=root_dir,
                            raw=out,
                        )
                except (subprocess.SubprocessError, OSError):
                    continue

        # ---- kernel taint ----
        taint = Path("/proc/sys/kernel/tainted")
        if taint.exists():
            try:
                v = taint.read_text().strip()
                yield self.make(subject="kernel-tainted", value=v)
            except (PermissionError, OSError):
                pass
