#!/usr/bin/env python3
"""wipe-birthtimes — reset APFS file birthtime (+ mtime + atime) to a sentinel.

Used by `tools/opsec/install.sh` consumers who want full filesystem
timestamp cleansing on top of what the post-commit hook does.

Why this is its own tool (instead of being in the hook):
  - The post-commit hook can only touch mtime/atime via `touch -t`,
    which leaves APFS birthtime alone. A forensic walker that
    inspects creation time can still timeline the file's first
    appearance.
  - The only modern macOS API that mutates btime is
    setattrlist(2) with ATTR_CMN_CRTIME. There's no shell wrapper
    for it — Apple deprecated SetFile from Xcode Command Line
    Tools in recent macOS. So we go through ctypes.
  - btime mutation is more destructive than touch (changes inode
    attributes in a way some tools cache), so we keep it opt-in:
    operator runs it manually when they explicitly want it.

Usage:
  ./tools/opsec/wipe-birthtimes.py                    # all tracked files
  ./tools/opsec/wipe-birthtimes.py path/to/file ...   # specific paths

Configuration (env vars, same as post-commit-cleanse for symmetry):
  DIGGER_CLEANSE_DATE  — ISO date for the sentinel
                         (default 2026-01-01T00:00:00+0000)

Caveats:
  - Requires macOS. Linux exFAT doesn't have btime in the syscall
    API the same way.
  - Run as the owner of the files. setattrlist on root-owned
    files needs sudo.
  - The local reflog still records real wallclock. Run
    `git reflog expire --expire=now --all` for forensic-grade
    cleansing of the reflog too.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import subprocess
import sys
from datetime import datetime


# ---- setattrlist(2) bindings (from <sys/attr.h>) ---- #

ATTR_BIT_MAP_COUNT = 5
ATTR_CMN_MODTIME   = 0x00000400
ATTR_CMN_ACCTIME   = 0x00001000
ATTR_CMN_CRTIME    = 0x00000200

FSOPT_NOFOLLOW = 0x1


class attrlist(ctypes.Structure):
    _fields_ = [
        ("bitmapcount", ctypes.c_ushort),
        ("reserved",    ctypes.c_ushort),
        ("commonattr",  ctypes.c_uint),
        ("volattr",     ctypes.c_uint),
        ("dirattr",     ctypes.c_uint),
        ("fileattr",    ctypes.c_uint),
        ("forkattr",    ctypes.c_uint),
    ]


class timespec(ctypes.Structure):
    _fields_ = [
        ("tv_sec",  ctypes.c_long),
        ("tv_nsec", ctypes.c_long),
    ]


_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_setattrlist = _libc.setattrlist
_setattrlist.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(attrlist),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_ulong,
]
_setattrlist.restype = ctypes.c_int


def set_all_times(path: str, sentinel: float) -> None:
    """Set birthtime + mtime + atime on ``path`` to ``sentinel``
    (unix-seconds). Order in the buffer matches the bit order of
    commonattr — Apple's setattrlist groups bits by category and
    within-category by bit number, so:
      ATTR_CMN_CRTIME   = 0x0200  (bit 9)
      ATTR_CMN_MODTIME  = 0x0400  (bit 10)
      ATTR_CMN_ACCTIME  = 0x1000  (bit 12)
    The data array is laid out in increasing bit order:
      [0] = crtime (bit 9)
      [1] = modtime (bit 10)
      [2] = acctime (bit 12)
    """
    al = attrlist(
        bitmapcount=ATTR_BIT_MAP_COUNT,
        reserved=0,
        commonattr=ATTR_CMN_CRTIME | ATTR_CMN_MODTIME | ATTR_CMN_ACCTIME,
        volattr=0, dirattr=0, fileattr=0, forkattr=0,
    )
    sec  = int(sentinel)
    nsec = int((sentinel - sec) * 1_000_000_000)
    buf = (timespec * 3)()
    for i in range(3):
        buf[i].tv_sec  = sec
        buf[i].tv_nsec = nsec
    rc = _setattrlist(
        path.encode("utf-8"),
        ctypes.byref(al),
        buf,
        ctypes.sizeof(buf),
        FSOPT_NOFOLLOW,
    )
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), path)


def _parse_sentinel(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        capture_output=True, check=True,
    ).stdout
    return [f for f in out.decode("utf-8", errors="replace").split("\x00") if f]


def main(argv: list[str]) -> int:
    if sys.platform != "darwin":
        print("  ✗ macOS only (setattrlist is darwin-specific)",
              file=sys.stderr)
        return 1

    sentinel_iso = os.environ.get(
        "DIGGER_CLEANSE_DATE", "2026-01-01T00:00:00+0000",
    )
    try:
        sentinel = _parse_sentinel(sentinel_iso)
    except ValueError as exc:
        print(f"  ✗ bad DIGGER_CLEANSE_DATE={sentinel_iso!r}: {exc}",
              file=sys.stderr)
        return 1

    if argv:
        files = argv
    else:
        try:
            files = _tracked_files()
        except subprocess.CalledProcessError:
            print("  ✗ not inside a git repo; pass file paths "
                  "explicitly to operate outside git",
                  file=sys.stderr)
            return 1

    ok = 0
    err = 0
    for f in files:
        if not os.path.exists(f):
            continue
        try:
            set_all_times(f, sentinel)
            ok += 1
        except OSError as exc:
            err += 1
            print(f"  ✗ {f}: {exc}", file=sys.stderr)

    print(f"  ✓ btime + mtime + atime set to {sentinel_iso} on {ok} file(s)")
    if err:
        print(f"  ⚠ {err} failure(s) — see stderr above", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
