"""Cross-platform memory-region enumeration.

Returns a list of ``MemoryRegion`` per pid. Each region carries:

  start / end / size      — virtual address range and size in bytes
  perms                   — permission string: r-?-x-?-w-?p|s
  readable/writable/executable/private  — booleans
  offset                  — file offset for file-backed regions
  backing                 — file path, "[heap]" / "[stack]" / "[anon]" /
                            "[anonymous-rwx]" / module name etc.
  is_anonymous_exec       — executable but no on-disk backing → shellcode tell
  is_rwx                  — read+write+execute simultaneously → injection tell
  is_backing_in_drop      — file-backed region whose path lives in /tmp,
                            /Users/Shared, AppData/Local/Temp etc.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Iterable


_DROP_PATHS = ("/tmp/", "/var/tmp/", "/dev/shm/",
               "/Users/Shared/", "/private/tmp/",
               "\\Temp\\", "\\AppData\\Local\\Temp\\",
               "\\Users\\Public\\")


@dataclass
class MemoryRegion:
    pid: int
    start: int
    end: int
    perms: str
    offset: int
    backing: str
    private: bool = True

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def readable(self) -> bool:
        return "r" in self.perms

    @property
    def writable(self) -> bool:
        return "w" in self.perms

    @property
    def executable(self) -> bool:
        return "x" in self.perms

    @property
    def is_anonymous_exec(self) -> bool:
        return self.executable and (not self.backing or self.backing.startswith("["))

    @property
    def is_rwx(self) -> bool:
        return self.readable and self.writable and self.executable

    @property
    def is_backing_in_drop(self) -> bool:
        if not self.backing or self.backing.startswith("["):
            return False
        return any(p in self.backing for p in _DROP_PATHS)

    def to_dict(self) -> dict:
        return {
            "pid":               self.pid,
            "start":             f"0x{self.start:x}",
            "end":               f"0x{self.end:x}",
            "size":              self.size,
            "perms":             self.perms,
            "offset":            self.offset,
            "backing":           self.backing,
            "private":           self.private,
            "readable":          self.readable,
            "writable":          self.writable,
            "executable":        self.executable,
            "is_anonymous_exec": self.is_anonymous_exec,
            "is_rwx":            self.is_rwx,
            "is_backing_in_drop":self.is_backing_in_drop,
        }


# ---- platform parsers --------------------------------------------------- #


# Linux /proc/[pid]/maps line:
#   563f72e8c000-563f72e8d000 r-xp 00000000 fe:00 12345  /usr/bin/cat
_LINUX_MAPS_LINE = re.compile(
    r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(\S+)\s+([0-9a-fA-F]+)\s+\S+\s+\d+\s*(.*)$"
)


def _parse_linux_maps(pid: int) -> list[MemoryRegion]:
    path = f"/proc/{pid}/maps"
    try:
        with open(path) as f:
            lines = f.readlines()
    except (FileNotFoundError, PermissionError, OSError):
        return []
    out: list[MemoryRegion] = []
    for line in lines:
        m = _LINUX_MAPS_LINE.match(line)
        if not m:
            continue
        start = int(m.group(1), 16)
        end   = int(m.group(2), 16)
        perms = m.group(3)
        offset = int(m.group(4), 16)
        backing = (m.group(5) or "").strip() or "[anon]"
        private = perms.endswith("p")
        out.append(MemoryRegion(
            pid=pid, start=start, end=end, perms=perms,
            offset=offset, backing=backing, private=private,
        ))
    return out


# macOS vmmap output:
#   __TEXT      000000010be91000-000000010beae000 [   116K   116K     0K     0K] r-x/r-x SM=COW  /usr/bin/grep
_MACOS_VMMAP_LINE = re.compile(
    r"^\S+\s+([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+\[.*?\]\s+([rwx-]{3}/[rwx-]{3})\s+SM=\S+\s*(.*)$"
)


def _parse_macos_vmmap(pid: int) -> list[MemoryRegion]:
    if not shutil.which("vmmap"):
        return []
    try:
        r = subprocess.run(
            ["vmmap", "-interleaved", str(pid)],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return []
    out: list[MemoryRegion] = []
    for line in r.stdout.splitlines():
        m = _MACOS_VMMAP_LINE.match(line)
        if not m:
            continue
        start = int(m.group(1), 16)
        end   = int(m.group(2), 16)
        # vmmap shows current/max perms — use current.
        cur_perms = m.group(3).split("/")[0]
        # Translate to a Linux-style perms string for uniformity.
        perms = (
            ("r" if "r" in cur_perms else "-") +
            ("w" if "w" in cur_perms else "-") +
            ("x" if "x" in cur_perms else "-") +
            "p"
        )
        rest = (m.group(4) or "").strip()
        backing = rest or "[anon]"
        out.append(MemoryRegion(
            pid=pid, start=start, end=end, perms=perms,
            offset=0, backing=backing, private=True,
        ))
    return out


# Windows: use ctypes for VirtualQueryEx + OpenProcess.
def _parse_windows(pid: int) -> list[MemoryRegion]:
    if sys.platform != "win32":
        return []
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return []

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ           = 0x0010

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress",       ctypes.c_void_p),
            ("AllocationBase",    ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize",        ctypes.c_size_t),
            ("State",             wintypes.DWORD),
            ("Protect",           wintypes.DWORD),
            ("Type",              wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi    = ctypes.WinDLL("psapi", use_last_error=True)

    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return []

    PAGE_EXECUTE         = 0x10
    PAGE_EXECUTE_READ    = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_READONLY        = 0x02
    PAGE_READWRITE       = 0x04
    PAGE_WRITECOPY       = 0x08

    def _perms(protect: int) -> str:
        x = "x" if protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) else "-"
        r = "r" if protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                              PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) else "-"
        w = "w" if protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) else "-"
        return f"{r}{w}{x}p"

    MEM_COMMIT = 0x1000
    MEM_FREE   = 0x10000

    out: list[MemoryRegion] = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while True:
        ret = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                       ctypes.byref(mbi),
                                       ctypes.sizeof(mbi))
        if ret == 0:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if mbi.State == MEM_COMMIT:
            # Try to resolve a backing module
            backing = "[anon]"
            try:
                buf = ctypes.create_unicode_buffer(260)
                n = psapi.GetMappedFileNameW(h, ctypes.c_void_p(base), buf, 260)
                if n > 0:
                    backing = buf.value
            except Exception:
                pass
            out.append(MemoryRegion(
                pid=pid, start=base, end=base + size,
                perms=_perms(mbi.Protect), offset=0,
                backing=backing, private=True,
            ))
        if base + size <= addr:
            break
        addr = base + size
    kernel32.CloseHandle(h)
    return out


# ---- public API --------------------------------------------------------- #


def list_regions_for_pid(pid: int) -> list[MemoryRegion]:
    if sys.platform == "linux":
        return _parse_linux_maps(pid)
    if sys.platform == "darwin":
        return _parse_macos_vmmap(pid)
    if sys.platform == "win32":
        return _parse_windows(pid)
    return []


def list_regions_for_all_pids(*, limit: int | None = None) -> dict[int, list[MemoryRegion]]:
    """Best-effort regions for every PID we can read."""
    try:
        import psutil
    except ImportError:
        return {}
    out: dict[int, list[MemoryRegion]] = {}
    for proc in psutil.process_iter(attrs=["pid"]):
        try:
            pid = proc.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        regions = list_regions_for_pid(pid)
        if regions:
            out[pid] = regions
        if limit and len(out) >= limit:
            break
    return out
