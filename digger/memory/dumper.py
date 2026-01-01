"""Dump bytes from a live process's memory region.

Permissions:
  * Linux: /proc/[pid]/mem requires CAP_SYS_PTRACE — usually root or
    yama ptrace_scope <= 0. Read-only for own user is sometimes allowed.
  * macOS: no portable way without lldb. We refuse rather than fail
    silently.
  * Windows: ReadProcessMemory needs SeDebugPrivilege (typically admin).
"""

from __future__ import annotations

import sys

from digger.memory.maps import MemoryRegion


def can_dump_pid(pid: int) -> tuple[bool, str]:
    """Return (capable, reason). Side-effect-free."""
    if sys.platform == "linux":
        import os
        try:
            os.stat(f"/proc/{pid}/mem")
        except FileNotFoundError:
            return False, f"/proc/{pid}/mem does not exist"
        except PermissionError:
            return False, f"no permission to open /proc/{pid}/mem (need CAP_SYS_PTRACE)"
        return True, "ok"
    if sys.platform == "darwin":
        return False, "macOS region dumping requires lldb attachment; not supported"
    if sys.platform == "win32":
        # Best-effort — actual ReadProcessMemory may still fail.
        return True, "best-effort via ReadProcessMemory"
    return False, f"unsupported platform: {sys.platform}"


def dump_region(region: MemoryRegion, max_bytes: int = 16 * 1024 * 1024) -> bytes | None:
    """Try to read the bytes of ``region``. Returns None on failure.

    Caps at ``max_bytes`` (default 16 MB) to avoid runaway reads of
    large mapped regions like Chrome's heap.
    """
    if not region.readable:
        return None
    size = min(region.size, max_bytes)

    if sys.platform == "linux":
        return _dump_linux(region.pid, region.start, size)
    if sys.platform == "win32":
        return _dump_windows(region.pid, region.start, size)
    return None


def _dump_linux(pid: int, addr: int, size: int) -> bytes | None:
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as f:
            f.seek(addr)
            return f.read(size)
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _dump_windows(pid: int, addr: int, size: int) -> bytes | None:
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_VM_READ           = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return None
    buf = (ctypes.c_ubyte * size)()
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(read))
    kernel32.CloseHandle(h)
    if not ok:
        return None
    return bytes(buf[:read.value])
