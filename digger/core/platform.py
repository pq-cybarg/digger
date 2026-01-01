"""Platform detection and privilege checks."""

from __future__ import annotations

import ctypes
import os
import platform
import sys
from enum import Enum


class OS(str, Enum):
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    UNKNOWN = "unknown"


def current_os() -> OS:
    s = platform.system().lower()
    if s == "windows":
        return OS.WINDOWS
    if s == "darwin":
        return OS.MACOS
    if s == "linux":
        return OS.LINUX
    return OS.UNKNOWN


def is_admin() -> bool:
    """True if running with elevated privileges (root / Administrator)."""
    if current_os() == OS.WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def host_fingerprint() -> dict:
    """Stable identifying info about the host for the evidence record."""
    return {
        "os": current_os().value,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "node": platform.node(),
        "python": sys.version.split()[0],
        "release": platform.release(),
        "version": platform.version(),
        "processor": platform.processor(),
        "admin": is_admin(),
    }
