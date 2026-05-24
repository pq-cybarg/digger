"""In-memory forensics — VM region inspection, anomaly detection, YARA scans.

A snapshot tool can still get a lot of mileage out of memory inspection:

  * Anonymous executable regions      — shellcode landing pads
  * RWX regions                       — process injection signal
  * Libraries loaded from /tmp        — sideloaded malicious dylibs
  * Hollow exe                        — main module memory disagrees with disk
  * YARA hits on dumped regions       — known-bad payloads in RAM

We do not attempt full Volatility-grade memory analysis (that needs a
saved memory image and a profile). Instead we read live process memory
maps and, where permissions allow, dump suspicious regions for YARA.

Cross-platform support:

  Linux   — /proc/[pid]/maps (region list, freely readable for own user;
            most processes for root). /proc/[pid]/mem for actual bytes
            (needs CAP_SYS_PTRACE / root / yama ptrace_scope=0).
  macOS   — vmmap(1) for region info (works without elevation for own
            user). No portable byte read without lldb attaching, so we
            stop at region anomaly detection.
  Windows — best-effort via ctypes: OpenProcess +
            VirtualQueryEx for regions. ReadProcessMemory needs
            SeDebugPrivilege.
"""

from digger.memory.maps import (
    MemoryRegion, list_regions_for_pid, list_regions_for_all_pids,
)
from digger.memory.collector import MemoryRegionsCollector
from digger.memory.detector import MemoryAnomalyDetector
from digger.memory.dumper import dump_region, can_dump_pid
from digger.memory.scanner import yara_scan_region

__all__ = [
    "MemoryRegion", "list_regions_for_pid", "list_regions_for_all_pids",
    "MemoryRegionsCollector", "MemoryAnomalyDetector",
    "dump_region", "can_dump_pid", "yara_scan_region",
]
