"""Android device forensics via adb (Android Debug Bridge).

Connects to a USB-attached or network-bridged Android device, pulls
the package list, dumpsys snapshots, and selected /system metadata,
then emits Artifacts for the ``AndroidSecurityDetector`` to consume.

Design notes
------------
- Strictly read-only. adb is invoked with shell commands that
  *enumerate* state; nothing is written to the device.
- The operator must enable adb-debugging and authorize the host
  pairing themselves; we do not push apks, change settings, or
  pull non-public files. The forensic stance is "what the user's
  device sees about itself."
- Graceful degradation: if no adb binary, no device attached, or
  the device is offline, the collector emits zero Artifacts (does
  not raise).

Public API
----------
``collect_device(case_dir, *, serial=None, binary=None)``
``discover_binary()``
``AdbError``
``AndroidPackage`` / ``AndroidCollectSummary``
"""

from __future__ import annotations

from digger.android.collector import (
    AdbError,
    AndroidCollectSummary,
    AndroidPackage,
    collect_device,
    discover_binary,
    parse_dumpsys_package,
    parse_pm_list_packages,
)

__all__ = [
    "AdbError",
    "AndroidCollectSummary",
    "AndroidPackage",
    "collect_device",
    "discover_binary",
    "parse_dumpsys_package",
    "parse_pm_list_packages",
]
