"""Installed application inventory."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS, current_os


class InstalledSoftwareCollector(Collector):
    name = "installed_software"
    category = "inventory"
    description = "Native package manager inventories: apt/dpkg, rpm, brew, mas, Windows registry uninstall keys."

    def collect(self) -> Iterable[Artifact]:
        os_ = current_os()
        if os_ == OS.MACOS:
            yield from self._macos()
        elif os_ == OS.LINUX:
            yield from self._linux()
        elif os_ == OS.WINDOWS:
            yield from self._windows()

    def _macos(self):
        # /Applications
        apps_root = Path("/Applications")
        if apps_root.exists():
            apps = []
            for p in apps_root.glob("*.app"):
                info_plist = p / "Contents/Info.plist"
                meta = {}
                if info_plist.exists() and shutil.which("plutil"):
                    try:
                        out = subprocess.run(
                            ["plutil", "-convert", "json", "-o", "-", str(info_plist)],
                            capture_output=True, text=True, timeout=5, check=False,
                        ).stdout
                        meta = json.loads(out) if out else {}
                    except Exception:
                        meta = {}
                apps.append({
                    "path": str(p),
                    "name": p.name,
                    "bundle_id": meta.get("CFBundleIdentifier"),
                    "version": meta.get("CFBundleShortVersionString"),
                    "min_os": meta.get("LSMinimumSystemVersion"),
                })
            yield self.make(subject="applications", count=len(apps), entries=apps)
        # brew
        if shutil.which("brew"):
            try:
                out = subprocess.run(
                    ["brew", "list", "--versions"],
                    capture_output=True, text=True, timeout=30, check=False,
                ).stdout
                yield self.make(subject="brew", raw=out)
            except Exception:
                pass

    def _linux(self):
        if shutil.which("dpkg"):
            out = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"],
                capture_output=True, text=True, timeout=30, check=False,
            ).stdout
            yield self.make(subject="dpkg", raw=out)
        if shutil.which("rpm"):
            out = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{RELEASE}\n"],
                capture_output=True, text=True, timeout=30, check=False,
            ).stdout
            yield self.make(subject="rpm", raw=out)
        if shutil.which("snap"):
            out = subprocess.run(
                ["snap", "list"], capture_output=True, text=True, timeout=15, check=False,
            ).stdout
            yield self.make(subject="snap", raw=out)
        if shutil.which("flatpak"):
            out = subprocess.run(
                ["flatpak", "list"], capture_output=True, text=True, timeout=15, check=False,
            ).stdout
            yield self.make(subject="flatpak", raw=out)

    def _windows(self):
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError:
            return
        keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for hive, sub in keys:
            try:
                with winreg.OpenKey(hive, sub) as k:
                    entries = []
                    for i in range(winreg.QueryInfoKey(k)[0]):
                        try:
                            subkey = winreg.EnumKey(k, i)
                            with winreg.OpenKey(k, subkey) as sk:
                                vals = {}
                                for j in range(winreg.QueryInfoKey(sk)[1]):
                                    n, v, _ = winreg.EnumValue(sk, j)
                                    vals[n] = v
                                entries.append({"id": subkey, **{
                                    k: vals.get(k) for k in (
                                        "DisplayName", "DisplayVersion", "Publisher",
                                        "InstallDate", "InstallLocation", "UninstallString",
                                    )
                                }})
                        except OSError:
                            continue
                    yield self.make(subject=f"uninstall:{sub}", hive=str(hive), entries=entries)
            except OSError:
                continue
