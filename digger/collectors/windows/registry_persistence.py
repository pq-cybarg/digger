"""Common Windows registry persistence locations.

Covers Run/RunOnce, Image File Execution Options, AppInit_DLLs, Winlogon
shells/Userinit, Office trusted locations, COM hijacking surfaces, etc.
Read-only.
"""

from __future__ import annotations

from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS

# (hive, subkey, kind)  — kind is the MITRE ATT&CK technique we tag findings with
PERSISTENCE_KEYS: list[tuple[str, str, str]] = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "T1547.001"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "T1547.001"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "T1547.001"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "T1547.001"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "T1547.001"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "T1547.004"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "T1546.012"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit", "T1546.012"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "T1546.010"),
    ("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager", "T1546.009"),
    ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "T1547.008"),
    ("HKLM", r"SOFTWARE\Classes\CLSID", "T1546.015"),  # huge — sampled
    ("HKCU", r"SOFTWARE\Classes\CLSID", "T1546.015"),
    ("HKLM", r"SOFTWARE\Microsoft\Active Setup\Installed Components", "T1547.014"),
    ("HKLM", r"SOFTWARE\Microsoft\Office\Outlook\Addins", "T1137.006"),
    ("HKLM", r"SOFTWARE\Microsoft\Office\14.0\Excel\Resiliency", "T1137"),
]

_HIVE_MAP = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKU": "HKEY_USERS",
    "HKCR": "HKEY_CLASSES_ROOT",
}


class RegistryPersistenceCollector(Collector):
    name = "windows.registry_persistence"
    category = "persistence"
    supported_os = (OS.WINDOWS,)
    description = "Read-only walk of registry persistence keys (Run, Winlogon, IFEO, COM, Office add-ins)."

    def collect(self) -> Iterable[Artifact]:
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError:
            return
        hkey_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKU": winreg.HKEY_USERS,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
        }
        for hive_name, subkey, mitre in PERSISTENCE_KEYS:
            try:
                with winreg.OpenKey(hkey_map[hive_name], subkey, 0, winreg.KEY_READ) as k:
                    info = winreg.QueryInfoKey(k)
                    n_sub = info[0]
                    n_val = info[1]
                    values = {}
                    for i in range(min(n_val, 200)):
                        try:
                            n, v, _ = winreg.EnumValue(k, i)
                            values[n] = v
                        except OSError:
                            continue
                    subkeys = []
                    for i in range(min(n_sub, 500)):
                        try:
                            subkeys.append(winreg.EnumKey(k, i))
                        except OSError:
                            continue
                    yield self.make(
                        subject=f"{hive_name}\\{subkey}",
                        hive=hive_name,
                        subkey=subkey,
                        mitre=mitre,
                        values=values,
                        subkey_count=n_sub,
                        subkey_sample=subkeys,
                    )
            except OSError:
                continue
