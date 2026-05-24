"""Collector registry. Imports lazily to avoid pulling platform-specific deps."""

from __future__ import annotations

from typing import Callable, Iterable

from digger.core.collector import Collector
from digger.core.platform import OS, current_os


def all_collectors(include_admin: bool = True) -> list[Collector]:
    """Return every collector relevant to the current OS."""
    out: list[Collector] = []
    out.extend(_common())
    os_ = current_os()
    if os_ == OS.WINDOWS:
        out.extend(_windows())
    elif os_ == OS.MACOS:
        out.extend(_macos())
    elif os_ == OS.LINUX:
        out.extend(_linux())
    if not include_admin:
        out = [c for c in out if not c.requires_admin]
    return out


def _common() -> list[Collector]:
    from digger.collectors.common.processes import ProcessCollector
    from digger.collectors.common.network import NetworkCollector
    from digger.collectors.common.users import UserCollector
    from digger.collectors.common.browsers import BrowserCollector
    from digger.collectors.common.system_info import SystemInfoCollector
    from digger.collectors.common.env import EnvCollector
    from digger.collectors.common.dns import DnsCollector
    from digger.collectors.common.recent_files import RecentFilesCollector
    from digger.collectors.common.installed_software import InstalledSoftwareCollector
    from digger.collectors.common.python_packages import PythonPackagesCollector
    from digger.collectors.common.npm_packages import NpmPackagesCollector
    from digger.collectors.common.ssh_keys import SshKeysCollector
    from digger.collectors.common.github_workflows import GithubWorkflowsCollector
    from digger.collectors.common.service_versions import ServiceVersionsCollector
    from digger.memory.collector import MemoryRegionsCollector
    from digger.signing.collector import CodeSigningCollector
    return [
        SystemInfoCollector(),
        ProcessCollector(),
        NetworkCollector(),
        UserCollector(),
        BrowserCollector(),
        EnvCollector(),
        DnsCollector(),
        RecentFilesCollector(),
        InstalledSoftwareCollector(),
        PythonPackagesCollector(),
        NpmPackagesCollector(),
        SshKeysCollector(),
        GithubWorkflowsCollector(),
        ServiceVersionsCollector(),
        MemoryRegionsCollector(),
        CodeSigningCollector(),
    ]


def _windows() -> list[Collector]:
    from digger.collectors.windows.registry_persistence import RegistryPersistenceCollector
    from digger.collectors.windows.scheduled_tasks import ScheduledTasksCollector
    from digger.collectors.windows.services import ServicesCollector
    from digger.collectors.windows.event_logs import EventLogCollector
    from digger.collectors.windows.defender import DefenderCollector
    from digger.collectors.windows.firewall import FirewallCollector
    from digger.collectors.windows.wmi_persistence import WmiPersistenceCollector
    from digger.collectors.windows.startup import StartupFoldersCollector
    return [
        RegistryPersistenceCollector(),
        ScheduledTasksCollector(),
        ServicesCollector(),
        EventLogCollector(),
        DefenderCollector(),
        FirewallCollector(),
        WmiPersistenceCollector(),
        StartupFoldersCollector(),
    ]


def _macos() -> list[Collector]:
    from digger.collectors.macos.launchd import LaunchdCollector
    from digger.collectors.macos.login_items import LoginItemsCollector
    from digger.collectors.macos.tcc import TccCollector
    from digger.collectors.macos.quarantine import QuarantineCollector
    from digger.collectors.macos.unified_logs import UnifiedLogsCollector
    from digger.collectors.macos.kext import KextCollector
    from digger.collectors.macos.profiles import ProfilesCollector
    from digger.collectors.macos.security_posture import SecurityPostureCollector
    from digger.collectors.macos.firewall import MacFirewallCollector
    from digger.collectors.macos.privesc import MacPrivescSurfaceCollector
    return [
        LaunchdCollector(),
        LoginItemsCollector(),
        TccCollector(),
        QuarantineCollector(),
        UnifiedLogsCollector(),
        KextCollector(),
        ProfilesCollector(),
        SecurityPostureCollector(),
        MacFirewallCollector(),
        MacPrivescSurfaceCollector(),
    ]


def _linux() -> list[Collector]:
    from digger.collectors.linux.systemd import SystemdCollector
    from digger.collectors.linux.cron import CronCollector
    from digger.collectors.linux.auth_logs import AuthLogsCollector
    from digger.collectors.linux.audit import AuditCollector
    from digger.collectors.linux.kmod import KmodCollector
    from digger.collectors.linux.sudoers import SudoersCollector
    from digger.collectors.linux.firewall import LinuxFirewallCollector
    from digger.collectors.linux.privesc import PrivescSurfaceCollector
    return [
        SystemdCollector(),
        CronCollector(),
        AuthLogsCollector(),
        AuditCollector(),
        KmodCollector(),
        SudoersCollector(),
        LinuxFirewallCollector(),
        PrivescSurfaceCollector(),
    ]
