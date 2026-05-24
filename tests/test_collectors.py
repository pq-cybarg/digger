"""Smoke tests for cross-platform collectors — ensure they don't crash."""

from __future__ import annotations

from pathlib import Path

from digger.collectors.common.dns import DnsCollector
from digger.collectors.common.env import EnvCollector
from digger.collectors.common.system_info import SystemInfoCollector
from digger.collectors.common.users import UserCollector
from digger.core import EvidenceStore


def _run_collector(collector, tmp_path: Path) -> int:
    with EvidenceStore(tmp_path) as store:
        result = collector.run(store)
        return result.artifacts_collected if not result.skipped else -1


def test_env_collector(tmp_path: Path):
    n = _run_collector(EnvCollector(), tmp_path)
    assert n >= 2  # env + interesting + path


def test_system_info_collector(tmp_path: Path):
    n = _run_collector(SystemInfoCollector(), tmp_path)
    assert n >= 1


def test_users_collector(tmp_path: Path):
    n = _run_collector(UserCollector(), tmp_path)
    assert n >= 1


def test_dns_collector(tmp_path: Path):
    n = _run_collector(DnsCollector(), tmp_path)
    assert n >= 0


def test_all_collectors_loadable():
    """The registry must yield real collector instances for the current OS."""
    from digger.collectors import all_collectors
    cols = all_collectors()
    assert len(cols) > 0
    for c in cols:
        assert c.name
        assert c.category
