"""Volatility 3 memory-image bridge tests."""

from __future__ import annotations

import json
import subprocess

import pytest

from digger.core.evidence import Artifact, EvidenceStore  # noqa: F401
from digger.volatility.runner import (
    DEFAULT_PLUGINS,
    ScanSummary,
    VolatilityError,
    VolatilityResult,
    _normalize_row,
    _parse_json_rows,
    _row_subject,
    discover_binary,
    image_info,
    run_plugin,
    scan_image,
)


# ---- binary discovery ---- #


def test_discover_binary_honors_env(monkeypatch, tmp_path):
    fake = tmp_path / "vol"
    fake.write_text("#!/bin/sh\necho hi\n")
    fake.chmod(0o755)
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", str(fake))
    assert discover_binary() == str(fake)


def test_discover_binary_env_missing_returns_none(monkeypatch):
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", "/nonexistent/zzz")
    assert discover_binary() is None


def test_discover_binary_path_scan(monkeypatch):
    monkeypatch.delenv("DIGGER_VOLATILITY_BIN", raising=False)
    # Pretend vol3 is on PATH
    monkeypatch.setattr(
        "digger.volatility.runner.shutil.which",
        lambda name: "/usr/local/bin/vol3" if name == "vol3" else None,
    )
    assert discover_binary() == "/usr/local/bin/vol3"


def test_discover_binary_path_scan_misses(monkeypatch):
    monkeypatch.delenv("DIGGER_VOLATILITY_BIN", raising=False)
    monkeypatch.setattr(
        "digger.volatility.runner.shutil.which", lambda name: None,
    )
    assert discover_binary() is None


# ---- JSON parsing ---- #


def test_parse_json_rows_clean_input():
    rows, trunc = _parse_json_rows(json.dumps([
        {"PID": 1, "Name": "init"},
        {"PID": 42, "Name": "node"},
    ]))
    assert rows == [{"PID": 1, "Name": "init"}, {"PID": 42, "Name": "node"}]
    assert trunc is False


def test_parse_json_rows_empty():
    rows, trunc = _parse_json_rows("")
    assert rows == []
    assert trunc is False


def test_parse_json_rows_single_dict_wrapped():
    rows, trunc = _parse_json_rows(json.dumps({"a": 1}))
    assert rows == [{"a": 1}]
    assert trunc is False


def test_parse_json_rows_truncated_recovers_to_last_bracket():
    """If vol3 stdout was truncated, find the largest valid JSON
    array substring."""
    raw = '[{"PID": 1}, {"PID": 2}] some trailing garbage'
    rows, trunc = _parse_json_rows(raw)
    assert rows == [{"PID": 1}, {"PID": 2}]


def test_parse_json_rows_unparseable_marks_truncated():
    rows, trunc = _parse_json_rows("not json at all")
    assert rows == []
    assert trunc is True


# ---- row normalization ---- #


def test_normalize_row_truncates_huge_strings():
    huge = "x" * (10 * 1024)
    out = _normalize_row({"k": huge})
    assert len(out["k"]) < len(huge)
    assert "truncated" in out["k"]


def test_normalize_row_preserves_normal_fields():
    row = {"PID": 1234, "Name": "init", "Path": "/sbin/init"}
    assert _normalize_row(row) == row


# ---- _row_subject ---- #


def test_row_subject_prefers_pid():
    s = _row_subject("windows.pslist", {"PID": 1234, "Name": "lsass.exe"})
    assert s == "PID=1234"


def test_row_subject_falls_back_to_hash():
    s = _row_subject("custom.plugin", {"weird": "shape"})
    assert s.startswith("h=")


# ---- run_plugin ---- #


def test_run_plugin_requires_binary(tmp_path, monkeypatch):
    monkeypatch.delenv("DIGGER_VOLATILITY_BIN", raising=False)
    monkeypatch.setattr(
        "digger.volatility.runner.shutil.which", lambda name: None,
    )
    img = tmp_path / "x.mem"
    img.write_bytes(b"\x00" * 1024)
    with pytest.raises(VolatilityError, match="no Volatility 3 binary"):
        run_plugin(img, "windows.pslist")


def test_run_plugin_rejects_missing_image(monkeypatch, tmp_path):
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN",
                       str(_install_fake_vol(tmp_path)))
    with pytest.raises(VolatilityError, match="image not found"):
        run_plugin(tmp_path / "missing.mem", "windows.pslist")


def _install_fake_vol(tmp_path, *, stdout="[]", rc=0):
    """Drop a tiny fake `vol` binary that emits ``stdout`` and exits
    with ``rc``. Marked executable so subprocess.run finds it."""
    fake = tmp_path / "fake_vol"
    fake.write_text(
        f'#!/bin/sh\nprintf "%s" {json.dumps(stdout)!s}\nexit {rc}\n',
    )
    fake.chmod(0o755)
    return fake


def test_run_plugin_parses_json_rows(monkeypatch, tmp_path):
    rows = [
        {"PID": 1, "Name": "init"},
        {"PID": 42, "Name": "node"},
    ]
    fake = _install_fake_vol(tmp_path, stdout=json.dumps(rows))
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", str(fake))
    img = tmp_path / "x.mem"
    img.write_bytes(b"\x00" * 1024)
    result = run_plugin(img, "windows.pslist")
    assert isinstance(result, VolatilityResult)
    assert result.plugin == "windows.pslist"
    assert result.returncode == 0
    assert result.rows == rows
    assert result.raw_truncated is False


def test_run_plugin_image_size_cap(monkeypatch, tmp_path):
    """Refuse images > 64 GiB by default. We can't make a 64 GiB file
    in a test, so monkey-patch the cap to something tiny and prove
    the gate fires."""
    monkeypatch.setattr(
        "digger.volatility.runner._MAX_IMAGE_BYTES", 100,
    )
    fake = _install_fake_vol(tmp_path)
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", str(fake))
    big = tmp_path / "big.mem"
    big.write_bytes(b"\x00" * 200)
    with pytest.raises(VolatilityError, match="bytes"):
        run_plugin(big, "windows.pslist")


def test_run_plugin_subprocess_failure_returns_nonzero(monkeypatch, tmp_path):
    fake = _install_fake_vol(tmp_path, stdout="", rc=2)
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", str(fake))
    img = tmp_path / "x.mem"
    img.write_bytes(b"\x00" * 1024)
    result = run_plugin(img, "windows.pslist")
    assert result.returncode == 2
    assert result.rows == []


# ---- image_info ---- #


def test_image_info_windows_first(monkeypatch, tmp_path):
    """If windows.info returns rows, that wins immediately."""
    fake = _install_fake_vol(
        tmp_path,
        stdout=json.dumps([{"Variable": "BuildNumber", "Value": "10.0.19045"}]),
    )
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", str(fake))
    img = tmp_path / "x.mem"
    img.write_bytes(b"\x00" * 1024)
    os_name, _ = image_info(img)
    assert os_name == "windows"


def test_image_info_raises_when_nothing_matches(monkeypatch, tmp_path):
    """Empty rows from every info plugin → VolatilityError."""
    fake = _install_fake_vol(tmp_path, stdout="[]")
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", str(fake))
    img = tmp_path / "x.mem"
    img.write_bytes(b"\x00" * 1024)
    with pytest.raises(VolatilityError, match="could not identify"):
        image_info(img)


# ---- scan_image ---- #


def test_scan_image_emits_one_artifact_per_row(monkeypatch, tmp_path):
    rows = [
        {"PID": 1, "Name": "init"},
        {"PID": 42, "Name": "node"},
        {"PID": 100, "Name": "sshd"},
    ]
    fake = _install_fake_vol(tmp_path, stdout=json.dumps(rows))
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", str(fake))
    img = tmp_path / "x.mem"
    img.write_bytes(b"\x00" * 1024)
    store = EvidenceStore(tmp_path / "case")

    # Provide explicit os + a single plugin to avoid the image_info
    # plumbing in the test
    summary = scan_image(
        img, store, os_name="windows", plugins=["windows.pslist"],
    )
    assert isinstance(summary, ScanSummary)
    assert summary.plugins_run == 1
    assert summary.plugins_failed == 0
    assert summary.rows_emitted == 3

    arts = list(store.iter_artifacts(collector="volatility:windows.pslist"))
    assert len(arts) == 3
    assert arts[0]["category"] == "memory"
    assert arts[0]["data"]["vol_plugin"] == "windows.pslist"
    assert arts[0]["data"]["row"]["PID"] == 1
    # PID is the subject anchor
    pids = sorted(int(a["subject"].split("=")[-1]) for a in arts)
    assert pids == [1, 42, 100]
    store.close()


def test_scan_image_tracks_failures(monkeypatch, tmp_path):
    """Plugin with non-zero rc still completes the scan; summary
    increments plugins_failed."""
    fake = _install_fake_vol(tmp_path, stdout="", rc=3)
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", str(fake))
    img = tmp_path / "x.mem"
    img.write_bytes(b"\x00" * 1024)
    store = EvidenceStore(tmp_path / "case")
    summary = scan_image(
        img, store, os_name="windows", plugins=["windows.pslist"],
    )
    assert summary.plugins_run == 1
    assert summary.plugins_failed == 1
    assert summary.rows_emitted == 0
    store.close()


def test_scan_image_uses_default_plugins_when_none(monkeypatch, tmp_path):
    """Without --plugins, scan_image picks DEFAULT_PLUGINS[os]."""
    fake = _install_fake_vol(tmp_path, stdout=json.dumps([{"PID": 1}]))
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", str(fake))
    img = tmp_path / "x.mem"
    img.write_bytes(b"\x00" * 1024)
    store = EvidenceStore(tmp_path / "case")
    summary = scan_image(img, store, os_name="linux")
    # Every Linux default plugin should have been executed
    assert summary.plugins_run == len(DEFAULT_PLUGINS["linux"])
    store.close()


def test_scan_image_rejects_unknown_os_yields_empty_plugin_list(
    monkeypatch, tmp_path,
):
    """An os_name not in DEFAULT_PLUGINS still runs (with zero plugins)
    rather than crashing — caller may have a custom plugin list."""
    fake = _install_fake_vol(tmp_path, stdout="[]")
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", str(fake))
    img = tmp_path / "x.mem"
    img.write_bytes(b"\x00" * 1024)
    store = EvidenceStore(tmp_path / "case")
    summary = scan_image(img, store, os_name="esxi")
    assert summary.plugins_run == 0
    assert summary.rows_emitted == 0
    store.close()


# ---- CLI smoke ---- #


def test_cli_vol_info_lists_plugins_without_image(monkeypatch, tmp_path):
    """Without --image, `vol info` just prints the curated plugin set
    (assuming a vol binary exists)."""
    import sys as _sys
    fake = _install_fake_vol(tmp_path, stdout="[]")
    monkeypatch.setenv("DIGGER_VOLATILITY_BIN", str(fake))
    import os
    env = {**os.environ, "DIGGER_VOLATILITY_BIN": str(fake)}
    r = subprocess.run(
        [_sys.executable, "-m", "digger", "--no-banner",
         "vol", "info"],
        capture_output=True, text=True, timeout=20, env=env,
    )
    assert r.returncode == 0, r.stderr
    assert "windows plugins" in r.stdout
    assert "linux plugins" in r.stdout
    assert "mac plugins" in r.stdout
    assert "windows.pslist" in r.stdout


def test_cli_vol_info_without_binary():
    import os
    import sys as _sys
    env = {k: v for k, v in os.environ.items()
           if k != "DIGGER_VOLATILITY_BIN"}
    env["DIGGER_VOLATILITY_BIN"] = "/nonexistent/zzz/vol"
    env["PATH"] = "/usr/local/bin"  # narrow PATH to miss any vol
    r = subprocess.run(
        [_sys.executable, "-m", "digger", "--no-banner",
         "vol", "info"],
        capture_output=True, text=True, timeout=20, env=env,
    )
    assert r.returncode == 1
    assert "no Volatility 3 binary" in r.stderr
