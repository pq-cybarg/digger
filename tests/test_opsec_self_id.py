"""digger.opsec.self_id — recognizing digger's own process."""

from __future__ import annotations

import os

from digger.opsec.self_id import identify, digger_self_pids


def test_recognizes_python_running_digger():
    sa = identify({
        "pid": 99999, "ppid": 1, "name": "Python",
        "exe": "/opt/homebrew/Cellar/python@3.14/.../Python",
        "cmdline": ["/opt/homebrew/.../Python",
                    "/Users/x/.venv/bin/digger",
                    "--no-banner", "collect", "--case-dir", "/tmp/foo"],
    })
    assert sa is not None
    assert "digger" in sa.lower()
    assert "collect" in sa


def test_recognizes_dash_m_invocation():
    sa = identify({
        "pid": 99998, "ppid": 1, "name": "python3",
        "exe": "/usr/bin/python3",
        "cmdline": ["python3", "-m", "digger.cli", "scan", "--case-dir", "x"],
    })
    assert sa is not None
    assert "digger" in sa.lower()
    assert "scan" in sa


def test_recognizes_direct_digger_invocation():
    sa = identify({
        "pid": 99997, "ppid": 1, "name": "digger",
        "exe": "/usr/local/bin/digger",
        "cmdline": ["digger", "investigate", "--case-dir", "/tmp/foo"],
    })
    assert sa is not None
    assert "digger" in sa.lower()
    assert "investigate" in sa


def test_does_not_match_unrelated_python():
    sa = identify({
        "pid": 99996, "ppid": 1, "name": "python3",
        "exe": "/usr/bin/python3",
        "cmdline": ["python3", "/Users/x/code/myapp/run.py"],
    })
    assert sa is None


def test_self_pid_includes_current():
    pids = digger_self_pids()
    # The test process itself imports digger, so it should be detected
    # via at least the os.getpid() shortcut.
    assert os.getpid() in pids
