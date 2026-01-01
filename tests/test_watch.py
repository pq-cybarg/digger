"""digger watch continuous-monitoring daemon."""

from __future__ import annotations

import io
from unittest.mock import MagicMock


from digger.watch.daemon import (
    StdoutSink,
    WatchLoop,
    WebhookSink,
    _finding_identity_hash,
    diff_findings,
)


# ---- identity hash + diff ------------------------------------------- #


def _f(**kw):
    base = {"detector": "x", "title": "y", "mitre": "T1",
            "severity": "low", "evidence": {}}
    base.update(kw)
    return base


def test_identity_hash_is_substance_only_not_timestamp():
    a = _f(ts=100)
    b = _f(ts=200)
    assert _finding_identity_hash(a) == _finding_identity_hash(b)


def test_identity_hash_changes_with_detector_or_title():
    a = _f(detector="A")
    b = _f(detector="B")
    assert _finding_identity_hash(a) != _finding_identity_hash(b)
    a2 = _f(title="x")
    b2 = _f(title="y")
    assert _finding_identity_hash(a2) != _finding_identity_hash(b2)


def test_identity_hash_canonicalizes_evidence_dict_order():
    a = _f(evidence={"k1": 1, "k2": 2})
    b = _f(evidence={"k2": 2, "k1": 1})
    assert _finding_identity_hash(a) == _finding_identity_hash(b)


def test_diff_findings_returns_only_new():
    prev = [_f(detector="A"), _f(detector="B")]
    cur = [
        _f(detector="A"),
        _f(detector="B"),
        _f(detector="C"),  # new
    ]
    new, cur_ids = diff_findings(prev, cur)
    assert len(new) == 1
    assert new[0]["detector"] == "C"
    assert len(cur_ids) == 3


def test_diff_findings_empty_previous_returns_all():
    cur = [_f(detector="A"), _f(detector="B")]
    new, ids = diff_findings([], cur)
    assert len(new) == 2
    assert len(ids) == 2


def test_diff_findings_empty_current_returns_none():
    prev = [_f(detector="A")]
    new, ids = diff_findings(prev, [])
    assert new == []
    assert ids == set()


def test_diff_findings_handles_pre_hashed_previous():
    """The loop stores prev as identity hashes only, not full findings.
    The diff function must accept the synthetic-dict form."""
    h = _finding_identity_hash(_f(detector="A"))
    prev_synthetic = [{"_pre_hashed_identity": h}]
    cur = [_f(detector="A"), _f(detector="B")]
    new, _ = diff_findings(prev_synthetic, cur)
    assert len(new) == 1
    assert new[0]["detector"] == "B"


# ---- StdoutSink ---------------------------------------------------- #


def test_stdout_sink_prints_summary_when_findings(capsys):
    sink = StdoutSink()
    sink.emit([_f(detector="x", severity="high", title="bad")], tick=5)
    captured = capsys.readouterr()
    assert "tick 5" in captured.out
    assert "1 NEW finding" in captured.out
    assert "HIGH" in captured.out
    assert "bad" in captured.out


def test_stdout_sink_prints_idle_when_no_findings(capsys):
    StdoutSink().emit([], tick=3)
    captured = capsys.readouterr()
    assert "tick 3" in captured.out
    assert "no new findings" in captured.out


def test_stdout_sink_verbose_includes_evidence(capsys):
    sink = StdoutSink(verbose=True)
    sink.emit([_f(evidence={"key": "value"})], tick=1)
    captured = capsys.readouterr()
    assert "evidence" in captured.out
    assert "value" in captured.out


# ---- WebhookSink --------------------------------------------------- #


def test_webhook_sink_skips_when_no_findings(monkeypatch):
    """Empty batch → no POST at all (avoid spamming Slack with idles)."""
    posts = []
    monkeypatch.setattr("requests.post",
                        lambda *a, **kw: posts.append((a, kw)))
    WebhookSink(url="http://h").emit([], tick=1)
    assert posts == []


def test_webhook_sink_posts_findings(monkeypatch):
    posts = []
    class _Resp:
        status_code = 200
        text = "ok"
    monkeypatch.setattr(
        "requests.post",
        lambda *a, **kw: (posts.append((a, kw)), _Resp())[1],
    )
    sink = WebhookSink(url="https://hooks.example/x")
    sink.emit([_f(detector="trapdoor", severity="critical",
                  title="t", mitre="T1195.001",
                  evidence={"package": "x@1.0"})], tick=7)
    assert len(posts) == 1
    payload = posts[0][1].get("json")
    assert payload["tick"] == 7
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["detector"] == "trapdoor"
    assert payload["findings"][0]["severity"] == "critical"


def test_webhook_sink_swallows_network_errors(monkeypatch):
    """A failing webhook MUST NOT crash the loop."""
    def _boom(*a, **kw):
        raise ConnectionError("network down")
    monkeypatch.setattr("requests.post", _boom)
    stderr = io.StringIO()
    sink = WebhookSink(url="http://h", _stderr=stderr)
    # Should NOT raise
    sink.emit([_f(severity="critical")], tick=1)
    assert "webhook POST failed" in stderr.getvalue()


def test_webhook_sink_handles_requests_missing(monkeypatch):
    """When the requests module isn't importable, fail-soft."""
    import builtins
    real_import = builtins.__import__
    def _no_requests(name, *a, **kw):
        if name == "requests":
            raise ImportError("not available")
        return real_import(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", _no_requests)
    stderr = io.StringIO()
    sink = WebhookSink(url="http://h", _stderr=stderr)
    sink.emit([_f()], tick=1)
    assert "requests not installed" in stderr.getvalue()


# ---- WatchLoop.tick ------------------------------------------------ #


def test_tick_emits_only_new_findings_across_cycles():
    """Two ticks back-to-back: the second tick should NOT re-emit any
    finding that fired in the first."""
    findings_state = {
        1: [_f(detector="trapdoor", title="t1", evidence={"pkg": "a"})],
        2: [
            _f(detector="trapdoor", title="t1", evidence={"pkg": "a"}),  # same
            _f(detector="mini_shai_hulud", title="t2",  # NEW
               evidence={"pkg": "b"}),
        ],
    }
    seen_per_tick: list[list[dict]] = []

    class _CaptureSink:
        def emit(self, findings, tick):
            seen_per_tick.append(list(findings))

    loop = WatchLoop(
        case_dir="/tmp/x",
        sinks=[_CaptureSink()],
        _collect_fn=lambda store, _cs, _only, _admin: None,
        _scan_fn=lambda store, _only: 0,
        _findings_fn=lambda store: findings_state[loop._tick_count],
    )
    # Override store-open to avoid actually opening sqlite
    loop._open_store = lambda: MagicMock()
    loop._close_store = lambda store: None
    loop.tick()
    loop.tick()
    assert len(seen_per_tick) == 2
    assert len(seen_per_tick[0]) == 1  # first tick: 1 finding
    assert seen_per_tick[0][0]["detector"] == "trapdoor"
    assert len(seen_per_tick[1]) == 1  # second tick: ONLY the new one
    assert seen_per_tick[1][0]["detector"] == "mini_shai_hulud"


def test_tick_alert_on_critical_trips_rc():
    """If alert_on includes 'critical', a new critical finding sets
    the alert_tripped flag → run() returns rc=2."""
    findings = [_f(severity="critical", detector="mini_shai_hulud",
                   title="t1")]

    class _NoopSink:
        def emit(self, findings, tick): pass

    loop = WatchLoop(
        case_dir="/tmp/x",
        sinks=[_NoopSink()],
        alert_on={"critical"},
        _collect_fn=lambda store, _cs, _only, _admin: None,
        _scan_fn=lambda store, _only: 0,
        _findings_fn=lambda store: findings,
    )
    loop._open_store = lambda: MagicMock()
    loop._close_store = lambda store: None
    result = loop.tick()
    assert result["alert"] is True
    assert loop._alert_tripped is True


def test_tick_alert_ignores_below_threshold():
    """If alert_on={critical}, a new HIGH finding should NOT trip alert."""
    findings = [_f(severity="high", detector="x", title="t")]

    class _NoopSink:
        def emit(self, findings, tick): pass

    loop = WatchLoop(
        case_dir="/tmp/x", sinks=[_NoopSink()],
        alert_on={"critical"},
        _collect_fn=lambda *_: None,
        _scan_fn=lambda *_: 0,
        _findings_fn=lambda _: findings,
    )
    loop._open_store = lambda: MagicMock()
    loop._close_store = lambda store: None
    result = loop.tick()
    assert result["alert"] is False


def test_tick_alert_high_or_critical_threshold():
    """alert_on={high} should fire on critical too (rank-based)."""
    findings = [_f(severity="critical", detector="x", title="t")]

    class _NoopSink:
        def emit(self, findings, tick): pass

    loop = WatchLoop(
        case_dir="/tmp/x", sinks=[_NoopSink()],
        alert_on={"high"},
        _collect_fn=lambda *_: None,
        _scan_fn=lambda *_: 0,
        _findings_fn=lambda _: findings,
    )
    loop._open_store = lambda: MagicMock()
    loop._close_store = lambda store: None
    result = loop.tick()
    assert result["alert"] is True


def test_tick_with_no_alert_on_never_trips():
    """Empty alert_on → no exit-2 even on critical findings."""
    findings = [_f(severity="critical", detector="x", title="t")]

    class _NoopSink:
        def emit(self, findings, tick): pass

    loop = WatchLoop(
        case_dir="/tmp/x", sinks=[_NoopSink()],
        _collect_fn=lambda *_: None,
        _scan_fn=lambda *_: 0,
        _findings_fn=lambda _: findings,
    )
    loop._open_store = lambda: MagicMock()
    loop._close_store = lambda store: None
    result = loop.tick()
    assert result["alert"] is False
    assert loop._alert_tripped is False


def test_tick_sink_failure_doesnt_kill_loop(capsys):
    """A sink that raises must not crash the tick."""
    class _BadSink:
        def emit(self, findings, tick):
            raise RuntimeError("sink down")

    loop = WatchLoop(
        case_dir="/tmp/x", sinks=[_BadSink()],
        _collect_fn=lambda *_: None,
        _scan_fn=lambda *_: 0,
        _findings_fn=lambda _: [_f(detector="x", title="t")],
    )
    loop._open_store = lambda: MagicMock()
    loop._close_store = lambda store: None
    # Must NOT raise
    loop.tick()
    captured = capsys.readouterr()
    assert "sink failed" in captured.err


# ---- WatchLoop.run ------------------------------------------------- #


def test_run_exits_cleanly_on_stop():
    """stop() during run should exit rc=0 on the next sleep slice."""
    findings_calls = [0]

    class _StopAfterFirst:
        def emit(self, findings, tick):
            findings_calls[0] += 1

    loop = WatchLoop(
        case_dir="/tmp/x",
        interval_s=0.05,
        sinks=[_StopAfterFirst()],
        _collect_fn=lambda *_: None,
        _scan_fn=lambda *_: 0,
        _findings_fn=lambda _: [],
        _sleep_fn=lambda _: None,
    )
    loop._open_store = lambda: MagicMock()
    loop._close_store = lambda store: None
    # Install a sink that triggers stop after the first tick
    class _StopAfterTickSink:
        def emit(self, findings, tick):
            if tick >= 1:
                loop.stop()
    loop.sinks = [_StopAfterTickSink()]
    rc = loop.run()
    assert rc == 0
    assert loop._tick_count >= 1


def test_run_exits_2_when_alert_trips():
    """If alert_on is set and a critical finding fires, run() returns 2."""

    class _StopAfterTickSink:
        def emit(self, findings, tick):
            if tick >= 1:
                loop.stop()

    loop = WatchLoop(
        case_dir="/tmp/x",
        interval_s=0.05,
        sinks=[],
        alert_on={"critical"},
        _collect_fn=lambda *_: None,
        _scan_fn=lambda *_: 0,
        _findings_fn=lambda _: [_f(severity="critical",
                                     detector="mini_shai_hulud",
                                     title="t")],
        _sleep_fn=lambda _: None,
    )
    loop._open_store = lambda: MagicMock()
    loop._close_store = lambda store: None
    loop.sinks = [_StopAfterTickSink()]
    rc = loop.run()
    assert rc == 2


def test_run_keeps_going_on_tick_failure(capsys):
    """If tick raises (e.g. a transient OSError), the loop should
    log and continue."""
    tick_count = [0]

    def _flaky_collect(*a):
        tick_count[0] += 1
        if tick_count[0] == 1:
            raise RuntimeError("transient")

    class _StopAfterTwo:
        def emit(self, findings, tick):
            if tick >= 2:
                loop.stop()

    loop = WatchLoop(
        case_dir="/tmp/x",
        interval_s=0.05,
        sinks=[],
        _collect_fn=_flaky_collect,
        _scan_fn=lambda *_: 0,
        _findings_fn=lambda _: [],
        _sleep_fn=lambda _: None,
    )
    loop._open_store = lambda: MagicMock()
    loop._close_store = lambda store: None
    loop.sinks = [_StopAfterTwo()]
    rc = loop.run()
    captured = capsys.readouterr()
    assert "tick failed" in captured.err
    assert rc == 0  # eventually exits cleanly
    assert tick_count[0] >= 2


# ---- CLI smoke ----------------------------------------------------- #


def test_cli_watch_help_runs():
    import subprocess
    import sys as _sys
    r = subprocess.run(
        [_sys.executable, "-m", "digger", "--no-banner",
         "watch", "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode == 0
    assert "--interval" in r.stdout
    assert "--alert-on" in r.stdout
    assert "--webhook" in r.stdout
