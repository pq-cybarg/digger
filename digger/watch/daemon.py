"""Watch-loop core: collect → scan → diff → emit, on a timer.

Single-host monitor pattern. Each tick:

  1. Run collectors (subset, configurable)
  2. Run detectors over the fresh artifacts
  3. Diff resulting findings against the previous tick's set
  4. Emit only the NEW findings to each registered sink
  5. Sleep until next tick (or exit on signal)

Stable-finding identity: a finding is "new" if its (detector, title,
mitre, evidence-canonical-hash) tuple was not present in the previous
tick. We deliberately do NOT use the chain hash because triage might
mutate the finding metadata between ticks; the identity hash is over
the *substance* of the finding, not its serialized form.

Signal handling
---------------
SIGINT and SIGTERM are caught and trip the loop's stop flag so the
current tick finishes cleanly. The loop exits with rc=0 on graceful
shutdown, rc=2 on alert-severity threshold (caller can wire to
systemd/launchd Restart=on-failure for re-launch).
"""

from __future__ import annotations

import hashlib
import json
import signal
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


# ---- Finding identity (for diffing across ticks) --------------------- #


def _finding_identity_hash(f: dict[str, Any]) -> str:
    """Substance-only hash; ignores ts, chain hashes, triage state.

    Two findings with the same identity hash are "the same finding"
    for diff purposes — even if their timestamps differ across ticks."""
    payload = json.dumps({
        "detector": f.get("detector", ""),
        "title": f.get("title", ""),
        "mitre": f.get("mitre", ""),
        # canonicalize evidence so dict ordering doesn't matter
        "evidence": _canonical_json(f.get("evidence", {})),
        "severity": f.get("severity", ""),
    }, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


def diff_findings(
    previous: Iterable[dict[str, Any]],
    current: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str]]:
    """Return (new_findings, current_identity_set).

    ``new_findings`` is the subset of ``current`` whose identity hash
    is not in ``previous``. ``current_identity_set`` is the full set
    of identity hashes from this tick — pass it as ``previous`` next
    tick to track only-new across the loop."""
    prev_ids = {_finding_identity_hash(f) for f in previous}
    new: list[dict[str, Any]] = []
    cur_ids: set[str] = set()
    for f in current:
        h = _finding_identity_hash(f)
        cur_ids.add(h)
        if h not in prev_ids:
            new.append(f)
    return new, cur_ids


# ---- Sinks ---- #


class Sink(Protocol):
    """Anything that consumes newly-emitted findings."""
    def emit(self, findings: list[dict[str, Any]], tick: int) -> None: ...


@dataclass
class StdoutSink:
    """Print each new finding as a one-line summary + optional indent
    of the evidence block. Default for the CLI."""
    verbose: bool = False

    def emit(self, findings: list[dict[str, Any]], tick: int) -> None:
        if not findings:
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}] tick {tick}: no new findings", flush=True)
            return
        ts = time.strftime("%H:%M:%S")
        print(
            f"[{ts}] tick {tick}: {len(findings)} NEW finding"
            f"{'' if len(findings) == 1 else 's'}",
            flush=True,
        )
        for f in findings:
            sev = (f.get("severity") or "?").upper()
            det = f.get("detector") or "?"
            print(
                f"  · [{sev:>8}] {det:<22} "
                f"{(f.get('title') or '')[:120]}",
                flush=True,
            )
            if self.verbose and f.get("evidence"):
                snippet = json.dumps(f["evidence"], default=str)[:200]
                print(f"      evidence: {snippet}", flush=True)


@dataclass
class WebhookSink:
    """POST each batch of new findings to a webhook as JSON.

    Designed for Slack-compatible webhooks (and similar): payload is
    ``{tick, ts, findings: [...]}``. The caller is responsible for the
    URL being one they intend to send to; we POST in the clear (or
    over TLS if the URL is https://).

    Errors are logged-and-continued — a failing webhook never crashes
    the loop, that would defeat the purpose."""
    url: str
    timeout_s: float = 10.0
    headers: dict[str, str] = field(default_factory=dict)
    _stderr: Any = None  # injected in tests; defaults to sys.stderr

    def emit(self, findings: list[dict[str, Any]], tick: int) -> None:
        if not findings:
            return
        stderr = self._stderr or sys.stderr
        try:
            import requests
        except ImportError:
            print("[watch] requests not installed; cannot POST webhook",
                  file=stderr, flush=True)
            return
        payload = {
            "tick": tick,
            "ts": time.time(),
            "finding_count": len(findings),
            "findings": [
                {
                    "detector": f.get("detector"),
                    "severity": f.get("severity"),
                    "title": f.get("title"),
                    "mitre": f.get("mitre"),
                    "summary": (f.get("summary") or "")[:1000],
                    "evidence": f.get("evidence") or {},
                }
                for f in findings
            ],
        }
        try:
            requests.post(
                self.url, json=payload,
                timeout=self.timeout_s,
                headers={"Content-Type": "application/json", **self.headers},
            )
        except Exception as exc:
            print(f"[watch] webhook POST failed: {exc!r}",
                  file=stderr, flush=True)


# ---- Loop ---- #


_SEVERITY_RANK = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


@dataclass
class WatchLoop:
    """Drives the collect → scan → diff → emit cycle.

    Caller-driven via ``tick()`` for tests; ``run()`` runs the full
    loop until ``stop()`` is called or a signal arrives.

    Most parameters mirror the CLI surface, but everything is
    constructor-injectable so tests don't need real collectors /
    detectors / network."""
    case_dir: str
    interval_s: float = 60.0
    sinks: list[Sink] = field(default_factory=list)
    alert_on: set[str] = field(default_factory=set)  # severity names
    only_collectors: list[str] | None = None
    only_detectors: list[str] | None = None
    include_admin: bool = True

    # Test injection — production wiring uses the runner helpers
    _collect_fn: Callable[[Any, list, list[str] | None, bool], None] | None = None
    _scan_fn: Callable[[Any, list[str] | None], int] | None = None
    _findings_fn: Callable[[Any], list[dict[str, Any]]] | None = None
    _sleep_fn: Callable[[float], None] = field(default=time.sleep)

    _prev_ids: set[str] = field(default_factory=set)
    _stopped: bool = False
    _alert_tripped: bool = False
    _tick_count: int = 0

    # ---- public surface ---- #

    def stop(self) -> None:
        self._stopped = True

    def tick(self) -> dict[str, Any]:
        """Run one cycle. Returns ``{new_findings, total, alert}`` for
        the caller / test."""
        self._tick_count += 1
        store = self._open_store()
        try:
            self._collect(store)
            n_findings = self._scan(store)
            current = self._iter_findings(store)
            new, cur_ids = diff_findings(self._prev_ids_as_findings(), current)
            self._prev_ids = cur_ids
            for sink in self.sinks:
                try:
                    sink.emit(new, self._tick_count)
                except Exception as exc:
                    print(f"[watch] sink failed: {exc!r}",
                          file=sys.stderr, flush=True)
            alert_hit = self._check_alert(new)
            if alert_hit:
                self._alert_tripped = True
            return {
                "tick": self._tick_count,
                "new_findings": len(new),
                "total_findings": n_findings,
                "alert": alert_hit,
            }
        finally:
            self._close_store(store)

    def run(self) -> int:
        """Run until stop() or signal. Returns rc=0 on clean shutdown,
        rc=2 on alert-trip (when alert_on is non-empty)."""
        self._install_signal_handlers()
        while not self._stopped:
            try:
                self.tick()
            except Exception as exc:
                # One bad tick never kills the loop. We surface and
                # keep going — the next tick will catch up.
                print(f"[watch] tick failed: {exc!r}",
                      file=sys.stderr, flush=True)
            # Sleep in 1-second slices so SIGTERM is responsive
            slept = 0.0
            while slept < self.interval_s and not self._stopped:
                quantum = min(1.0, self.interval_s - slept)
                self._sleep_fn(quantum)
                slept += quantum
        return 2 if (self._alert_tripped and self.alert_on) else 0

    # ---- internals (overridable for tests) ---- #

    def _open_store(self):
        from digger.core.evidence import EvidenceStore
        return EvidenceStore(self.case_dir)

    def _close_store(self, store) -> None:
        try:
            store.close()
        except Exception:
            pass

    def _collect(self, store) -> None:
        if self._collect_fn is not None:
            self._collect_fn(store, [], self.only_collectors,
                             self.include_admin)
            return
        from digger.collectors import all_collectors
        from digger.core.runner import run_collection
        cs = all_collectors(include_admin=self.include_admin)
        if self.only_collectors:
            wanted = set(self.only_collectors)
            cs = [c for c in cs if c.name in wanted]
        run_collection(store, cs)

    def _scan(self, store) -> int:
        if self._scan_fn is not None:
            return self._scan_fn(store, self.only_detectors) or 0
        from digger.detectors import all_detectors
        dets = all_detectors()
        if self.only_detectors:
            wanted = set(self.only_detectors)
            dets = [d for d in dets if d.name in wanted]
        total = 0
        for d in dets:
            total += d.run(store)
        return total

    def _iter_findings(self, store) -> list[dict[str, Any]]:
        if self._findings_fn is not None:
            return self._findings_fn(store) or []
        return list(store.iter_findings())

    def _prev_ids_as_findings(self) -> list[dict[str, Any]]:
        """The diff function takes finding dicts, but for prev we only
        care about identity hashes. Trick: return a synthetic dict per
        prev hash so the identity-hash function returns each hash."""
        out = []
        for h in self._prev_ids:
            out.append({"_pre_hashed_identity": h})
        return out

    def _check_alert(self, new_findings: list[dict[str, Any]]) -> bool:
        if not self.alert_on:
            return False
        wanted_rank = min(
            _SEVERITY_RANK.get(s, -1) for s in self.alert_on
        )
        for f in new_findings:
            sev = f.get("severity") or "info"
            if _SEVERITY_RANK.get(sev, -1) >= wanted_rank:
                return True
        return False

    def _install_signal_handlers(self) -> None:
        def _handler(_signum, _frame):
            self._stopped = True
            print("\n[watch] shutdown requested, finishing current tick",
                  file=sys.stderr, flush=True)
        try:
            signal.signal(signal.SIGINT, _handler)
            signal.signal(signal.SIGTERM, _handler)
        except (ValueError, OSError):
            # Not in main thread; skip — caller drives via .stop()
            pass


# Override the diff function for the synthetic pre-hashed prev path.
# We do this by giving _finding_identity_hash a fallback: if a dict has
# the magic key, just return that.
_original_identity = _finding_identity_hash


def _identity_hash_with_fallback(f: dict[str, Any]) -> str:
    h = f.get("_pre_hashed_identity")
    if isinstance(h, str):
        return h
    return _original_identity(f)


# Patch the module-level function so diff_findings picks up the fallback.
# This is hairy but tightly scoped — the alternative is plumbing a
# parameter through diff_findings, which makes the public API uglier.
globals()["_finding_identity_hash"] = _identity_hash_with_fallback


# ---- CLI wrapper ---- #


def run_watch(
    case_dir: str,
    *,
    interval_s: float = 60.0,
    only_collectors: list[str] | None = None,
    only_detectors: list[str] | None = None,
    alert_on: list[str] | None = None,
    webhook_url: str | None = None,
    verbose: bool = False,
    include_admin: bool = True,
) -> int:
    """Configure + run the watch loop. Returns the process exit code."""
    sinks: list[Sink] = [StdoutSink(verbose=verbose)]
    if webhook_url:
        sinks.append(WebhookSink(url=webhook_url))
    loop = WatchLoop(
        case_dir=case_dir,
        interval_s=interval_s,
        sinks=sinks,
        alert_on=set(alert_on or []),
        only_collectors=only_collectors,
        only_detectors=only_detectors,
        include_admin=include_admin,
    )
    return loop.run()
