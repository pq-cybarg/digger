"""Continuous-monitoring daemon (``digger watch``).

Turns digger from a snapshot tool into a real-time monitor. Re-collects
+ re-scans at a user-set interval, diffs the new findings against the
previous cycle, and emits ONLY the new ones to stdout (and optionally
a webhook).

Design rationale
----------------
Several detectors in the corpus catch attacks where after-the-fact
scans are too late:

  * Mini Shai-Hulud / Shai-Hulud → ``rm -rf ~/`` on token revocation.
    Once the wipe fires, the home dir is gone.
  * TrapDoor → credential exfiltration.
  * ImpactDetector → ransomware encryption in progress, shadow-copy
    deletion, EDR tampering.

Watch mode catches these in the live window where intervention still
helps. Lightweight: re-uses the same collectors + detectors, just on
a loop.

Public API
----------
``WatchLoop`` — the loop itself (testable: caller drives ticks)
``run_watch`` — convenience wrapper for the CLI
``WebhookSink`` / ``StdoutSink`` — output sinks for emitted findings
"""

from __future__ import annotations

from digger.watch.daemon import (
    StdoutSink,
    WatchLoop,
    WebhookSink,
    diff_findings,
    run_watch,
)

__all__ = [
    "StdoutSink",
    "WatchLoop",
    "WebhookSink",
    "diff_findings",
    "run_watch",
]
