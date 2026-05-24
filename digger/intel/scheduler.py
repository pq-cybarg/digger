"""Background polling daemon for threat-intel feeds.

A single thread per feed group is wasteful; we use one thread that wakes
up at the next-due interval and refreshes all feeds whose interval has
elapsed. SIGINT/SIGTERM cleanly stops the loop.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from digger.intel.feeds import FEEDS, update_feed


class IntelScheduler:
    def __init__(
        self,
        on_update: Optional[Callable[[dict], None]] = None,
        force_first: bool = False,
        min_sleep: int = 60,
    ):
        self.on_update = on_update
        self.force_first = force_first
        self.min_sleep = min_sleep
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _loop(self) -> None:
        first = True
        while not self._stop.is_set():
            now = time.time()
            soonest_due_in = max(f.interval for f in FEEDS)
            for feed in FEEDS:
                if self._stop.is_set():
                    return
                result = update_feed(feed, force=self.force_first and first)
                if self.on_update:
                    try:
                        self.on_update(result)
                    except Exception:
                        pass
                # compute how long until this feed needs to be touched again
                soonest_due_in = min(soonest_due_in, feed.interval)
            first = False
            # Sleep until the closest next-due feed is due, but at least min_sleep.
            self._stop.wait(timeout=max(self.min_sleep, soonest_due_in))

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="digger-intel", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None
