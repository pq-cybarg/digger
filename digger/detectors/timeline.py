"""Build a chronological timeline artifact from collected events."""

from __future__ import annotations

import time
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


def _extract_events(store: EvidenceStore):
    """Yield (timestamp, source, what) tuples from any artifact with usable ts."""
    for art in store.iter_artifacts():
        data = art["data"]
        # Processes — use create_time
        if art["collector"] == "processes":
            ct = data.get("create_time")
            if ct:
                yield (ct, "process", f"{data.get('name')} pid={data.get('pid')}")
            continue
        # Recent files — entries each have mtime
        if art["collector"] == "recent_files":
            for e in data.get("entries", []) or []:
                if e.get("mtime"):
                    yield (e["mtime"], "file", e.get("path"))
            continue
        # Quarantine — entries with timestamp
        if art["collector"] == "macos.quarantine":
            for e in data.get("entries", []) or []:
                if e.get("timestamp"):
                    yield (
                        # Cocoa epoch -> Unix epoch (978307200 = 2001-01-01)
                        e["timestamp"] + 978307200,
                        "quarantine",
                        f"{e.get('agent_name')} <- {e.get('data_url')}",
                    )


class TimelineBuilder(Detector):
    name = "timeline"
    description = "Synthesized chronological event timeline."

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        events = sorted(_extract_events(store), key=lambda x: x[0])
        if not events:
            return
        # Persist the timeline as an informational finding so the report can render it.
        f = Finding(
            detector=self.name,
            severity="info",
            title=f"Timeline ({len(events)} events)",
            summary="Synthesized event timeline across processes, files, quarantine.",
            evidence={
                "count": len(events),
                "events": [
                    {"ts": ts, "source": src, "what": what}
                    for ts, src, what in events[-2000:]
                ],
            },
        )
        yield f
