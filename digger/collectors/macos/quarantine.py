"""LaunchServices quarantine events — files downloaded by quarantine-aware apps."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


class QuarantineCollector(Collector):
    name = "macos.quarantine"
    category = "filesystem"
    supported_os = (OS.MACOS,)
    description = "QuarantineEventsV2 — what was downloaded by what app, from where."

    def collect(self) -> Iterable[Artifact]:
        db = Path.home() / "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        if not db.exists():
            return
        try:
            uri = f"file:{db}?immutable=1&mode=ro"
            with sqlite3.connect(uri, uri=True) as conn:
                rows = conn.execute(
                    "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, "
                    "LSQuarantineAgentBundleIdentifier, LSQuarantineOriginURLString, "
                    "LSQuarantineDataURLString, LSQuarantineSenderName, "
                    "LSQuarantineSenderAddress, LSQuarantineEventIdentifier, "
                    "LSQuarantineTypeNumber "
                    "FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 5000"
                ).fetchall()
        except sqlite3.Error:
            return
        yield self.make(
            subject="quarantine-events",
            count=len(rows),
            entries=[
                {
                    "timestamp": r[0],
                    "agent_name": r[1],
                    "agent_bundle_id": r[2],
                    "origin_url": r[3],
                    "data_url": r[4],
                    "sender_name": r[5],
                    "sender_address": r[6],
                    "event_id": r[7],
                    "type": r[8],
                }
                for r in rows
            ],
        )
