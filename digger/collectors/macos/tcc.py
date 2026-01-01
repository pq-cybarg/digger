"""macOS TCC (Transparency, Consent, and Control) database.

Two databases:
    /Library/Application Support/com.apple.TCC/TCC.db          — system
    ~/Library/Application Support/com.apple.TCC/TCC.db         — user

System DB requires Full Disk Access for the running process to read.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS


class TccCollector(Collector):
    name = "macos.tcc"
    category = "security_posture"
    supported_os = (OS.MACOS,)
    description = "Apps with privacy permissions: camera, mic, screen recording, AppleEvents, full-disk."

    def collect(self) -> Iterable[Artifact]:
        for path in [
            Path("/Library/Application Support/com.apple.TCC/TCC.db"),
            Path.home() / "Library/Application Support/com.apple.TCC/TCC.db",
        ]:
            if not path.exists():
                continue
            try:
                uri = f"file:{path}?immutable=1&mode=ro"
                with sqlite3.connect(uri, uri=True) as conn:
                    rows = conn.execute(
                        "SELECT service, client, client_type, auth_value, auth_reason, "
                        "indirect_object_identifier, last_modified "
                        "FROM access ORDER BY last_modified DESC"
                    ).fetchmany(2000)
            except sqlite3.Error:
                continue
            yield self.make(
                subject=f"tcc:{path}",
                path=str(path),
                count=len(rows),
                entries=[
                    {
                        "service": r[0],
                        "client": r[1],
                        "client_type": r[2],
                        "auth_value": r[3],
                        "auth_reason": r[4],
                        "indirect_object": r[5],
                        "last_modified": r[6],
                    }
                    for r in rows
                ],
            )
