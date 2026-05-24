"""Collector that signature-verifies every running process exe."""

from __future__ import annotations

from typing import Iterable

import psutil

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.signing.verify import verify_path


class CodeSigningCollector(Collector):
    name = "code_signing"
    category = "integrity"
    description = (
        "Signature-verify every running process's exe. macOS via codesign+spctl, "
        "Linux via package-manager ownership, Windows best-effort (currently "
        "marked skipped — verify externally with signtool)."
    )

    def collect(self) -> Iterable[Artifact]:
        seen: dict[str, dict] = {}
        for proc in psutil.process_iter(attrs=["pid", "name", "username", "exe"]):
            try:
                info = proc.info
                exe = info.get("exe")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if not exe:
                continue
            # de-duplicate per exe path so we don't run codesign 500x on
            # the same binary across Chrome's renderer pool.
            if exe in seen:
                seen[exe]["pids"].append(info["pid"])
                continue
            sig = verify_path(exe)
            entry = {
                "exe": exe,
                "pids": [info["pid"]],
                "first_seen_name": info.get("name"),
                "first_seen_user": info.get("username"),
                "state":    sig.state,
                "signer":   sig.signer,
                "team_id":  sig.team_id,
                "cdhash":   sig.cdhash,
                "details":  sig.details,
            }
            seen[exe] = entry

        for exe, entry in seen.items():
            yield self.make(
                subject=f"sig:{exe}",
                **entry,
            )
