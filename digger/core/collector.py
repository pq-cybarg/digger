"""Base classes for collectors."""

from __future__ import annotations

import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterable

from digger.core.evidence import Artifact, EvidenceStore
from digger.core.platform import OS, current_os


@dataclass
class CollectorResult:
    name: str
    artifacts_collected: int
    elapsed_s: float
    error: str | None = None
    skipped: bool = False
    reason: str = ""


class Collector(ABC):
    """Base collector.

    Subclasses set:
      - ``name``        unique identifier ("processes", "windows.registry", …)
      - ``category``    grouping ("process", "persistence", "network", …)
      - ``supported_os`` iterable of OS values this collector runs on
      - ``requires_admin`` whether this needs elevation; if so and we aren't,
                          the collector is skipped (but reported)

    Then implement ``collect() -> Iterable[Artifact]``.
    """

    name: str = ""
    category: str = ""
    supported_os: tuple[OS, ...] = (OS.WINDOWS, OS.MACOS, OS.LINUX)
    requires_admin: bool = False
    description: str = ""

    @abstractmethod
    def collect(self) -> Iterable[Artifact]:
        ...

    def is_supported(self) -> tuple[bool, str]:
        if current_os() not in self.supported_os:
            return False, f"unsupported OS ({current_os().value})"
        if self.requires_admin:
            from digger.core.platform import is_admin
            if not is_admin():
                return False, "requires admin/root privileges"
        return True, ""

    def make(self, subject: str, **data) -> Artifact:
        """Helper to build an Artifact tagged with this collector's metadata."""
        return Artifact(collector=self.name, category=self.category, subject=subject, data=data)

    def run(self, store: EvidenceStore) -> CollectorResult:
        start = time.time()
        ok, reason = self.is_supported()
        if not ok:
            store.log("info", f"skip {self.name}: {reason}")
            return CollectorResult(self.name, 0, 0.0, skipped=True, reason=reason)
        count = 0
        try:
            for art in self.collect():
                store.add_artifact(art)
                count += 1
            return CollectorResult(self.name, count, time.time() - start)
        except Exception as exc:
            tb = traceback.format_exc()
            store.log("error", f"{self.name} failed: {exc}\n{tb}")
            return CollectorResult(self.name, count, time.time() - start, error=str(exc))
