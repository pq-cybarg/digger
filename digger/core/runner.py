"""Orchestrates running collectors and detectors against an evidence store."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Iterable

from digger.core.collector import Collector, CollectorResult
from digger.core.evidence import EvidenceStore
from digger.core.platform import host_fingerprint


@dataclass
class RunSummary:
    case_id: str
    started: float
    finished: float
    collector_results: list[CollectorResult]

    @property
    def total_artifacts(self) -> int:
        return sum(r.artifacts_collected for r in self.collector_results)

    @property
    def errors(self) -> list[CollectorResult]:
        return [r for r in self.collector_results if r.error]

    @property
    def skipped(self) -> list[CollectorResult]:
        return [r for r in self.collector_results if r.skipped]


def run_collection(
    store: EvidenceStore,
    collectors: Iterable[Collector],
    progress=None,
    classification: str = "UNCLASSIFIED",
    tlp: str = "TLP:AMBER",
) -> RunSummary:
    from digger.coc import open_custody
    from digger.coc.record import append_event
    started = time.time()
    case_id = store.get_meta("case_id") or str(uuid.uuid4())
    store.set_meta("case_id", case_id)
    store.set_meta("host", host_fingerprint())
    store.set_meta("classification", classification)
    store.set_meta("tlp", tlp)
    store.set_meta("collection_started", started)
    coc = open_custody(store.case_dir, case_id=case_id, classification=classification, tlp=tlp)
    append_event(store.case_dir, coc, "collection_started",
                 f"running {len(list(collectors))} collectors" if hasattr(collectors, '__len__') else "collection begun")
    store.log("info", f"begin collection (case {case_id}, classification={classification}, tlp={tlp})")
    results: list[CollectorResult] = []
    for c in collectors:
        if progress:
            progress.start(c.name)
        result = c.run(store)
        results.append(result)
        if progress:
            progress.finish(c.name, result)
    finished = time.time()
    store.set_meta("collection_finished", finished)
    append_event(store.case_dir, coc, "collection_finished",
                 f"{sum(r.artifacts_collected for r in results)} artifacts collected by {len(results)} collectors")
    store.log("info", f"end collection ({finished - started:.2f}s, {sum(r.artifacts_collected for r in results)} artifacts)")
    return RunSummary(case_id=case_id, started=started, finished=finished, collector_results=results)
