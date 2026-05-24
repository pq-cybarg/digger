"""JSON report renderer."""

from __future__ import annotations

import json
from typing import Any

from digger.core.evidence import EvidenceStore


def render_json(store: EvidenceStore) -> str:
    out: dict[str, Any] = {
        "case_id": store.get_meta("case_id"),
        "host": store.get_meta("host"),
        "collection_started": store.get_meta("collection_started"),
        "collection_finished": store.get_meta("collection_finished"),
        "ai_triage_run": store.get_meta("ai_triage_run"),
        "ai_case_summary": store.get_meta("ai_case_summary"),
        "counts": store.counts(),
        "chain_tip": store.chain_tip(),
        "findings": list(store.iter_findings()),
        # Artifacts are big; include only their indexes by default.
        "artifacts_index": [
            {"uuid": a["artifact_uuid"], "collector": a["collector"],
             "category": a["category"], "subject": a["subject"], "ts": a["ts"]}
            for a in store.iter_artifacts()
        ],
    }
    return json.dumps(out, indent=2, default=str)
