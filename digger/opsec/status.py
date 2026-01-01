"""One-shot opsec posture summary.

Aggregates the state every other opsec module can report. The CLI
``digger opsec status`` invokes this and prints the result; programs
can call it directly.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any


def opsec_status() -> dict[str, Any]:
    from digger.fips.mode import current_state as fips_state
    from digger.opsec.airgap import current_state as airgap_state, traffic_summary
    from digger.opsec.watchers import find_watchers
    from digger.opsec.self_id import digger_self_pids

    fips = fips_state()
    air  = airgap_state()
    watchers = find_watchers()
    by_cat: dict[str, list[dict]] = {}
    for w in watchers:
        by_cat.setdefault(w.category, []).append(asdict(w))

    return {
        "fips": {
            "enabled":             fips.enabled,
            "self_test_passed":    fips.self_test_passed,
            "os_fips_marker":      fips.os_fips_marker,
            "notes":               fips.notes,
        },
        "airgap": {
            "enabled":             air.enabled,
            "enabled_at":          air.enabled_at,
            "attempted_violations": air.attempted_violations,
            "last_violation":      air.last_violation,
        },
        "traffic": traffic_summary(),
        "self": {
            "pids":                digger_self_pids(),
        },
        "watchers": {
            "total":               len(watchers),
            "by_category":         {k: len(v) for k, v in by_cat.items()},
            "high_severity":       [asdict(w) for w in watchers if w.severity == "high"],
            "details_by_category": by_cat,
        },
    }
