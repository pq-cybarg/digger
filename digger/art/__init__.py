"""Atomic Red Team (Red Canary) validation harness.

Maps ATT&CK techniques tested by ART atomic tests to digger detectors,
and (with explicit sandbox-gating) runs selected tests to verify the
corresponding detector fires.

Two modes:

  coverage   Pure metadata — load ART YAML test files, cross-reference
             with `digger.genrule.heatmap.build_coverage()`, produce a
             three-way report:
               - ART technique × digger detector matrix
               - "ART has tests / we don't detect" gaps
               - "we detect / ART doesn't test" reverse gaps
             Safe to run anywhere; no execution.

  run        Sandbox-gated execution. Requires the env var
             ``DIGGER_ART_SANDBOX_OK=1`` AND a sandbox marker file at
             ``/tmp/digger-art-sandbox.ok`` (created by the operator
             as an explicit "I have read the docs, this is a VM" gate).
             Runs the test, then verifies the named detector emitted a
             matching finding within the run window.

ART tests live in the official Red Canary corpus
(https://github.com/redcanaryco/atomic-red-team) under
``atomics/T<id>/T<id>.yaml``. The harness clones / fast-forwards into
``$DIGGER_ART_DIR`` or ``~/.cache/digger/atomic-red-team``.

Public API
----------
``load_atomics()``           — parse all T####.yaml under the cache
``build_coverage_matrix()``  — ART techniques × digger detectors
``coverage_report(text/json/html)``  — render the matrix
``run_test(t_id, idx, ...)`` — sandbox-gated execution
``verify_detection(store, t_id, after_ts)`` — check store for matching
                                              finding
"""

from __future__ import annotations

from digger.art.harness import (
    AtomicTest,
    build_coverage_matrix,
    coverage_report_json,
    coverage_report_text,
    load_atomics,
    sandbox_check,
)

__all__ = [
    "AtomicTest",
    "build_coverage_matrix",
    "coverage_report_json",
    "coverage_report_text",
    "load_atomics",
    "sandbox_check",
]
