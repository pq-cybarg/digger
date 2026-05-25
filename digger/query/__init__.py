"""Ad-hoc query layer over the EvidenceStore.

Two surfaces:

  ``Query.run(sql, case_dir)`` — execute a single read-only SELECT
                                 against the case's evidence.db and
                                 return rows.
  ``CANNED`` — dict of pre-canned named queries for common slices
               (top-detectors / severity-distribution / etc.). The CLI
               exposes them via ``digger query --canned NAME``.

Safety gate
-----------
Only ``SELECT`` and ``WITH`` (CTE) statements are accepted. The
``EvidenceStore`` chain is append-only by design — we open the
underlying SQLite with ``mode=ro`` so even a clever DROP TABLE in
the user's SQL would fail at the connection layer too, but the
explicit statement-level reject gives a friendlier error and
prevents accidental writes during read-only sessions.

JSON evidence-blob queries are supported via SQLite's
``json_extract()`` / ``->>`` / ``->`` operators. The
``data_json`` / ``evidence_json`` columns are valid JSON so
``json_extract(data_json, '$.pid')`` works out-of-the-box.
"""

from __future__ import annotations

from digger.query.runner import (
    CANNED,
    QueryError,
    Query,
    QueryResult,
    list_canned,
    run_canned,
    run_query,
)

__all__ = [
    "CANNED",
    "Query",
    "QueryError",
    "QueryResult",
    "list_canned",
    "run_canned",
    "run_query",
]
