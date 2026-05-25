"""Read-only SQL query runner against a case's evidence.db.

Two layers of safety:

  1. Statement-level reject: only ``SELECT`` and ``WITH`` accepted.
     ``DROP``, ``DELETE``, ``UPDATE``, ``INSERT``, ``ATTACH``,
     ``PRAGMA``, ``CREATE``, ``ALTER`` all refused with QueryError.
  2. Connection-level: SQLite opened via ``mode=ro`` URI so even if
     statement parsing missed something, the DB rejects writes at
     the cursor.

Tables available
----------------
  artifacts(id, artifact_uuid, collector, category, subject, ts,
            data_json, data_sha256, data_sha3_256,
            chain_sha256, chain_sha3_256)
  findings (id, finding_uuid, detector, severity, title, summary,
            artifact_refs, evidence_json, mitre, ts,
            data_sha256, data_sha3_256, chain_sha256, chain_sha3_256,
            triage_json)
  files    (path, size, sha256, sha3_256, seen_ts, artifact_uuid)
  log      (ts, level, msg)

JSON access: SQLite supports ``json_extract(col, '$.path')`` and
``col -> '$.path'`` / ``col ->> '$.path'`` operators against the
``data_json`` / ``evidence_json`` / ``triage_json`` columns.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---- exception ---- #


class QueryError(ValueError):
    """Raised when a query is rejected (unsafe verb, bad SQL, etc.)."""


# ---- safety gate ---- #


_ALLOWED_FIRST_TOKEN = re.compile(
    r"^\s*(?:--[^\n]*\n\s*)*(SELECT|WITH)\b",
    re.IGNORECASE,
)

# Forbidden keywords anywhere in the statement, even inside strings.
# We're deliberately strict — a user with legitimate need to look up
# the literal text "DROP TABLE" in evidence can use a hex literal or
# parameterize.
_FORBIDDEN = (
    r"\bATTACH\b", r"\bDETACH\b", r"\bPRAGMA\b",
    r"\bDROP\b", r"\bDELETE\b", r"\bINSERT\b",
    r"\bUPDATE\b", r"\bREPLACE\b", r"\bMERGE\b",
    r"\bCREATE\b", r"\bALTER\b", r"\bTRUNCATE\b",
    r"\bVACUUM\b", r"\bREINDEX\b", r"\bANALYZE\b",
    r"\bSAVEPOINT\b", r"\bRELEASE\b", r"\bROLLBACK\b",
    r"\bCOMMIT\b", r"\bBEGIN\b",
)
_FORBIDDEN_RE = re.compile("|".join(_FORBIDDEN), re.IGNORECASE)


def _gate(sql: str) -> None:
    """Raise QueryError if the SQL is not a single safe read-only stmt."""
    if not sql or not sql.strip():
        raise QueryError("empty query")
    # Reject multi-statement bodies — sqlite3 lets you stack them
    # separated by ``;`` which a clever query like
    # ``SELECT 1; DROP TABLE artifacts; --`` would exploit.
    stripped = sql.strip().rstrip(";")
    if ";" in stripped:
        raise QueryError(
            "multi-statement queries not allowed — submit one SELECT at a time"
        )
    if not _ALLOWED_FIRST_TOKEN.match(sql):
        raise QueryError(
            "only SELECT and WITH (CTE) statements allowed; "
            "DROP/DELETE/UPDATE/INSERT/CREATE/PRAGMA are rejected"
        )
    if _FORBIDDEN_RE.search(stripped):
        # Find which keyword fired
        m = _FORBIDDEN_RE.search(stripped)
        raise QueryError(
            f"forbidden keyword detected: {m.group(0).upper()}"
        )


# ---- result + runner ---- #


@dataclass
class QueryResult:
    columns: list[str]
    rows: list[tuple[Any, ...]]
    row_count: int
    sql: str = ""

    def to_json(self) -> str:
        objs = [
            {col: _jsonable(val) for col, val in zip(self.columns, r)}
            for r in self.rows
        ]
        return json.dumps(objs, indent=2, default=str)

    def to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(self.columns)
        for r in self.rows:
            w.writerow([_csv_safe(v) for v in r])
        return buf.getvalue()

    def to_text(self, *, max_col: int = 80) -> str:
        if not self.columns:
            return f"(no columns; {self.row_count} rows)"
        widths = [len(c) for c in self.columns]
        for r in self.rows:
            for i, v in enumerate(r):
                widths[i] = min(max_col, max(widths[i], len(_repr_cell(v))))
        sep = " | "
        head = sep.join(c.ljust(widths[i]) for i, c in enumerate(self.columns))
        rule = "-+-".join("-" * w for w in widths)
        out = [head, rule]
        for r in self.rows:
            out.append(sep.join(
                _repr_cell(v)[:max_col].ljust(widths[i])
                for i, v in enumerate(r)
            ))
        out.append(f"({self.row_count} row{'s' if self.row_count != 1 else ''})")
        return "\n".join(out)


def _jsonable(v: Any) -> Any:
    """Coerce SQLite return values to JSON-safe Python."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.hex()
    return str(v)


def _csv_safe(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray)):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.hex()
    return v


def _repr_cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.hex()
    return str(v)


@dataclass
class Query:
    """Container so callers can build a query + bind params then run.

    Most callers should use ``run_query()`` directly; this exists for
    test/debug ergonomics and future expansion."""
    sql: str
    params: tuple = field(default_factory=tuple)

    def run(self, case_dir: str | Path) -> QueryResult:
        return run_query(self.sql, case_dir, params=self.params)


def _ro_connect(case_dir: str | Path) -> sqlite3.Connection:
    path = Path(case_dir) / "evidence.db"
    if not path.is_file():
        raise QueryError(f"no evidence.db at {path}")
    # mode=ro URI gives DB-side read-only guarantee on top of our
    # statement-level reject. ``uri=True`` to enable URI parsing.
    return sqlite3.connect(
        f"file:{path}?mode=ro",
        uri=True,
        timeout=10.0,
    )


def run_query(
    sql: str,
    case_dir: str | Path,
    *,
    params: tuple | list = (),
    limit: int | None = None,
) -> QueryResult:
    """Execute a single read-only SELECT/WITH and return rows.

    Raises ``QueryError`` if the statement is unsafe, or
    ``sqlite3.OperationalError`` if the SQL has a real syntax/runtime
    issue (e.g. references a missing column)."""
    _gate(sql)
    conn = _ro_connect(case_dir)
    try:
        cur = conn.cursor()
        if limit is not None and "limit" not in sql.lower():
            sql = f"{sql.rstrip(';')} LIMIT {int(limit)}"
        cur.execute(sql, tuple(params))
        columns = [d[0] for d in (cur.description or [])]
        rows = cur.fetchall()
        return QueryResult(
            columns=columns, rows=rows, row_count=len(rows), sql=sql,
        )
    finally:
        conn.close()


# ---- canned queries ---- #


CANNED: dict[str, dict[str, str]] = {
    "top-detectors": {
        "description": "Findings per detector, descending.",
        "sql": (
            "SELECT detector, COUNT(*) AS n "
            "FROM findings GROUP BY detector ORDER BY n DESC"
        ),
    },
    "severity-distribution": {
        "description": "Findings per severity bucket.",
        "sql": (
            "SELECT severity, COUNT(*) AS n "
            "FROM findings GROUP BY severity "
            "ORDER BY CASE severity "
            "  WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
            "  WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC"
        ),
    },
    "critical-findings": {
        "description": "Every critical finding, newest first.",
        "sql": (
            "SELECT ts, detector, title, mitre FROM findings "
            "WHERE severity='critical' ORDER BY ts DESC"
        ),
    },
    "mitre-coverage": {
        "description": "Distinct MITRE techniques observed in this case.",
        "sql": (
            "SELECT mitre, COUNT(*) AS n FROM findings "
            "WHERE mitre != '' GROUP BY mitre ORDER BY n DESC"
        ),
    },
    "campaign-attributions": {
        "description": (
            "Findings grouped by suspected campaign "
            "(from evidence.campaign)."
        ),
        "sql": (
            "SELECT json_extract(evidence_json, '$.campaign') AS campaign, "
            "       COUNT(*) AS n "
            "FROM findings "
            "WHERE json_extract(evidence_json, '$.campaign') IS NOT NULL "
            "GROUP BY campaign ORDER BY n DESC"
        ),
    },
    "artifacts-by-collector": {
        "description": "Artifact count per collector.",
        "sql": (
            "SELECT collector, COUNT(*) AS n "
            "FROM artifacts GROUP BY collector ORDER BY n DESC"
        ),
    },
    "process-tree": {
        "description": "(pid, ppid, name, exe) from process artifacts.",
        "sql": (
            "SELECT json_extract(data_json, '$.pid')  AS pid, "
            "       json_extract(data_json, '$.ppid') AS ppid, "
            "       json_extract(data_json, '$.name') AS name, "
            "       json_extract(data_json, '$.exe')  AS exe "
            "FROM artifacts WHERE collector='processes' "
            "ORDER BY pid"
        ),
    },
    "remediation-commands": {
        "description": (
            "Every hardening / remediation block emitted by detectors. "
            "Useful for printing one canonical fix-it sheet for a case."
        ),
        "sql": (
            "SELECT detector, title, "
            "       json_extract(evidence_json, '$.remediation_commands') "
            "         AS remediation, "
            "       json_extract(evidence_json, '$.hardening_commands') "
            "         AS hardening "
            "FROM findings "
            "WHERE json_extract(evidence_json, '$.remediation_commands') "
            "      IS NOT NULL "
            "   OR json_extract(evidence_json, '$.hardening_commands') "
            "      IS NOT NULL "
            "ORDER BY severity DESC"
        ),
    },
    "destructive-warnings": {
        "description": (
            "Findings carrying a destructive_warning evidence field "
            "(e.g. Mini Shai-Hulud rm-rf-on-token-revoke). Disarm "
            "FIRST before touching anything else."
        ),
        "sql": (
            "SELECT detector, title, "
            "       json_extract(evidence_json, '$.destructive_warning') "
            "         AS destructive_warning "
            "FROM findings "
            "WHERE json_extract(evidence_json, '$.destructive_warning') "
            "      IS NOT NULL"
        ),
    },
    "recent-criticals": {
        "description": (
            "Last 24h of critical findings — for triage of just-fired "
            "events."
        ),
        "sql": (
            "SELECT ts, detector, title, mitre FROM findings "
            "WHERE severity='critical' "
            "  AND ts > strftime('%s', 'now') - 86400 "
            "ORDER BY ts DESC"
        ),
    },
}


def list_canned() -> list[tuple[str, str]]:
    """Return [(name, description), ...] for `--canned` discovery."""
    return [(k, v["description"]) for k, v in CANNED.items()]


def run_canned(name: str, case_dir: str | Path) -> QueryResult:
    if name not in CANNED:
        raise QueryError(
            f"unknown canned query: {name!r}. "
            f"Available: {', '.join(CANNED)}"
        )
    return run_query(CANNED[name]["sql"], case_dir)
