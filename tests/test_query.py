"""VQL-style query layer over the EvidenceStore."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from digger.core.evidence import Artifact, EvidenceStore, Finding
from digger.query.runner import (
    Query,
    QueryError,
    _gate,
    list_canned,
    run_canned,
    run_query,
)


# ---- safety gate ---- #


@pytest.mark.parametrize("sql", [
    "SELECT 1",
    "  SELECT * FROM findings",
    "SELECT detector, COUNT(*) FROM findings GROUP BY detector",
    "WITH t AS (SELECT 1 AS x) SELECT * FROM t",
    "-- comment\nSELECT 1",
    "SELECT 1;",  # trailing semicolon OK after strip
])
def test_gate_accepts_select_and_with(sql):
    _gate(sql)  # MUST NOT raise


@pytest.mark.parametrize("sql,reason", [
    ("DROP TABLE artifacts", "DROP"),
    ("delete from findings", "DELETE"),
    ("INSERT INTO findings VALUES (1)", "INSERT"),
    ("UPDATE findings SET severity='low'", "UPDATE"),
    ("CREATE TABLE x (a INT)", "CREATE"),
    ("ALTER TABLE artifacts ADD COLUMN x INT", "ALTER"),
    ("PRAGMA table_info(artifacts)", "PRAGMA"),
    ("ATTACH DATABASE '/etc/passwd' AS p", "ATTACH"),
    ("DETACH DATABASE p", "DETACH"),
    ("REPLACE INTO findings VALUES (1)", "REPLACE"),
    ("TRUNCATE findings", "TRUNCATE"),
    ("VACUUM", "VACUUM"),
    ("BEGIN; SELECT 1; COMMIT", "BEGIN"),
])
def test_gate_blocks_forbidden_verbs(sql, reason):
    with pytest.raises(QueryError):
        _gate(sql)


def test_gate_blocks_multi_statement():
    with pytest.raises(QueryError, match="multi-statement"):
        _gate("SELECT 1; DROP TABLE artifacts;")


def test_gate_blocks_empty():
    with pytest.raises(QueryError, match="empty"):
        _gate("")
    with pytest.raises(QueryError, match="empty"):
        _gate("   \n  ")


def test_gate_blocks_non_select_first_token():
    """Even if no forbidden verb is later in the statement, the very
    first token must be SELECT or WITH."""
    with pytest.raises(QueryError, match="only SELECT and WITH"):
        _gate("EXPLAIN SELECT 1")


# ---- run_query ---- #


@pytest.fixture
def seeded_store(tmp_path):
    """A small case with mixed artifacts + findings to query against."""
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=1 init",
        data={"pid": 1, "ppid": 0, "name": "init", "exe": "/sbin/init"},
    ))
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject="pid=42 node",
        data={"pid": 42, "ppid": 1, "name": "node",
              "exe": "/usr/bin/node"},
    ))
    store.add_artifact(Artifact(
        collector="dns", category="network",
        subject="dns:cache",
        data={"host": "evil.example", "entries": []},
    ))
    store.add_finding(Finding(
        detector="trapdoor", severity="critical",
        title="Compromised npm package",
        summary="x", artifact_refs=[],
        evidence={"campaign": "TrapDoor",
                  "package": "eth-wallet-sentinel@1.0"},
        mitre="T1195.001",
    ))
    store.add_finding(Finding(
        detector="exfiltration", severity="high",
        title="C2 callout to evil.example",
        summary="y", artifact_refs=[],
        evidence={"host": "evil.example",
                  "destructive_warning": "do not rotate"},
        mitre="T1041",
    ))
    store.add_finding(Finding(
        detector="anti_forensics", severity="medium",
        title="history -c",
        summary="z", artifact_refs=[],
        evidence={"remediation_commands": "history -c"},
        mitre="T1070.003",
    ))
    store.close()
    return tmp_path


def test_run_query_returns_columns_and_rows(seeded_store):
    r = run_query(
        "SELECT detector, severity FROM findings ORDER BY detector",
        seeded_store,
    )
    assert r.columns == ["detector", "severity"]
    assert r.row_count == 3
    detectors = [row[0] for row in r.rows]
    assert detectors == sorted(detectors)
    assert "trapdoor" in detectors


def test_run_query_with_aggregate(seeded_store):
    r = run_query(
        "SELECT severity, COUNT(*) FROM findings GROUP BY severity",
        seeded_store,
    )
    counts = {row[0]: row[1] for row in r.rows}
    assert counts["critical"] == 1
    assert counts["high"] == 1
    assert counts["medium"] == 1


def test_run_query_with_json_extract(seeded_store):
    """SQLite json_extract over evidence_json should work for queries
    over the evidence blob."""
    r = run_query(
        "SELECT detector, "
        "       json_extract(evidence_json, '$.campaign') AS campaign "
        "FROM findings "
        "WHERE json_extract(evidence_json, '$.campaign') IS NOT NULL",
        seeded_store,
    )
    assert r.row_count == 1
    assert r.rows[0] == ("trapdoor", "TrapDoor")


def test_run_query_with_limit_arg(seeded_store):
    r = run_query("SELECT * FROM findings", seeded_store, limit=2)
    assert r.row_count == 2


def test_run_query_doesnt_overwrite_existing_limit(seeded_store):
    """If the user's SQL already has a LIMIT clause, we don't append
    another one."""
    r = run_query(
        "SELECT * FROM findings LIMIT 1", seeded_store, limit=99,
    )
    assert r.row_count == 1


def test_run_query_rejects_missing_case_dir(tmp_path):
    with pytest.raises(QueryError, match="no evidence.db"):
        run_query("SELECT 1", tmp_path / "does-not-exist")


def test_run_query_rejects_drop(seeded_store):
    with pytest.raises(QueryError):
        run_query("DROP TABLE findings", seeded_store)


def test_query_dataclass_run(seeded_store):
    q = Query(sql="SELECT COUNT(*) FROM findings")
    r = q.run(seeded_store)
    assert r.rows[0][0] == 3


# ---- result formatters ---- #


def test_result_to_json_round_trip(seeded_store):
    r = run_query(
        "SELECT detector, severity FROM findings ORDER BY detector",
        seeded_store,
    )
    parsed = json.loads(r.to_json())
    assert isinstance(parsed, list)
    assert len(parsed) == 3
    assert parsed[0]["detector"] in {"anti_forensics",
                                       "exfiltration", "trapdoor"}


def test_result_to_csv_well_formed(seeded_store):
    r = run_query(
        "SELECT detector, severity FROM findings ORDER BY detector",
        seeded_store,
    )
    csv_out = r.to_csv()
    lines = [ln for ln in csv_out.splitlines() if ln]
    # 1 header + 3 rows
    assert len(lines) == 4
    assert lines[0] == "detector,severity"


def test_result_to_text_includes_row_count(seeded_store):
    r = run_query(
        "SELECT detector FROM findings", seeded_store,
    )
    out = r.to_text()
    assert "detector" in out
    assert "3 rows" in out or "3 row)" in out


def test_result_to_text_empty_set(seeded_store):
    r = run_query(
        "SELECT detector FROM findings WHERE severity='nonexistent'",
        seeded_store,
    )
    out = r.to_text()
    assert "0 rows" in out


# ---- canned queries ---- #


def test_list_canned_returns_entries():
    names = [n for n, _ in list_canned()]
    assert "top-detectors" in names
    assert "severity-distribution" in names
    assert "campaign-attributions" in names
    assert "destructive-warnings" in names


def test_canned_top_detectors(seeded_store):
    r = run_canned("top-detectors", seeded_store)
    assert r.columns == ["detector", "n"]
    # 3 distinct detectors, each with 1 finding
    assert r.row_count == 3


def test_canned_severity_distribution(seeded_store):
    r = run_canned("severity-distribution", seeded_store)
    # critical comes first in the ordering
    assert r.rows[0][0] == "critical"


def test_canned_critical_findings(seeded_store):
    r = run_canned("critical-findings", seeded_store)
    assert r.row_count == 1
    assert r.rows[0][1] == "trapdoor"


def test_canned_mitre_coverage(seeded_store):
    r = run_canned("mitre-coverage", seeded_store)
    techniques = {row[0] for row in r.rows}
    assert "T1195.001" in techniques
    assert "T1041" in techniques


def test_canned_campaign_attributions(seeded_store):
    r = run_canned("campaign-attributions", seeded_store)
    assert r.row_count == 1
    assert r.rows[0][0] == "TrapDoor"


def test_canned_artifacts_by_collector(seeded_store):
    r = run_canned("artifacts-by-collector", seeded_store)
    cols = {row[0]: row[1] for row in r.rows}
    assert cols["processes"] == 2
    assert cols["dns"] == 1


def test_canned_process_tree(seeded_store):
    r = run_canned("process-tree", seeded_store)
    assert r.row_count == 2
    # JSON-extract returns ints from int values
    pids = sorted(row[0] for row in r.rows)
    assert pids == [1, 42]


def test_canned_remediation_commands(seeded_store):
    """At least the anti_forensics seeded finding should appear."""
    r = run_canned("remediation-commands", seeded_store)
    detectors = [row[0] for row in r.rows]
    assert "anti_forensics" in detectors


def test_canned_destructive_warnings(seeded_store):
    r = run_canned("destructive-warnings", seeded_store)
    detectors = [row[0] for row in r.rows]
    assert "exfiltration" in detectors


def test_canned_unknown_name_raises():
    with pytest.raises(QueryError, match="unknown canned query"):
        run_canned("not-a-real-query", "/tmp")


# ---- CLI smoke ---- #


def test_cli_query_list_canned(tmp_path):
    """--list-canned doesn't even need a case dir."""
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "query", "--list-canned"],
        capture_output=True, text=True, timeout=20,
    )
    assert r.returncode == 0
    assert "top-detectors" in r.stdout
    assert "destructive-warnings" in r.stdout


def test_cli_query_canned_text(seeded_store):
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "query", "--case-dir", str(seeded_store),
         "--canned", "top-detectors",
         "--format", "text"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert "detector" in r.stdout
    assert "trapdoor" in r.stdout


def test_cli_query_sql_json(seeded_store):
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "query", "--case-dir", str(seeded_store),
         "--format", "json",
         "SELECT detector, severity FROM findings ORDER BY detector"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    parsed = json.loads(r.stdout)
    assert len(parsed) == 3


def test_cli_query_rejects_drop(seeded_store):
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "query", "--case-dir", str(seeded_store),
         "DROP TABLE findings"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 2
    assert "query error" in r.stderr
