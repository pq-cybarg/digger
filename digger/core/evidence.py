"""Evidence store — SQLite-backed, append-only, tamper-evident.

Every artifact and finding row carries TWO independent content hashes
(SHA-256 and SHA3-256) and TWO independent chain hashes. The two chains
thread through the table in parallel:

    chain_sha256[n]   = SHA-256  ( chain_sha256[n-1]   || data_sha256[n]   )
    chain_sha3_256[n] = SHA3-256 ( chain_sha3_256[n-1] || data_sha3_256[n] )

SHA-256 stays for ecosystem interop (IOC feeds, VirusTotal, MalwareBazaar,
signature-base, git/sigstore consumers all speak SHA-256). SHA3-256 is the
Keccak sponge — a structurally independent construction from SHA-2 — so
a future cryptanalytic break against one family does not collapse the
other. Forging undetectable tampering requires breaking both at once.

The PQC signature emitted by ``digger pqc sign`` covers both chain tips
in one signed payload, so verifying the signature also attests to both
algorithms simultaneously.

Use ``verify_chain()`` to revalidate. It returns a per-algorithm report.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS case_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_uuid TEXT UNIQUE NOT NULL,
    collector TEXT NOT NULL,
    category TEXT NOT NULL,
    subject TEXT NOT NULL,
    ts REAL NOT NULL,
    data_json TEXT NOT NULL,
    data_sha256    TEXT NOT NULL,
    data_sha3_256  TEXT NOT NULL,
    chain_sha256   TEXT NOT NULL,
    chain_sha3_256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_collector ON artifacts(collector);
CREATE INDEX IF NOT EXISTS idx_artifacts_category ON artifacts(category);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_uuid TEXT UNIQUE NOT NULL,
    detector TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    artifact_refs TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    mitre TEXT NOT NULL DEFAULT '',
    ts REAL NOT NULL,
    data_sha256    TEXT NOT NULL DEFAULT '',
    data_sha3_256  TEXT NOT NULL DEFAULT '',
    chain_sha256   TEXT NOT NULL,
    chain_sha3_256 TEXT NOT NULL,
    triage_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_detector ON findings(detector);

CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    sha256    TEXT NOT NULL,
    sha3_256  TEXT NOT NULL DEFAULT '',
    seen_ts REAL NOT NULL,
    artifact_uuid TEXT
);

CREATE TABLE IF NOT EXISTS log (
    ts REAL NOT NULL,
    level TEXT NOT NULL,
    msg TEXT NOT NULL
);
"""

SEVERITIES = ("info", "low", "medium", "high", "critical")


def _hash_pair(data: bytes) -> dict[str, str]:
    return {
        "sha256":   hashlib.sha256(data).hexdigest(),
        "sha3_256": hashlib.sha3_256(data).hexdigest(),
    }


def _chain_step_pair(prev: dict[str, str], content: dict[str, str]) -> dict[str, str]:
    """Both-algorithm chain step. Each algorithm chains independently."""
    h2 = hashlib.sha256()
    h2.update(bytes.fromhex(prev["sha256"]) if prev["sha256"] else b"")
    h2.update(bytes.fromhex(content["sha256"]))

    h3 = hashlib.sha3_256()
    h3.update(bytes.fromhex(prev["sha3_256"]) if prev["sha3_256"] else b"")
    h3.update(bytes.fromhex(content["sha3_256"]))

    return {"sha256": h2.hexdigest(), "sha3_256": h3.hexdigest()}


@dataclass
class Artifact:
    collector: str
    category: str
    subject: str
    data: dict[str, Any]
    ts: float = field(default_factory=time.time)
    artifact_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))

    def canonical_json(self) -> str:
        return json.dumps(self.data, sort_keys=True, separators=(",", ":"), default=str)

    def content_payload(self) -> bytes:
        return f"{self.collector}|{self.category}|{self.subject}|{self.canonical_json()}".encode("utf-8")

    def content_hashes(self) -> dict[str, str]:
        """Return both SHA-256 and SHA3-256 of the canonical content."""
        return _hash_pair(self.content_payload())

    # Back-compat: callers can still ask for just the SHA-256 digest.
    def content_sha256(self) -> str:
        return self.content_hashes()["sha256"]

    def content_sha3_256(self) -> str:
        return self.content_hashes()["sha3_256"]


@dataclass
class Finding:
    detector: str
    severity: str
    title: str
    summary: str
    artifact_refs: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    mitre: str = ""
    ts: float = field(default_factory=time.time)
    finding_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    triage: Optional[dict[str, Any]] = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}; must be one of {SEVERITIES}")


class EvidenceStore:
    def __init__(self, case_dir: str | Path):
        self.case_dir = Path(case_dir)
        self.case_dir.mkdir(parents=True, exist_ok=True)
        (self.case_dir / "files").mkdir(exist_ok=True)
        self.db_path = self.case_dir / "evidence.db"
        self._conn = sqlite3.connect(self.db_path)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # ---- case metadata ------------------------------------------------- #

    def set_meta(self, key: str, value: Any) -> None:
        v = json.dumps(value, default=str) if not isinstance(value, str) else value
        self._conn.execute(
            "INSERT INTO case_meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, v),
        )
        self._conn.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self._conn.execute("SELECT value FROM case_meta WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            return row[0]

    # ---- paired hash chain --------------------------------------------- #

    def _last_chain(self, table: str) -> dict[str, str]:
        row = self._conn.execute(
            f"SELECT chain_sha256, chain_sha3_256 FROM {table} ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return {"sha256": "", "sha3_256": ""}
        return {"sha256": row[0], "sha3_256": row[1]}

    # ---- artifacts ----------------------------------------------------- #

    def add_artifact(self, art: Artifact) -> str:
        data_json = art.canonical_json()
        content = art.content_hashes()
        prev = self._last_chain("artifacts")
        chain = _chain_step_pair(prev, content)
        self._conn.execute(
            "INSERT INTO artifacts"
            "(artifact_uuid,collector,category,subject,ts,data_json,"
            " data_sha256,data_sha3_256,chain_sha256,chain_sha3_256) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                art.artifact_uuid,
                art.collector,
                art.category,
                art.subject,
                art.ts,
                data_json,
                content["sha256"], content["sha3_256"],
                chain["sha256"], chain["sha3_256"],
            ),
        )
        self._conn.commit()
        return art.artifact_uuid

    def add_artifacts(self, arts: Iterable[Artifact]) -> list[str]:
        return [self.add_artifact(a) for a in arts]

    def iter_artifacts(
        self,
        collector: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Iterator[dict[str, Any]]:
        q = "SELECT artifact_uuid,collector,category,subject,ts,data_json FROM artifacts"
        params: list[Any] = []
        clauses: list[str] = []
        if collector:
            clauses.append("collector=?")
            params.append(collector)
        if category:
            clauses.append("category=?")
            params.append(category)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY id"
        for row in self._conn.execute(q, params):
            yield {
                "artifact_uuid": row[0],
                "collector": row[1],
                "category": row[2],
                "subject": row[3],
                "ts": row[4],
                "data": json.loads(row[5]),
            }

    # ---- findings ------------------------------------------------------ #

    def _finding_content_payload(self, f: "Finding", evidence_json: str, refs_json: str) -> bytes:
        return f"{f.detector}|{f.severity}|{f.title}|{f.summary}|{refs_json}|{evidence_json}|{f.mitre}".encode("utf-8")

    def add_finding(self, f: Finding) -> str:
        evidence_json = json.dumps(f.evidence, sort_keys=True, default=str)
        refs_json = json.dumps(f.artifact_refs)
        payload = self._finding_content_payload(f, evidence_json, refs_json)
        content = _hash_pair(payload)
        prev = self._last_chain("findings")
        chain = _chain_step_pair(prev, content)
        self._conn.execute(
            "INSERT INTO findings"
            "(finding_uuid,detector,severity,title,summary,artifact_refs,evidence_json,mitre,ts,"
            " data_sha256,data_sha3_256,chain_sha256,chain_sha3_256,triage_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                f.finding_uuid,
                f.detector,
                f.severity,
                f.title,
                f.summary,
                refs_json,
                evidence_json,
                f.mitre,
                f.ts,
                content["sha256"], content["sha3_256"],
                chain["sha256"], chain["sha3_256"],
                json.dumps(f.triage) if f.triage is not None else None,
            ),
        )
        self._conn.commit()
        return f.finding_uuid

    def update_triage(self, finding_uuid: str, triage: dict[str, Any]) -> None:
        self._conn.execute(
            "UPDATE findings SET triage_json=? WHERE finding_uuid=?",
            (json.dumps(triage, default=str), finding_uuid),
        )
        self._conn.commit()

    def iter_findings(self, severity_min: Optional[str] = None) -> Iterator[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT finding_uuid,detector,severity,title,summary,artifact_refs,"
            "evidence_json,mitre,ts,triage_json FROM findings ORDER BY id"
        )
        min_idx = SEVERITIES.index(severity_min) if severity_min else 0
        for row in rows:
            if SEVERITIES.index(row[2]) < min_idx:
                continue
            yield {
                "finding_uuid": row[0],
                "detector": row[1],
                "severity": row[2],
                "title": row[3],
                "summary": row[4],
                "artifact_refs": json.loads(row[5]),
                "evidence": json.loads(row[6]) if row[6] else {},
                "mitre": row[7],
                "ts": row[8],
                "triage": json.loads(row[9]) if row[9] else None,
            }

    # ---- files (preserved evidence files) ------------------------------ #

    def record_file(
        self,
        source_path: str | Path,
        sha256: str,
        size: int,
        artifact_uuid: str | None = None,
        sha3_256: str = "",
    ) -> None:
        self._conn.execute(
            "INSERT INTO files(path,size,sha256,sha3_256,seen_ts,artifact_uuid) "
            "VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256, "
            "sha3_256=excluded.sha3_256, size=excluded.size, seen_ts=excluded.seen_ts",
            (str(source_path), size, sha256, sha3_256, time.time(), artifact_uuid),
        )
        self._conn.commit()

    # ---- log ----------------------------------------------------------- #

    def log(self, level: str, msg: str) -> None:
        self._conn.execute(
            "INSERT INTO log(ts,level,msg) VALUES(?,?,?)",
            (time.time(), level, msg),
        )
        self._conn.commit()

    # ---- chain verification ------------------------------------------- #

    def verify_chain(self) -> dict[str, Any]:
        """Re-validate both content hashes and both chain hashes per table.

        Returns:
            {
              "artifacts_ok": {"sha256": bool, "sha3_256": bool, "any": bool},
              "findings_ok":  {"sha256": bool, "sha3_256": bool, "any": bool},
              "errors": [...]
            }

            Top-level convenience keys "artifacts_ok" / "findings_ok" each
            also expose a boolean ``"all"`` — both algorithms validated.
        """
        out: dict[str, Any] = {
            "artifacts_ok": {"sha256": True, "sha3_256": True},
            "findings_ok":  {"sha256": True, "sha3_256": True},
            "errors": [],
        }

        # Artifacts
        prev = {"sha256": "", "sha3_256": ""}
        for row in self._conn.execute(
            "SELECT id,collector,category,subject,data_json,"
            "       data_sha256,data_sha3_256,chain_sha256,chain_sha3_256 "
            "FROM artifacts ORDER BY id"
        ):
            (rid, collector, category, subject, data_json,
             d2, d3, c2, c3) = row
            payload = f"{collector}|{category}|{subject}|{data_json}".encode("utf-8")
            recomputed = _hash_pair(payload)
            if recomputed["sha256"] != d2:
                out["artifacts_ok"]["sha256"] = False
                out["errors"].append(f"artifact id={rid} SHA-256 content hash mismatch")
            if recomputed["sha3_256"] != d3:
                out["artifacts_ok"]["sha3_256"] = False
                out["errors"].append(f"artifact id={rid} SHA3-256 content hash mismatch")
            step = _chain_step_pair(prev, recomputed)
            if step["sha256"] != c2:
                out["artifacts_ok"]["sha256"] = False
                out["errors"].append(f"artifact id={rid} SHA-256 chain hash mismatch")
            if step["sha3_256"] != c3:
                out["artifacts_ok"]["sha3_256"] = False
                out["errors"].append(f"artifact id={rid} SHA3-256 chain hash mismatch")
            prev = {"sha256": c2, "sha3_256": c3}

        # Findings
        prev = {"sha256": "", "sha3_256": ""}
        for row in self._conn.execute(
            "SELECT id,detector,severity,title,summary,artifact_refs,evidence_json,mitre,"
            "       data_sha256,data_sha3_256,chain_sha256,chain_sha3_256 "
            "FROM findings ORDER BY id"
        ):
            (rid, det, sev, title, summary, refs, ev, mitre,
             d2, d3, c2, c3) = row
            payload = f"{det}|{sev}|{title}|{summary}|{refs}|{ev}|{mitre}".encode("utf-8")
            recomputed = _hash_pair(payload)
            if d2 and recomputed["sha256"] != d2:
                out["findings_ok"]["sha256"] = False
                out["errors"].append(f"finding id={rid} SHA-256 content hash mismatch")
            if d3 and recomputed["sha3_256"] != d3:
                out["findings_ok"]["sha3_256"] = False
                out["errors"].append(f"finding id={rid} SHA3-256 content hash mismatch")
            step = _chain_step_pair(prev, recomputed)
            if step["sha256"] != c2:
                out["findings_ok"]["sha256"] = False
                out["errors"].append(f"finding id={rid} SHA-256 chain hash mismatch")
            if step["sha3_256"] != c3:
                out["findings_ok"]["sha3_256"] = False
                out["errors"].append(f"finding id={rid} SHA3-256 chain hash mismatch")
            prev = {"sha256": c2, "sha3_256": c3}

        out["artifacts_ok"]["all"] = (
            out["artifacts_ok"]["sha256"] and out["artifacts_ok"]["sha3_256"]
        )
        out["findings_ok"]["all"] = (
            out["findings_ok"]["sha256"] and out["findings_ok"]["sha3_256"]
        )
        return out

    def chain_tip(self) -> dict[str, Any]:
        """Both chain tips per table — what ``digger pqc sign`` covers.

        Shape::
            {
                "artifacts": {"sha256": "...", "sha3_256": "..."},
                "findings":  {"sha256": "...", "sha3_256": "..."},
                "case_id": "...",
                "algorithms": ["SHA-256", "SHA3-256"],
            }
        """
        return {
            "artifacts": self._last_chain("artifacts"),
            "findings":  self._last_chain("findings"),
            "case_id": str(self.get_meta("case_id", "")),
            "algorithms": ["SHA-256", "SHA3-256"],
        }

    def chain_tip_message(self) -> bytes:
        """Canonical bytes form of the chain tip — the actual signed payload."""
        return json.dumps(self.chain_tip(), sort_keys=True).encode("utf-8")

    def counts(self) -> dict[str, Any]:
        a = self._conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        f = self._conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        by_sev = {
            sev: self._conn.execute("SELECT COUNT(*) FROM findings WHERE severity=?", (sev,)).fetchone()[0]
            for sev in SEVERITIES
        }
        by_collector = dict(
            self._conn.execute("SELECT collector, COUNT(*) FROM artifacts GROUP BY collector")
        )
        return {
            "artifacts": a,
            "findings": f,
            "by_severity": by_sev,
            "by_collector": by_collector,
        }

    # ---- lifecycle ---------------------------------------------------- #

    def close(self) -> None:
        try:
            self._conn.commit()
            self._conn.close()
        except sqlite3.ProgrammingError:
            pass

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def __enter__(self) -> "EvidenceStore":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
