"""ELK / OpenSearch _bulk NDJSON exporter.

Two surfaces:

  ``ElkExporter``  — serializes a whole case (artifacts + findings) into
                     bulk-API NDJSON for ``curl -X POST <es>/_bulk
                     --data-binary @file.ndjson``.

  ``ElkBulkSink``  — watch-daemon sink that POSTs each new-findings
                     batch live to a running ES/OpenSearch cluster.

Field mapping aligns to Elastic Common Schema (ECS) where natural —
``@timestamp``, ``event.kind``, ``event.category``, ``event.severity``,
``host.name``, ``rule.name``, ``threat.technique.id``. Digger-specific
fields are namespaced under ``digger.*`` to keep them out of ECS's way.

Bulk-API format
---------------
NDJSON, two lines per document::

  {"index": {"_index": "digger-findings", "_id": "<finding_uuid>"}}
  {"@timestamp": "...", "event.kind": "alert", ...}

Trailing newline required. Index name defaults to ``digger-findings``
and ``digger-artifacts``; both are overridable.

ECS severity scale: ``info=0 → critical=4`` mapped to ECS
``event.severity`` integer 1-100 (info=10, low=25, medium=50,
high=75, critical=100). Some SIEM dashboards key visual color on
this scale.
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Iterable


# ---- ECS severity scale ---- #

_ECS_SEVERITY = {
    "info":     10,
    "low":      25,
    "medium":   50,
    "high":     75,
    "critical": 100,
}


def _iso8601(ts: float) -> str:
    """ECS @timestamp wants RFC3339-with-Z UTC."""
    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


# ---- Finding → ECS doc ---- #


def finding_to_ecs(
    f: dict[str, Any], *,
    case_id: str = "",
    host_name: str = "",
) -> dict[str, Any]:
    """Map a digger finding dict to an ECS-shaped JSON document."""
    sev_name = f.get("severity") or "info"
    mitre = (f.get("mitre") or "").strip()
    ev = f.get("evidence") or {}
    ts = f.get("ts") or time.time()

    doc: dict[str, Any] = {
        "@timestamp":     _iso8601(ts),
        "event.kind":     "alert",
        "event.category": ["intrusion_detection"],
        "event.module":   "digger",
        "event.dataset":  "digger.findings",
        "event.severity": _ECS_SEVERITY.get(sev_name, 10),
        "event.original": (f.get("summary") or "")[:32_000],
        "host.name":      host_name,
        "rule.name":      f.get("detector") or "",
        "rule.uuid":      f.get("finding_uuid") or "",
        "message":        f.get("title") or "",
        # Digger-namespaced fields (out of ECS's way)
        "digger.case_id":         case_id,
        "digger.detector":        f.get("detector") or "",
        "digger.severity":        sev_name,
        "digger.evidence":        ev,
        "digger.artifact_refs":   f.get("artifact_refs") or [],
    }
    if mitre:
        # ECS threat.* fields
        doc["threat.framework"]    = "MITRE ATT&CK"
        doc["threat.technique.id"] = mitre
        doc["digger.mitre"]        = mitre

    # ECS source / destination / file when the evidence carries them
    for ev_key, ecs_key in (
        ("remote_ip",     "destination.ip"),
        ("ip",            "destination.ip"),
        ("domain",        "destination.domain"),
        ("host",          "destination.domain"),
        ("path",          "file.path"),
        ("hash",          "file.hash.sha256"),
        ("sha256",        "file.hash.sha256"),
        ("sha1",          "file.hash.sha1"),
        ("md5",           "file.hash.md5"),
        ("pid",           "process.pid"),
        ("ppid",          "process.parent.pid"),
        ("name",          "process.name"),
        ("exe",           "process.executable"),
        ("cmdline",       "process.command_line"),
        ("username",      "user.name"),
    ):
        v = ev.get(ev_key)
        if v is not None and v != "":
            doc[ecs_key] = v

    # Storyline / campaign tagging
    if ev.get("campaign"):
        doc["threat.group.name"] = ev["campaign"]
        doc["digger.campaign"]   = ev["campaign"]

    return doc


# ---- Artifact → ECS-ish doc ---- #


def artifact_to_ecs(
    a: dict[str, Any], *,
    case_id: str = "",
    host_name: str = "",
) -> dict[str, Any]:
    """Map a digger artifact dict to a shipping-friendly doc.

    Artifacts are heterogeneous so we don't try to deeply ECS-map them
    — we ship the raw data under ``digger.artifact_data`` and stamp
    @timestamp + a few cross-cutting fields. Operators can build
    Kibana visualizations on top via runtime fields."""
    ts = a.get("ts") or time.time()
    return {
        "@timestamp":         _iso8601(ts),
        "event.kind":         "state",
        "event.module":       "digger",
        "event.dataset":      "digger.artifacts",
        "host.name":          host_name,
        "digger.case_id":     case_id,
        "digger.collector":   a.get("collector") or "",
        "digger.category":    a.get("category") or "",
        "digger.subject":     a.get("subject") or "",
        "digger.artifact_uuid": a.get("artifact_uuid") or "",
        "digger.data_sha256": a.get("data_sha256") or "",
        "digger.artifact_data": a.get("data") or {},
    }


# ---- Bulk NDJSON ---- #


def bulk_lines(
    docs: Iterable[tuple[dict[str, Any], str | None]],
    *,
    index: str,
    op: str = "index",
) -> Iterable[str]:
    """Yield bulk-API NDJSON lines.

    Each input is a ``(doc, doc_id)`` tuple. ``doc_id`` may be None
    (let ES auto-assign), or a stable id (e.g., finding_uuid) so
    re-shipping is idempotent.

    ``op`` selects ``index`` (upsert), ``create`` (fail-on-exists), or
    ``update`` (partial-update with ``doc`` body). Use ``index`` for
    findings/artifacts so the same finding shipped twice updates in
    place rather than duplicating.
    """
    for doc, doc_id in docs:
        action: dict[str, Any] = {op: {"_index": index}}
        if doc_id:
            action[op]["_id"] = doc_id
        yield json.dumps(action, default=str)
        # For `update`, payload must be wrapped in {"doc": ...}
        body = {"doc": doc} if op == "update" else doc
        yield json.dumps(body, default=str)


# ---- Whole-case exporter ---- #


@dataclass
class ElkExporter:
    findings_index: str = "digger-findings"
    artifacts_index: str = "digger-artifacts"
    op: str = "index"  # index | create | update

    def dump_findings(
        self, store, *,
        case_id: str = "", host_name: str = "",
    ) -> Iterable[str]:
        for f in store.iter_findings():
            doc = finding_to_ecs(f, case_id=case_id, host_name=host_name)
            yield from bulk_lines(
                [(doc, f.get("finding_uuid"))],
                index=self.findings_index, op=self.op,
            )

    def dump_artifacts(
        self, store, *,
        case_id: str = "", host_name: str = "",
    ) -> Iterable[str]:
        for a in store.iter_artifacts():
            doc = artifact_to_ecs(a, case_id=case_id, host_name=host_name)
            yield from bulk_lines(
                [(doc, a.get("artifact_uuid"))],
                index=self.artifacts_index, op=self.op,
            )

    def dump_all(
        self, store, *,
        case_id: str = "", host_name: str = "",
        include_artifacts: bool = True,
    ) -> Iterable[str]:
        yield from self.dump_findings(
            store, case_id=case_id, host_name=host_name,
        )
        if include_artifacts:
            yield from self.dump_artifacts(
                store, case_id=case_id, host_name=host_name,
            )

    def write_file(
        self, store, out_path, *,
        case_id: str = "", host_name: str = "",
        include_artifacts: bool = True,
    ) -> int:
        """Write the full bulk NDJSON to ``out_path``. Returns line count."""
        from pathlib import Path
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with out_path.open("w", encoding="utf-8") as fh:
            for line in self.dump_all(
                store, case_id=case_id, host_name=host_name,
                include_artifacts=include_artifacts,
            ):
                fh.write(line + "\n")
                n += 1
        return n


# ---- Watch-daemon sink ---- #


@dataclass
class ElkBulkSink:
    """Watch sink that POSTs new findings to ES/OpenSearch _bulk.

    URL is the base ES endpoint, e.g. ``http://localhost:9200``. We
    append ``/_bulk`` ourselves. Optional API-key / basic-auth headers
    pass through via ``headers``. Errors are logged-and-continued —
    a failing ES cluster never crashes the watch loop."""
    url: str
    findings_index: str = "digger-findings"
    timeout_s: float = 10.0
    headers: dict[str, str] = field(default_factory=dict)
    case_id: str = ""
    host_name: str = ""
    op: str = "index"
    _stderr: Any = None

    def emit(self, findings: list[dict[str, Any]], tick: int) -> None:
        if not findings:
            return
        stderr = self._stderr or sys.stderr
        try:
            import requests
        except ImportError:
            print("[elk] requests not installed; cannot POST _bulk",
                  file=stderr, flush=True)
            return
        # Build the NDJSON body
        lines: list[str] = []
        for f in findings:
            doc = finding_to_ecs(
                f, case_id=self.case_id, host_name=self.host_name,
            )
            for line in bulk_lines(
                [(doc, f.get("finding_uuid"))],
                index=self.findings_index, op=self.op,
            ):
                lines.append(line)
        body = "\n".join(lines) + "\n"
        endpoint = self.url.rstrip("/") + "/_bulk"
        try:
            requests.post(
                endpoint, data=body,
                timeout=self.timeout_s,
                headers={
                    "Content-Type": "application/x-ndjson",
                    **self.headers,
                },
            )
        except Exception as exc:
            print(f"[elk] _bulk POST failed: {exc!r}",
                  file=stderr, flush=True)
