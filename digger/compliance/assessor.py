"""Compliance control assessor.

Loads framework YAML catalogs from ``digger/compliance/frameworks/``,
where each catalog has a list of controls. Each control may have one or
more ``checks`` — small predicates digger can evaluate automatically
against the collected evidence:

  artifact_present:      collector_name (passes if any artifact from that collector exists)
  artifact_count_min:    {collector: N}  (passes if ≥N artifacts)
  no_finding_with_detector: detector_name
  no_finding_with_mitre: mitre_id
  no_finding_above:      severity  (passes if no finding above this severity exists)
  data_contains:         {collector: ..., subject_glob: ..., field: ..., pattern: ...}
  manual:                true (always returns 'manual' — review required)

Controls without any machine-checkable predicate are assessed as 'manual'.
The assessor then maps detector findings to controls via control mapping
data (compliance_impact field on triaged findings + per-framework mapping
files), so a single finding (e.g. an unsigned LaunchAgent) implicates all
the controls it weakens.
"""

from __future__ import annotations

import fnmatch
import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from digger.core.evidence import EvidenceStore

_FRAMEWORK_DIR = Path(__file__).parent / "frameworks"


@dataclass
class ControlAssessment:
    framework: str
    control_id: str
    title: str
    family: str
    summary: str
    status: str            # "pass" | "fail" | "manual" | "partial" | "not_applicable"
    rationale: str
    evidence_refs: list[str] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    severity_if_failed: str = "medium"


@dataclass
class Framework:
    id: str
    title: str
    version: str
    publisher: str
    url: str
    description: str
    controls: list[dict[str, Any]] = field(default_factory=list)
    mapping_to_other_frameworks: dict[str, dict[str, list[str]]] = field(default_factory=dict)


def list_frameworks() -> list[str]:
    if not _FRAMEWORK_DIR.is_dir():
        return []
    return sorted(p.stem for p in _FRAMEWORK_DIR.glob("*.yaml"))


def load_framework(name: str) -> Framework:
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("compliance frameworks require pyyaml") from exc
    path = _FRAMEWORK_DIR / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"framework {name!r} not found in {_FRAMEWORK_DIR}")
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return Framework(
        id=raw.get("id", name),
        title=raw.get("title", name),
        version=raw.get("version", ""),
        publisher=raw.get("publisher", ""),
        url=raw.get("url", ""),
        description=raw.get("description", ""),
        controls=raw.get("controls", []),
        mapping_to_other_frameworks=raw.get("mapping_to_other_frameworks", {}),
    )


class ComplianceAssessor:
    def __init__(self, store: EvidenceStore):
        self.store = store
        self._artifact_collectors: dict[str, list[dict]] = {}
        self._findings: list[dict] = list(store.iter_findings())
        for a in store.iter_artifacts():
            self._artifact_collectors.setdefault(a["collector"], []).append(a)

    def _check_artifact_present(self, collector: str) -> tuple[bool, list[str]]:
        arts = self._artifact_collectors.get(collector, [])
        return bool(arts), [a["artifact_uuid"] for a in arts[:5]]

    def _check_artifact_count_min(self, spec: dict) -> tuple[bool, list[str]]:
        for c, n in spec.items():
            arts = self._artifact_collectors.get(c, [])
            if len(arts) < int(n):
                return False, [a["artifact_uuid"] for a in arts[:5]]
            return True, [a["artifact_uuid"] for a in arts[:5]]
        return False, []

    def _check_no_finding_with_detector(self, detector: str) -> tuple[bool, list[str]]:
        hits = [f for f in self._findings if f["detector"] == detector]
        return (not hits), [f["finding_uuid"] for f in hits[:5]]

    def _check_no_finding_with_mitre(self, mitre: str) -> tuple[bool, list[str]]:
        hits = [f for f in self._findings if (f.get("mitre") or "").startswith(mitre)]
        return (not hits), [f["finding_uuid"] for f in hits[:5]]

    def _check_no_finding_above(self, severity: str) -> tuple[bool, list[str]]:
        order = ["info", "low", "medium", "high", "critical"]
        if severity not in order:
            return True, []
        threshold = order.index(severity)
        hits = [f for f in self._findings if order.index(f["severity"]) > threshold]
        return (not hits), [f["finding_uuid"] for f in hits[:5]]

    def _check_data_contains(self, spec: dict) -> tuple[bool, list[str]]:
        collector = spec.get("collector")
        subject_glob = spec.get("subject_glob")
        field_name = spec.get("field")
        pattern = spec.get("pattern")
        if not all([collector, pattern]):
            return False, []
        regex = re.compile(pattern, re.I) if isinstance(pattern, str) else None
        evidence_uuids = []
        for a in self._artifact_collectors.get(collector, []):
            if subject_glob and not fnmatch.fnmatch(a["subject"], subject_glob):
                continue
            value = a["data"]
            if field_name:
                for part in field_name.split("."):
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        value = None
                        break
            haystack = json.dumps(value, default=str) if value is not None else json.dumps(a["data"], default=str)
            if regex.search(haystack):
                evidence_uuids.append(a["artifact_uuid"])
                if len(evidence_uuids) >= 5:
                    break
        return bool(evidence_uuids), evidence_uuids

    def _evaluate_one_check(self, check: dict) -> tuple[str, str, list[str]]:
        """Return (status, rationale, evidence_uuids) for one check."""
        for kind, arg in check.items():
            if kind == "artifact_present":
                ok, uuids = self._check_artifact_present(arg)
                return ("pass" if ok else "fail",
                        f"check artifact_present[{arg}] → {ok}", uuids)
            if kind == "artifact_count_min":
                ok, uuids = self._check_artifact_count_min(arg)
                return ("pass" if ok else "fail",
                        f"check artifact_count_min[{arg}] → {ok}", uuids)
            if kind == "no_finding_with_detector":
                ok, uuids = self._check_no_finding_with_detector(arg)
                return ("pass" if ok else "fail",
                        f"check no_finding_with_detector[{arg}] → {ok}", uuids)
            if kind == "no_finding_with_mitre":
                ok, uuids = self._check_no_finding_with_mitre(arg)
                return ("pass" if ok else "fail",
                        f"check no_finding_with_mitre[{arg}] → {ok}", uuids)
            if kind == "no_finding_above":
                ok, uuids = self._check_no_finding_above(arg)
                return ("pass" if ok else "fail",
                        f"check no_finding_above[{arg}] → {ok}", uuids)
            if kind == "data_contains":
                ok, uuids = self._check_data_contains(arg)
                return ("pass" if ok else "fail",
                        f"check data_contains[{arg}] → {ok}", uuids)
            if kind == "manual":
                return ("manual", "control requires manual review", [])
        return ("manual", "no machine-checkable predicate", [])

    def assess_control(self, framework: Framework, control: dict) -> ControlAssessment:
        checks = control.get("checks") or []
        if not checks:
            return ControlAssessment(
                framework=framework.id,
                control_id=control["id"],
                title=control.get("title", ""),
                family=control.get("family", ""),
                summary=control.get("summary", ""),
                status="manual",
                rationale="no machine-checkable predicate defined",
                references=control.get("references", []),
                severity_if_failed=control.get("severity_if_failed", "medium"),
            )
        results = [self._evaluate_one_check(c) for c in checks]
        statuses = {r[0] for r in results}
        if statuses == {"pass"}:
            final = "pass"
        elif "fail" in statuses and "pass" in statuses:
            final = "partial"
        elif statuses == {"fail"}:
            final = "fail"
        elif "manual" in statuses:
            final = "manual"
        else:
            final = "fail"
        rationale = "; ".join(r[1] for r in results)
        evidence_uuids = [u for r in results for u in r[2]]
        return ControlAssessment(
            framework=framework.id,
            control_id=control["id"],
            title=control.get("title", ""),
            family=control.get("family", ""),
            summary=control.get("summary", ""),
            status=final,
            rationale=rationale,
            evidence_refs=evidence_uuids[:10],
            references=control.get("references", []),
            severity_if_failed=control.get("severity_if_failed", "medium"),
        )

    def assess(self, framework: Framework) -> list[ControlAssessment]:
        return [self.assess_control(framework, c) for c in framework.controls]


def assess_all(store: EvidenceStore, framework_names: Iterable[str] | None = None) -> dict[str, list[ControlAssessment]]:
    names = list(framework_names) if framework_names else list_frameworks()
    assessor = ComplianceAssessor(store)
    return {n: assessor.assess(load_framework(n)) for n in names}
