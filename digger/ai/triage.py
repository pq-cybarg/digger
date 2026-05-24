"""Run AI triage over the findings in an evidence store."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from digger.ai.llama_client import LLMClient, LLMConfig, LLMError
from digger.ai.prompts import SYSTEM, SYSTEM_CASE, case_user_prompt, finding_user_prompt
from digger.core.evidence import EvidenceStore


@dataclass
class TriageOptions:
    skip_below: str = "low"            # don't triage info-level findings by default
    only_detectors: Optional[list[str]] = None
    max_findings: Optional[int] = None
    case_summary: bool = True


_FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": [
            "false_positive", "likely_benign", "needs_investigation",
            "likely_malicious", "confirmed_malicious",
        ]},
        "estimative_probability": {"type": "string", "enum": [
            "almost no chance", "very unlikely", "unlikely",
            "roughly even chance", "likely", "very likely", "almost certain",
        ]},
        "analytic_confidence": {"type": "string", "enum": ["low", "moderate", "high"]},
        "source_reliability": {"type": "string", "enum": ["A", "B", "C", "D", "E", "F"]},
        "info_credibility": {"type": "string", "enum": ["1", "2", "3", "4", "5", "6"]},
        "tlp": {"type": "string", "enum": [
            "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED",
        ]},
        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
        "one_line": {"type": "string"},
        "rationale": {"type": "string"},
        "assumptions": {"type": "array", "items": {"type": "string"}},
        "alternative_hypotheses": {"type": "array", "items": {"type": "string"}},
        "next_steps": {"type": "array", "items": {"type": "string"}},
        "attribution": {"type": ["string", "null"]},
        "iocs": {
            "type": "object",
            "properties": {
                "sha256": {"type": "array", "items": {"type": "string"}},
                "ipv4": {"type": "array", "items": {"type": "string"}},
                "domain": {"type": "array", "items": {"type": "string"}},
                "url": {"type": "array", "items": {"type": "string"}},
                "path": {"type": "array", "items": {"type": "string"}},
            },
        },
        "mitre_attack": {"type": "array", "items": {"type": "string"}},
        "compliance_impact": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "verdict", "estimative_probability", "analytic_confidence",
        "source_reliability", "info_credibility", "tlp",
        "severity", "one_line", "rationale", "next_steps",
    ],
}


class TriageRunner:
    def __init__(self, client: Optional[LLMClient] = None, options: Optional[TriageOptions] = None):
        self.client = client or LLMClient()
        self.options = options or TriageOptions()

    def _eligible(self, finding: dict) -> bool:
        order = ["info", "low", "medium", "high", "critical"]
        if order.index(finding["severity"]) < order.index(self.options.skip_below):
            return False
        if self.options.only_detectors and finding["detector"] not in self.options.only_detectors:
            return False
        return True

    def run(self, store: EvidenceStore) -> dict:
        host = store.get_meta("host") or {}
        triaged = []
        skipped = 0
        errors = 0
        n = 0

        artifacts_by_uuid = {a["artifact_uuid"]: a for a in store.iter_artifacts()}

        for finding in store.iter_findings():
            if not self._eligible(finding):
                skipped += 1
                continue
            if self.options.max_findings and n >= self.options.max_findings:
                break
            artifacts = [
                artifacts_by_uuid[u] for u in finding.get("artifact_refs", [])
                if u in artifacts_by_uuid
            ]
            user_prompt = finding_user_prompt(host, finding, artifacts)
            try:
                triage = self.client.json_chat(
                    [
                        {"role": "system", "content": SYSTEM},
                        {"role": "user", "content": user_prompt},
                    ],
                    schema=_FINDING_SCHEMA,
                )
                triage["triaged_at"] = time.time()
                triage["model"] = self.client.config.model
                store.update_triage(finding["finding_uuid"], triage)
                triaged.append({**finding, "triage": triage})
                n += 1
            except LLMError as exc:
                store.log("error", f"triage failed for {finding['finding_uuid']}: {exc}")
                errors += 1

        case_summary = None
        if self.options.case_summary and triaged:
            try:
                case_summary = self.client.json_chat(
                    [
                        {"role": "system", "content": SYSTEM_CASE},
                        {"role": "user", "content": case_user_prompt(host, triaged)},
                    ],
                )
                case_summary["produced_at"] = time.time()
                case_summary["model"] = self.client.config.model
                store.set_meta("ai_case_summary", case_summary)
            except LLMError as exc:
                store.log("error", f"case summary failed: {exc}")

        store.set_meta("ai_triage_run", {
            "triaged": n,
            "skipped": skipped,
            "errors": errors,
            "completed_at": time.time(),
            "model": self.client.config.model,
            "base_url": self.client.config.base_url,
        })
        return {
            "triaged": n,
            "skipped": skipped,
            "errors": errors,
            "case_summary": case_summary,
        }
