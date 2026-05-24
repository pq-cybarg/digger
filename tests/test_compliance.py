"""Compliance assessor end-to-end."""

from __future__ import annotations

from pathlib import Path

from digger.compliance import ComplianceAssessor, list_frameworks, load_framework
from digger.core import Artifact, EvidenceStore, Finding


def test_frameworks_are_loadable():
    names = list_frameworks()
    assert len(names) >= 8, f"expected at least 8 frameworks, got {names}"
    # Critical frameworks must be present
    for required in [
        "nist_800_53", "nist_800_171", "nist_csf_2", "cmmc_2_0",
        "iso_27001", "iso_27037", "pci_dss_4_0", "hipaa_security_rule",
        "gdpr", "nis2", "essential_eight", "icd_503",
    ]:
        assert required in names, f"missing framework: {required}"
        f = load_framework(required)
        assert f.controls, f"{required} has no controls"


def test_assessor_returns_per_control_assessments(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    # Seed a few artifacts that should make at least some controls pass
    store.add_artifact(Artifact(collector="users", category="identity", subject="account=root", data={}))
    store.add_artifact(Artifact(collector="processes", category="process", subject="pid=1", data={"pid": 1}))
    store.add_artifact(Artifact(collector="network", category="network", subject="nic=lo0", data={}))
    nist = load_framework("nist_800_53")
    results = ComplianceAssessor(store).assess(nist)
    assert len(results) == len(nist.controls)
    statuses = {r.status for r in results}
    assert "pass" in statuses or "partial" in statuses or "manual" in statuses
    store.close()


def test_assessor_detects_failure(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    store.add_finding(Finding(
        detector="c2", severity="critical",
        title="Cobalt Strike beacon", summary="x",
    ))
    iso = load_framework("iso_27001")
    results = ComplianceAssessor(store).assess(iso)
    # A.8.7 (malware protection) has multiple checks; with a c2 finding
    # present, at least one check fails, so the control must be fail or partial.
    bad = [r for r in results if r.status in ("fail", "partial")]
    assert any("8.7" in r.control_id for r in bad), bad
    store.close()
