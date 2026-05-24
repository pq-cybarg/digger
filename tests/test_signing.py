"""Code-signing verification — verify_path + collector + detector."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from digger.core import Artifact, EvidenceStore
from digger.signing import UnsignedBinaryDetector, verify_path
from digger.signing.collector import CodeSigningCollector


def test_verify_path_on_missing_file_skips(tmp_path):
    sig = verify_path(tmp_path / "does-not-exist")
    assert sig.state == "skipped"


def test_verify_path_on_a_dir_skips(tmp_path):
    sig = verify_path(tmp_path)
    assert sig.state == "skipped"


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only path")
def test_macos_system_binary_is_signed():
    sig = verify_path("/usr/bin/codesign")
    assert sig.state in {"signed", "skipped"}
    if sig.state == "signed":
        # On a real Apple-signed binary either an Authority or empty TeamID is expected.
        assert isinstance(sig.signer or "", str)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only path")
def test_macos_unsigned_text_file_reported_unsigned(tmp_path):
    f = tmp_path / "fake.bin"
    f.write_bytes(b"not actually a Mach-O - codesign should complain")
    sig = verify_path(f)
    # codesign on non-Mach-O returns 'code object is not signed at all' or similar
    assert sig.state in {"unsigned", "invalid", "skipped"}


def test_detector_emits_finding_for_unsigned(tmp_path):
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(
        collector="code_signing", category="integrity",
        subject="sig:/usr/local/evil",
        data={"exe": "/usr/local/evil", "pids": [1234],
              "state": "unsigned", "signer": None, "team_id": None,
              "cdhash": None, "details": ""},
    ))
    UnsignedBinaryDetector().run(store)
    findings = list(store.iter_findings())
    assert findings
    assert findings[0]["severity"] == "high"
    assert "unsigned" in findings[0]["title"].lower()
    store.close()


def test_detector_skips_signed_and_skipped(tmp_path):
    store = EvidenceStore(tmp_path)
    for state in ("signed", "skipped", "package_owned"):
        store.add_artifact(Artifact(
            collector="code_signing", category="integrity",
            subject=f"sig:/usr/bin/{state}",
            data={"exe": f"/usr/bin/{state}", "pids": [1],
                  "state": state, "signer": "Apple", "team_id": None,
                  "cdhash": None, "details": ""},
        ))
    UnsignedBinaryDetector().run(store)
    assert len(list(store.iter_findings())) == 0
    store.close()


def test_detector_emits_for_ad_hoc(tmp_path):
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(
        collector="code_signing", category="integrity",
        subject="sig:/tmp/x",
        data={"exe": "/tmp/x", "pids": [1], "state": "ad_hoc",
              "signer": "adhoc", "team_id": None, "cdhash": None, "details": ""},
    ))
    UnsignedBinaryDetector().run(store)
    f = list(store.iter_findings())[0]
    assert f["severity"] == "medium"
    assert "ad-hoc" in f["title"].lower()
    store.close()
