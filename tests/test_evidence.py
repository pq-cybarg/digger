"""Evidence store: insert, iterate, hash chain, tamper-detection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from digger.core import Artifact, EvidenceStore, Finding


def test_add_and_iterate(tmp_path: Path):
    with EvidenceStore(tmp_path) as store:
        store.add_artifact(Artifact(collector="x", category="c", subject="s1", data={"k": 1}))
        store.add_artifact(Artifact(collector="x", category="c", subject="s2", data={"k": 2}))
        rows = list(store.iter_artifacts())
        assert len(rows) == 2
        assert rows[0]["subject"] == "s1"
        assert rows[1]["data"] == {"k": 2}


def test_chain_verification_succeeds_on_clean_db(tmp_path: Path):
    with EvidenceStore(tmp_path) as store:
        for i in range(5):
            store.add_artifact(Artifact(collector="x", category="c", subject=f"s{i}", data={"i": i}))
        result = store.verify_chain()
        assert result["artifacts_ok"]["all"], result
        assert result["artifacts_ok"]["sha256"] is True
        assert result["artifacts_ok"]["sha3_256"] is True


def test_chain_verification_catches_tampering(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    for i in range(3):
        store.add_artifact(Artifact(collector="x", category="c", subject=f"s{i}", data={"i": i}))
    store.close()
    # Tamper: rewrite an artifact's data_json to a new value
    import sqlite3
    conn = sqlite3.connect(tmp_path / "evidence.db")
    conn.execute("UPDATE artifacts SET data_json='{\"i\": 999}' WHERE id=2")
    conn.commit()
    conn.close()
    store = EvidenceStore(tmp_path)
    result = store.verify_chain()
    # Tampering must fail BOTH chains — defense in depth.
    assert not result["artifacts_ok"]["all"]
    assert not result["artifacts_ok"]["sha256"]
    assert not result["artifacts_ok"]["sha3_256"]
    store.close()


def test_findings_severity_validation(tmp_path: Path):
    with pytest.raises(ValueError):
        Finding(detector="d", severity="oops", title="t", summary="s")


def test_chain_tip_is_stable(tmp_path: Path):
    with EvidenceStore(tmp_path) as store:
        store.set_meta("case_id", "case-1")
        store.add_artifact(Artifact(collector="x", category="c", subject="s", data={"k": 1}))
        tip1 = store.chain_tip_message()
    with EvidenceStore(tmp_path) as store:
        tip2 = store.chain_tip_message()
        assert tip1 == tip2


def test_chain_tip_exposes_both_algorithms(tmp_path: Path):
    with EvidenceStore(tmp_path) as store:
        store.set_meta("case_id", "case-2")
        store.add_artifact(Artifact(collector="x", category="c", subject="s1", data={"k": 1}))
        tip = store.chain_tip()
        assert "SHA-256"  in tip["algorithms"]
        assert "SHA3-256" in tip["algorithms"]
        assert tip["artifacts"]["sha256"]
        assert tip["artifacts"]["sha3_256"]
        # 32-byte digests → 64 hex characters each.
        assert len(tip["artifacts"]["sha256"])   == 64
        assert len(tip["artifacts"]["sha3_256"]) == 64
        # Same payload, different algorithms → different digests.
        assert tip["artifacts"]["sha256"] != tip["artifacts"]["sha3_256"]


def test_paired_chain_step_is_deterministic():
    from digger.core.hashing import paired_hash, paired_chain_step
    c1 = paired_hash(b"row-1")
    c2 = paired_hash(b"row-2")
    a1 = paired_chain_step(None, c1)
    a2 = paired_chain_step(a1, c2)
    b1 = paired_chain_step(None, c1)
    b2 = paired_chain_step(b1, c2)
    assert a1 == b1
    assert a2 == b2
    assert a1["sha256"] != a1["sha3_256"]
    assert a2["sha256"] != a2["sha3_256"]
