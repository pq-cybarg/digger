"""End-to-end tests of the opsec module."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from digger.core import Artifact, EvidenceStore, Finding
from digger.opsec import (
    RedactionPolicy, encrypt_case, decrypt_case, redact_case,
    secure_wipe_dir, opsec_status, find_watchers,
)
from digger.opsec.airgap import (
    AirgapViolation, assert_network_allowed, disable_airgap, enable_airgap,
)
from digger.crypto import PQCBackend, available_kems


def _make_demo_case(tmp_path: Path) -> Path:
    case_dir = tmp_path / "case"
    store = EvidenceStore(case_dir)
    store.set_meta("case_id", "demo-1")
    store.set_meta("host", {"node": "demo-host", "machine": "arm64"})
    store.add_artifact(Artifact(
        collector="processes", category="process", subject="pid=1 init",
        data={"pid": 1, "name": "init", "exe": "/sbin/init",
              "cmdline": ["init"], "username": "root"},
    ))
    store.add_finding(Finding(
        detector="test", severity="medium",
        title="example finding", summary="example summary",
    ))
    store.close()
    return case_dir


# ---- bundle ---- #

@pytest.mark.skipif("ML-KEM-768" not in available_kems(),
                    reason="liboqs without ML-KEM-768")
def test_encrypt_decrypt_roundtrip(tmp_path):
    case = _make_demo_case(tmp_path)

    # Generate a recipient ML-KEM-768 keypair
    backend = PQCBackend(kem_alg="ML-KEM-768")
    pk, sk = backend.generate_kem_key()
    pk_path = tmp_path / "recipient.pk"
    sk_path = tmp_path / "recipient.sk"
    pk_path.write_bytes(pk)
    sk_path.write_bytes(sk)

    bundle = tmp_path / "case.digger"
    result = encrypt_case(case, bundle, recipient_public_key=pk_path)
    assert result.out_path.exists()
    assert result.kem_alg == "ML-KEM-768"
    assert not result.signed

    out_dir = tmp_path / "restored"
    extracted = decrypt_case(bundle, recipient_secret_key=sk_path,
                              out_dir=out_dir, verify_signature=False)
    # Restored evidence DB should exist
    assert (extracted / "evidence.db").exists()
    # And carry the same case_id
    restored = EvidenceStore(extracted)
    assert restored.get_meta("case_id") == "demo-1"
    restored.close()


@pytest.mark.skipif("ML-KEM-768" not in available_kems(),
                    reason="liboqs without ML-KEM-768")
def test_signed_bundle_verifies(tmp_path):
    case = _make_demo_case(tmp_path)
    backend = PQCBackend(kem_alg="ML-KEM-768")
    pk, sk = backend.generate_kem_key()
    pk_path = tmp_path / "r.pk"
    sk_path = tmp_path / "r.sk"
    pk_path.write_bytes(pk)
    sk_path.write_bytes(sk)
    # Signer keypair
    signer = PQCBackend(sig_alg="ML-DSA-65")
    spk, ssk = signer.generate_signing_key()
    ssk_path = tmp_path / "sign.sk"
    ssk_path.write_bytes(ssk)
    (tmp_path / "sign.sk.pub").write_bytes(spk)

    bundle = tmp_path / "case.digger"
    result = encrypt_case(case, bundle, recipient_public_key=pk_path,
                          sign_with_secret_key=ssk_path)
    assert result.signed
    extracted = decrypt_case(bundle, recipient_secret_key=sk_path,
                              out_dir=tmp_path / "restored",
                              verify_signature=True)
    assert (extracted / "evidence.db").exists()


# ---- redaction ---- #

def test_redact_pseudonymizes_username(tmp_path):
    case_dir = tmp_path / "case"
    store = EvidenceStore(case_dir)
    store.set_meta("case_id", "r-1")
    store.set_meta("host", {"node": "real-host.acme.local", "machine": "arm64"})
    store.add_artifact(Artifact(
        collector="processes", category="process", subject="pid=500 vim",
        data={"pid": 500, "name": "vim", "exe": "/usr/bin/vim",
              "cmdline": ["vim", "/Users/alice/notes.txt"],
              "username": "alice"},
    ))
    store.close()

    out_dir = tmp_path / "redacted"
    summary = redact_case(case_dir, out_dir, policy=RedactionPolicy())
    assert summary["artifacts_redacted"] == 1
    restored = EvidenceStore(out_dir)
    host = restored.get_meta("host")
    assert host["node"].startswith("HOST"), host["node"]
    for art in restored.iter_artifacts():
        cl = " ".join(art["data"].get("cmdline") or [])
        assert "alice" not in cl
        assert "USER001" in cl or "/Users/USER" in cl
    restored.close()


# ---- airgap ---- #

def test_airgap_blocks_network_calls():
    disable_airgap()
    # Off — calling assert_network_allowed should be a no-op
    assert_network_allowed("ok")
    enable_airgap()
    try:
        with pytest.raises(AirgapViolation):
            assert_network_allowed("intel-feed:cisa_kev")
    finally:
        disable_airgap()


# ---- wipe ---- #

def test_wipe_refuses_non_case_dir(tmp_path):
    d = tmp_path / "not-a-case"
    d.mkdir()
    (d / "hello.txt").write_text("hi")
    r = secure_wipe_dir(d)
    assert r.errors, r
    assert d.exists()    # must NOT have been wiped


def test_wipe_removes_demo_case(tmp_path):
    case = _make_demo_case(tmp_path)
    assert (case / "evidence.db").exists()
    r = secure_wipe_dir(case, passes=1)
    assert r.files_overwritten >= 1
    assert r.files_unlinked >= 1
    assert not case.exists()


# ---- status / watchers ---- #

def test_status_returns_shape():
    s = opsec_status()
    assert "fips" in s
    assert "airgap" in s
    assert "watchers" in s
    assert "self" in s
    assert "pids" in s["self"]
    assert isinstance(s["watchers"]["total"], int)


def test_find_watchers_does_not_crash():
    # We can't assert presence of any specific watcher (host-dependent)
    # but the call must succeed and return a list of Watcher dataclasses.
    ws = find_watchers()
    for w in ws:
        assert w.severity in {"info", "low", "medium", "high"}
        assert w.category in {"debugger", "packet_capture", "edr",
                              "audit", "recorder", "ebpf", "tcc"}
