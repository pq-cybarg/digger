"""Post-quantum integrity for the signature-base corpus."""

from __future__ import annotations

from pathlib import Path

import pytest

from digger.crypto import PQCBackend, available_sigs
from digger.loki.integrity import (
    SIG_FILENAME, compute_tree_hash, sign_snapshot, verify_snapshot,
)


def _make_corpus(tmp_path: Path) -> Path:
    root = tmp_path / "corpus"
    (root / "yara").mkdir(parents=True)
    (root / "iocs").mkdir()
    (root / "yara" / "test.yar").write_text("rule x { condition: false }\n")
    (root / "iocs" / "hash-iocs.txt").write_text("deadbeef;example;100\n")
    (root / "README.md").write_text("test corpus\n")
    return root


def test_compute_tree_hash_is_deterministic(tmp_path):
    root = _make_corpus(tmp_path)
    h1 = compute_tree_hash(root)
    h2 = compute_tree_hash(root)
    assert h1.sha256_root == h2.sha256_root
    assert h1.sha3_256_root == h2.sha3_256_root
    assert h1.file_count == h2.file_count == 3
    # Different algorithms must yield different digests
    assert h1.sha256_root != h1.sha3_256_root


def test_tree_hash_changes_when_content_changes(tmp_path):
    root = _make_corpus(tmp_path)
    h1 = compute_tree_hash(root)
    (root / "yara" / "test.yar").write_text("rule x { condition: true }\n")
    h2 = compute_tree_hash(root)
    assert h1.sha256_root != h2.sha256_root
    assert h1.sha3_256_root != h2.sha3_256_root


def test_tree_hash_changes_when_file_renamed(tmp_path):
    root = _make_corpus(tmp_path)
    h1 = compute_tree_hash(root)
    (root / "yara" / "test.yar").rename(root / "yara" / "renamed.yar")
    h2 = compute_tree_hash(root)
    assert h1.sha256_root != h2.sha256_root


def test_tree_hash_ignores_sig_file(tmp_path):
    root = _make_corpus(tmp_path)
    h1 = compute_tree_hash(root)
    (root / SIG_FILENAME).write_text("{}\n")
    h2 = compute_tree_hash(root)
    assert h1.sha256_root == h2.sha256_root


@pytest.mark.skipif("ML-DSA-65" not in available_sigs(),
                    reason="liboqs without ML-DSA-65")
def test_sign_and_verify_roundtrip(tmp_path):
    root = _make_corpus(tmp_path)
    # Generate a keypair for the test
    backend = PQCBackend(sig_alg="ML-DSA-65")
    pk, sk = backend.generate_signing_key()
    sk_path = tmp_path / "op.sk"
    sk_path.write_bytes(sk)
    (tmp_path / "op.sk.pub").write_bytes(pk)

    sig_path = sign_snapshot(root, sk_path)
    assert sig_path.exists()
    result = verify_snapshot(root)
    assert result.signed is True
    assert result.verified is True
    assert result.algorithm == "ML-DSA-65"


@pytest.mark.skipif("ML-DSA-65" not in available_sigs(),
                    reason="liboqs without ML-DSA-65")
def test_verify_fails_after_tamper(tmp_path):
    root = _make_corpus(tmp_path)
    backend = PQCBackend(sig_alg="ML-DSA-65")
    pk, sk = backend.generate_signing_key()
    sk_path = tmp_path / "op.sk"
    sk_path.write_bytes(sk)
    (tmp_path / "op.sk.pub").write_bytes(pk)
    sign_snapshot(root, sk_path)

    # Tamper a single byte in a rule
    (root / "yara" / "test.yar").write_text("rule x { condition: true }\n")

    result = verify_snapshot(root)
    assert result.signed is True
    assert result.verified is False
    assert "TAMPERED" in result.note or "verify" in result.note.lower()


def test_verify_unsigned_returns_signed_false(tmp_path):
    root = _make_corpus(tmp_path)
    result = verify_snapshot(root)
    assert result.signed is False
    assert result.verified is None
