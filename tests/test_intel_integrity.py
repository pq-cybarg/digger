"""Threat-intel feed cache PQC integrity."""

from __future__ import annotations

from pathlib import Path

import pytest

from digger.crypto import PQCBackend, available_sigs
from digger.intel.integrity import (
    sign_intel, verify_intel, intel_quick_status,
)


def _seed_intel_dir(tmp_path: Path) -> Path:
    """Build a fake intel cache structure to sign."""
    root = tmp_path / "intel"
    root.mkdir()
    (root / "cisa_kev.json").write_text('{"entries": [], "count": 0}\n')
    (root / "cisa_kev.meta.json").write_text('{"fetched_at": 0}\n')
    (root / "urlhaus_recent.json").write_text('{"entries": []}\n')
    return root


@pytest.mark.skipif("ML-DSA-65" not in available_sigs(),
                    reason="liboqs without ML-DSA-65")
def test_sign_then_verify(tmp_path):
    root = _seed_intel_dir(tmp_path)
    backend = PQCBackend(sig_alg="ML-DSA-65")
    pk, sk = backend.generate_signing_key()
    sk_path = tmp_path / "op.sk"
    sk_path.write_bytes(sk)
    (tmp_path / "op.sk.pub").write_bytes(pk)

    sign_intel(root, sk_path)
    qs = intel_quick_status(root)
    assert qs["signed"] is True
    assert qs["algorithm"] == "ML-DSA-65"

    r = verify_intel(root)
    assert r.signed is True
    assert r.verified is True


@pytest.mark.skipif("ML-DSA-65" not in available_sigs(),
                    reason="liboqs without ML-DSA-65")
def test_tamper_detected(tmp_path):
    root = _seed_intel_dir(tmp_path)
    backend = PQCBackend(sig_alg="ML-DSA-65")
    pk, sk = backend.generate_signing_key()
    sk_path = tmp_path / "op.sk"
    sk_path.write_bytes(sk)
    (tmp_path / "op.sk.pub").write_bytes(pk)
    sign_intel(root, sk_path)

    # Tamper one feed's cache to add a fake "good" entry
    (root / "urlhaus_recent.json").write_text('{"entries": [{"url": "https://evil"}]}\n')

    r = verify_intel(root)
    assert r.signed is True
    assert r.verified is False


def test_unsigned_status(tmp_path):
    root = _seed_intel_dir(tmp_path)
    qs = intel_quick_status(root)
    assert qs["signed"] is False


# ---- load_intel verify-on-use ---- #


def _point_intel_dir(monkeypatch, root: Path) -> None:
    """Make digger.intel.feeds.intel_dir() return ``root`` for this test.

    cache_path / meta_path are properties that read intel_dir() each
    access, so a single patch is enough."""
    from digger.intel import feeds as feeds_mod
    monkeypatch.setattr(feeds_mod, "intel_dir", lambda: root)


def _reset_verdict():
    from digger.detectors import _rules_io
    _rules_io._reset_intel_verdict_for_tests()


def test_load_intel_warns_when_unsigned(tmp_path, monkeypatch, capsys):
    root = _seed_intel_dir(tmp_path)
    _point_intel_dir(monkeypatch, root)
    monkeypatch.delenv("DIGGER_INTEL_NO_VERIFY", raising=False)
    monkeypatch.delenv("DIGGER_INTEL_STRICT", raising=False)
    _reset_verdict()

    from digger.detectors._rules_io import load_intel
    # Cache is unsigned; we still get data (non-strict default) but warn.
    result = load_intel("cisa_kev")
    captured = capsys.readouterr()
    assert "unsigned" in captured.err.lower()
    # Cache file is empty entries list; data should be present (None means feed not found).
    assert result is not None


@pytest.mark.skipif("ML-DSA-65" not in available_sigs(),
                    reason="liboqs without ML-DSA-65")
def test_load_intel_refuses_tampered_in_strict_mode(tmp_path, monkeypatch, capsys):
    root = _seed_intel_dir(tmp_path)
    _point_intel_dir(monkeypatch, root)
    # Sign, then tamper.
    backend = PQCBackend(sig_alg="ML-DSA-65")
    pk, sk = backend.generate_signing_key()
    sk_path = tmp_path / "op.sk"
    sk_path.write_bytes(sk)
    (tmp_path / "op.sk.pub").write_bytes(pk)
    sign_intel(root, sk_path)
    (root / "cisa_kev.json").write_text('{"entries": [{"poisoned": true}]}\n')

    monkeypatch.delenv("DIGGER_INTEL_NO_VERIFY", raising=False)
    monkeypatch.setenv("DIGGER_INTEL_STRICT", "1")
    _reset_verdict()

    from digger.detectors._rules_io import load_intel
    result = load_intel("cisa_kev")
    captured = capsys.readouterr()
    assert "tampered" in captured.err.lower() or "does not verify" in captured.err.lower()
    assert result is None  # strict mode refuses


def test_load_intel_no_verify_env_silences_warning(tmp_path, monkeypatch, capsys):
    root = _seed_intel_dir(tmp_path)
    _point_intel_dir(monkeypatch, root)
    monkeypatch.setenv("DIGGER_INTEL_NO_VERIFY", "1")
    _reset_verdict()

    from digger.detectors._rules_io import load_intel
    load_intel("cisa_kev")
    captured = capsys.readouterr()
    assert captured.err == ""
