"""FIPS mode tests."""

from __future__ import annotations

import pytest

from digger.fips.mode import (
    FIPSViolation, FIPS_APPROVED_PQC_KEM, FIPS_APPROVED_PQC_SIG, FIPS_APPROVED_SYMMETRIC,
    assert_approved_kem, assert_approved_sig, assert_approved_symmetric, current_state,
    enable_fips_mode, fips_self_test, in_fips_mode,
)


def test_fips_self_test_runs():
    results = fips_self_test()
    assert results["sha256_kat"] is True


def test_fips_off_means_no_assertions(monkeypatch):
    # Ensure off-state
    from digger.fips import mode
    monkeypatch.setattr(mode, "_state", mode.FIPSMode(False, False, None, []))
    assert not in_fips_mode()
    # These should NOT raise when FIPS is off
    assert_approved_sig("Falcon-512")
    assert_approved_kem("ML-KEM-768")
    assert_approved_symmetric("AES-256-GCM")


def test_fips_on_rejects_non_approved(monkeypatch):
    from digger.fips import mode
    monkeypatch.setattr(mode, "_state", mode.FIPSMode(True, True, None, []))
    # Approved algorithms pass
    assert_approved_sig("ML-DSA-65")
    assert_approved_kem("ML-KEM-768")
    assert_approved_symmetric("AES-256-GCM")
    # Non-approved raise
    with pytest.raises(FIPSViolation):
        assert_approved_sig("CROSS-rsdp-128-balanced")
    with pytest.raises(FIPSViolation):
        assert_approved_kem("HQC-128")
    with pytest.raises(FIPSViolation):
        assert_approved_symmetric("ChaCha20-Poly1305")


def test_fips_finalized_algorithms_are_in_approved_set():
    assert "ML-DSA-65" in FIPS_APPROVED_PQC_SIG
    assert "ML-KEM-768" in FIPS_APPROVED_PQC_KEM
    assert "AES-256-GCM" in FIPS_APPROVED_SYMMETRIC
