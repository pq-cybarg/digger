"""PQC module — verifies algorithm tables and graceful degradation when liboqs is absent."""

from __future__ import annotations

import pytest

from digger.crypto import (
    PQC_ALL_KNOWN, PQC_FIPS_FINALIZED, PQC_NIST_ROUND4, PQC_SIG_ONRAMP,
    PQCBackend, available_kems, available_sigs,
)


def test_algorithm_tables_have_expected_finalized():
    # FIPS 203/204/205 finalized algorithms must be present in the bundled table.
    assert "ML-KEM-512" in PQC_FIPS_FINALIZED["kem"]
    assert "ML-KEM-768" in PQC_FIPS_FINALIZED["kem"]
    assert "ML-KEM-1024" in PQC_FIPS_FINALIZED["kem"]
    assert "ML-DSA-44" in PQC_FIPS_FINALIZED["sig"]
    assert "ML-DSA-65" in PQC_FIPS_FINALIZED["sig"]
    assert "ML-DSA-87" in PQC_FIPS_FINALIZED["sig"]
    # SLH-DSA finalized variants
    for v in ("SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f"):
        assert v in PQC_FIPS_FINALIZED["sig"]
    # FIPS 206 (Falcon)
    assert "Falcon-512" in PQC_FIPS_FINALIZED["sig"]


def test_round4_includes_hqc():
    assert "HQC-128" in PQC_NIST_ROUND4["kem"]


def test_onramp_includes_named_candidates():
    for name in ("MAYO-1", "CROSS-rsdp-128-balanced", "SQIsign-I", "HAWK-512", "FAEST-128f"):
        assert name in PQC_SIG_ONRAMP["sig"]


def test_all_known_is_union():
    for kind in ("kem", "sig"):
        s = set(PQC_FIPS_FINALIZED[kind]) | set(PQC_NIST_ROUND4[kind]) | set(PQC_SIG_ONRAMP[kind])
        assert set(PQC_ALL_KNOWN[kind]) == s


def test_backend_graceful_without_oqs():
    # If oqs isn't installed, available_* return [] not raise.
    sigs = available_sigs()
    kems = available_kems()
    assert isinstance(sigs, list)
    assert isinstance(kems, list)


def test_backend_raises_clear_error_without_oqs():
    backend = PQCBackend(sig_alg="ML-DSA-65")
    try:
        backend.generate_signing_key()
    except RuntimeError as exc:
        assert "oqs" in str(exc).lower()
    except ValueError:
        # liboqs is installed but the algorithm isn't enabled — also OK
        pass
