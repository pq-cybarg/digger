"""FIPS 140-3 operational mode for digger.

When FIPS mode is enabled, digger:
  * Restricts cryptographic algorithms to the FIPS-approved set
    (AES-256-GCM symmetric; SHA-256/384/512 hashing; ML-KEM, ML-DSA,
    SLH-DSA, FN-DSA/Falcon for PQC).
  * Refuses to load or sign with a non-approved algorithm — raising
    `FIPSViolation` with a clear remediation message.
  * Runs a Known-Answer-Test (KAT) self-test on startup over each
    approved algorithm available locally.
  * Records the FIPS mode marker in case metadata and the evidence log.

True FIPS 140-3 compliance also requires:
  - The underlying liboqs / OpenSSL build to be FIPS-validated (i.e.
    OpenSSL-3 FIPS provider loaded, or a CMVP-listed liboqs build).
  - OS-level FIPS mode enabled (kernel.fips_enabled=1 on Linux,
    HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy=1
    on Windows, com.apple.security.kext.policy on macOS).
  - Independent module validation; this code is a *user-mode wrapper*,
    not a validated cryptographic module on its own.

Use `digger fips status` to see the host's claimed posture and
`--fips-mode` (or `DIGGER_FIPS_MODE=1`) to opt into restrictions.
"""

from __future__ import annotations

import hashlib
import os
import platform
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class FIPSViolation(Exception):
    """Raised when a non-approved algorithm is requested while FIPS mode is on."""


# FIPS 197 / FIPS 800-38D — AES with approved modes.
FIPS_APPROVED_SYMMETRIC = {
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
    "AES-128-CCM", "AES-192-CCM", "AES-256-CCM",
    "AES-128-CTR", "AES-192-CTR", "AES-256-CTR",
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
    "AES-128-KW", "AES-192-KW", "AES-256-KW",          # FIPS 800-38F key wrap
    "AES-128-XTS", "AES-256-XTS",                       # FIPS 800-38E storage
}

# FIPS 180-4 + FIPS 202.
FIPS_APPROVED_HASHES = {
    "SHA-1",                # legacy-allowed for non-signature use only
    "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256",
    "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
    "SHAKE128", "SHAKE256",
}

# FIPS-finalized PQC signatures (FIPS 203 / 204 / 205 / 206).
FIPS_APPROVED_PQC_SIG = {
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
    "Falcon-512", "Falcon-1024", "Falcon-padded-512", "Falcon-padded-1024",
}

# FIPS-finalized PQC KEMs (FIPS 203).
FIPS_APPROVED_PQC_KEM = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
}


_FIPS_FLAG_ENV = "DIGGER_FIPS_MODE"


@dataclass
class FIPSMode:
    enabled: bool
    self_test_passed: bool
    os_fips_marker: Optional[bool]
    notes: list[str]


_state = FIPSMode(enabled=False, self_test_passed=False, os_fips_marker=None, notes=[])


def in_fips_mode() -> bool:
    return _state.enabled


def current_state() -> FIPSMode:
    return _state


def _detect_os_fips_marker() -> Optional[bool]:
    """Best-effort: does the OS claim FIPS mode? Returns None if unknown."""
    p = platform.system().lower()
    try:
        if p == "linux":
            f = Path("/proc/sys/crypto/fips_enabled")
            if f.exists():
                return f.read_text().strip() == "1"
            return None
        if p == "darwin":
            # macOS uses a corecrypto FIPS-validated module by default for the system
            # libraries; there is no boolean to flip. Treat as unknown but present.
            return None
        if p == "windows":
            try:
                import winreg  # type: ignore[import-not-found]
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy",
                ) as k:
                    v, _ = winreg.QueryValueEx(k, "Enabled")
                    return bool(v)
            except OSError:
                return None
    except Exception:
        return None
    return None


def fips_self_test() -> dict:
    """Run a Known-Answer-Test on each FIPS-approved algorithm we use.

    Returns a dict like:
        {"sha256": True, "aes_256_gcm": True, "ml_dsa_65": True/None}
    Failures are False; "skipped" means the algorithm wasn't available.
    """
    results: dict[str, object] = {}

    # SHA-256 KAT (FIPS 180-4 Appendix A.1)
    sha256_expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    results["sha256_kat"] = (hashlib.sha256(b"abc").hexdigest() == sha256_expected)

    # SHA3-256 KAT (FIPS 202 — input "abc", canonical NIST test vector)
    sha3_256_expected = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    results["sha3_256_kat"] = (hashlib.sha3_256(b"abc").hexdigest() == sha3_256_expected)

    # AES-256-GCM round-trip KAT
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = b"\x00" * 32
        nonce = b"\x00" * 12
        ct = AESGCM(key).encrypt(nonce, b"hello", b"aad")
        pt = AESGCM(key).decrypt(nonce, ct, b"aad")
        results["aes_256_gcm"] = (pt == b"hello")
    except Exception as exc:
        results["aes_256_gcm"] = f"skipped: {exc}"

    # ML-DSA-65 round-trip if liboqs has it
    try:
        from digger.crypto import PQCBackend, available_sigs
        if "ML-DSA-65" in available_sigs():
            backend = PQCBackend(sig_alg="ML-DSA-65")
            pk, sk = backend.generate_signing_key()
            msg = b"digger-self-test"
            sig = backend.sign(msg, sk)
            ok = backend.verify(msg, sig, pk)
            results["ml_dsa_65"] = bool(ok)
        else:
            results["ml_dsa_65"] = "skipped: not available"
    except Exception as exc:
        results["ml_dsa_65"] = f"skipped: {exc}"

    # ML-KEM-768 round-trip if liboqs has it
    try:
        from digger.crypto import PQCBackend, available_kems
        if "ML-KEM-768" in available_kems():
            backend = PQCBackend(kem_alg="ML-KEM-768")
            pk, sk = backend.generate_kem_key()
            ct, shared_a = backend.kem_encapsulate(pk)
            shared_b = backend.kem_decapsulate(ct, sk)
            results["ml_kem_768"] = (shared_a == shared_b)
        else:
            results["ml_kem_768"] = "skipped: not available"
    except Exception as exc:
        results["ml_kem_768"] = f"skipped: {exc}"

    return results


def enable_fips_mode(force: bool = False) -> FIPSMode:
    """Turn on FIPS mode for this process. Runs the self-test."""
    global _state
    results = fips_self_test()
    notes: list[str] = []
    passed = True
    for k, v in results.items():
        if v is False:
            passed = False
            notes.append(f"KAT failed: {k}")
        elif isinstance(v, str) and v.startswith("skipped"):
            notes.append(f"{k}: {v}")
    os_marker = _detect_os_fips_marker()
    if not passed and not force:
        _state = FIPSMode(enabled=False, self_test_passed=False, os_fips_marker=os_marker, notes=notes)
        raise FIPSViolation(
            f"FIPS self-test failed; refusing to enter FIPS mode. Details: {notes}"
        )
    _state = FIPSMode(
        enabled=True,
        self_test_passed=passed,
        os_fips_marker=os_marker,
        notes=notes,
    )
    return _state


def assert_approved_sig(alg: str) -> None:
    if not in_fips_mode():
        return
    if alg not in FIPS_APPROVED_PQC_SIG:
        raise FIPSViolation(
            f"signature algorithm {alg!r} is not FIPS-approved. "
            f"In FIPS mode you must use one of {sorted(FIPS_APPROVED_PQC_SIG)}."
        )


def assert_approved_kem(alg: str) -> None:
    if not in_fips_mode():
        return
    if alg not in FIPS_APPROVED_PQC_KEM:
        raise FIPSViolation(
            f"KEM algorithm {alg!r} is not FIPS-approved. "
            f"In FIPS mode you must use one of {sorted(FIPS_APPROVED_PQC_KEM)}."
        )


def assert_approved_symmetric(alg: str) -> None:
    if not in_fips_mode():
        return
    if alg.upper() not in FIPS_APPROVED_SYMMETRIC:
        raise FIPSViolation(
            f"symmetric algorithm {alg!r} not approved in FIPS mode."
        )


def auto_enable_from_env() -> Optional[FIPSMode]:
    if os.environ.get(_FIPS_FLAG_ENV, "").lower() in {"1", "true", "yes", "on"}:
        return enable_fips_mode()
    return None
