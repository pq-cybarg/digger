"""NIST Post-Quantum Cryptography support for digger.

Backed by liboqs (https://openquantumsafe.org) via the `oqs` Python binding.
liboqs is the canonical implementation tracking every algorithm in the NIST
PQC standardization process — finalized FIPS standards, the still-active
Round 4 candidates, and the additional signature on-ramp candidates.

Why liboqs instead of hand-rolling each algorithm: PQC primitives are
research-grade and continue to evolve. The NIST process is itself ongoing.
Re-implementing them is a footgun. We delegate to the algorithm-agile
reference implementation maintained by the Open Quantum Safe project and
expose whatever the installed liboqs version supports at runtime via
`oqs.get_enabled_kem_mechanisms()` / `oqs.get_enabled_sig_mechanisms()`.

This means digger automatically picks up every new algorithm liboqs adds
as soon as the user upgrades their `oqs-python` install — without code
changes here.

What digger uses PQC for:
    * Signing the evidence chain (`digger sign --case-dir …`) — produces
      `case_signature.json` binding the tip of the artifact chain to a
      PQC signature, with the public key and algorithm OID embedded.
    * Hybrid PQC-KEM + AES-256-GCM encryption of the entire case bundle
      (`digger encrypt`) for off-host archival.
    * Verifying a peer's case bundle (`digger verify --pubkey …`).

Install: `pip install oqs` after building liboqs locally, or use the
`liboqs-python` wheels. See README for setup. If oqs is missing every
PQC entry point raises a clear, actionable error.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# ---- NIST PQC algorithm reference tables --------------------------------- #
#
# These tables are *informational*. The set of algorithms actually
# available at runtime is whatever the installed liboqs version exposes
# (see `available_kems()` / `available_sigs()`). The tables let digger
# (a) display which algorithms are available vs. expected,
# (b) let the user request modes like "FIPS-finalized only" or "include
#     all algorithms under review".

# FIPS-finalized (published as NIST Federal Information Processing Standards).
PQC_FIPS_FINALIZED: dict[str, list[str]] = {
    "kem": [
        # FIPS 203 — Module-Lattice KEM (Kyber lineage).
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
    ],
    "sig": [
        # FIPS 204 — Module-Lattice DSA (Dilithium lineage).
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        # FIPS 205 — Stateless Hash-Based DSA (SPHINCS+ lineage).
        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s",
        "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s",
        "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s",
        "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s",
        "SLH-DSA-SHAKE-256f",
        # FIPS 206 — FN-DSA (Falcon lineage), draft as of standardization.
        "Falcon-512",
        "Falcon-1024",
        "Falcon-padded-512",
        "Falcon-padded-1024",
    ],
}

# Round 4 — algorithms NIST kept under review after Round 3 for additional KEM diversity.
PQC_NIST_ROUND4: dict[str, list[str]] = {
    "kem": [
        # HQC selected in 2025 as 5th KEM standard (code-based, FIPS draft pending).
        "HQC-128",
        "HQC-192",
        "HQC-256",
        # BIKE — still listed as round 4 in many liboqs builds.
        "BIKE-L1",
        "BIKE-L3",
        "BIKE-L5",
        # Classic McEliece — large-key conservative choice still under review.
        "Classic-McEliece-348864",
        "Classic-McEliece-460896",
        "Classic-McEliece-6688128",
        "Classic-McEliece-6960119",
        "Classic-McEliece-8192128",
    ],
    "sig": [],
}

# Additional signature on-ramp — Round 1 of the new NIST signature competition.
# Names track the liboqs identifiers; entries listed even when liboqs may not
# yet enable them, so `available_sigs()` reports the delta to the user.
PQC_SIG_ONRAMP: dict[str, list[str]] = {
    "kem": [],
    "sig": [
        "CROSS-rsdp-128-balanced",
        "CROSS-rsdp-128-fast",
        "CROSS-rsdp-128-small",
        "CROSS-rsdp-192-balanced",
        "CROSS-rsdp-192-fast",
        "CROSS-rsdp-192-small",
        "CROSS-rsdp-256-balanced",
        "CROSS-rsdp-256-fast",
        "CROSS-rsdp-256-small",
        "CROSS-rsdpg-128-balanced",
        "CROSS-rsdpg-128-fast",
        "CROSS-rsdpg-128-small",
        "CROSS-rsdpg-192-balanced",
        "CROSS-rsdpg-192-fast",
        "CROSS-rsdpg-192-small",
        "CROSS-rsdpg-256-balanced",
        "CROSS-rsdpg-256-fast",
        "CROSS-rsdpg-256-small",
        "MAYO-1",
        "MAYO-2",
        "MAYO-3",
        "MAYO-5",
        "OV-Is",
        "OV-Ip",
        "OV-III",
        "OV-V",
        "OV-Is-pkc",
        "OV-Ip-pkc",
        "OV-III-pkc",
        "OV-V-pkc",
        "OV-Is-pkc-skc",
        "OV-Ip-pkc-skc",
        "OV-III-pkc-skc",
        "OV-V-pkc-skc",
        "SNOVA_24_5_4",
        "SNOVA_24_5_4_SHAKE",
        "SNOVA_24_5_4_esk",
        "SNOVA_24_5_4_SHAKE_esk",
        "SNOVA_37_17_2",
        "SNOVA_25_8_3",
        "SNOVA_56_25_2",
        "SNOVA_49_11_3",
        "SNOVA_37_8_4",
        "SNOVA_24_5_5",
        "SNOVA_60_10_4",
        "SNOVA_29_6_5",
        # Below are tracked so `--mode all` reports them as expected-but-missing
        # when liboqs does not yet include them. Names follow the NIST/teams
        # submission naming; liboqs may use slight variants once added.
        "HAWK-512",
        "HAWK-1024",
        "FAEST-128f",
        "FAEST-128s",
        "FAEST-192f",
        "FAEST-192s",
        "FAEST-256f",
        "FAEST-256s",
        "FAEST-EM-128f",
        "FAEST-EM-128s",
        "FAEST-EM-192f",
        "FAEST-EM-192s",
        "FAEST-EM-256f",
        "FAEST-EM-256s",
        "LESS-1b",
        "LESS-1i",
        "LESS-1s",
        "LESS-3b",
        "LESS-3s",
        "LESS-5b",
        "LESS-5s",
        "MiRitH-Ia-fast",
        "MiRitH-Ia-short",
        "MiRitH-Ib-fast",
        "MiRitH-Ib-short",
        "MQOM-L1-gf31-short",
        "MQOM-L1-gf31-fast",
        "MQOM-L1-gf251-short",
        "MQOM-L1-gf251-fast",
        "PERK-I-fast3",
        "PERK-I-fast5",
        "PERK-I-short3",
        "PERK-I-short5",
        "QR-UOV-Ip",
        "QR-UOV-Is",
        "QR-UOV-III",
        "QR-UOV-V",
        "RYDE-128F",
        "RYDE-128S",
        "RYDE-192F",
        "RYDE-192S",
        "RYDE-256F",
        "RYDE-256S",
        "SDitH-L1-gf256",
        "SDitH-L1-gf251",
        "SDitH-L3-gf256",
        "SDitH-L3-gf251",
        "SDitH-L5-gf256",
        "SDitH-L5-gf251",
        "SQIsign-I",
        "SQIsign-III",
        "SQIsign-V",
        "UOV-Is",
        "UOV-Ip",
        "UOV-III",
        "UOV-V",
    ],
}

PQC_ALL_KNOWN: dict[str, list[str]] = {
    "kem": (
        PQC_FIPS_FINALIZED["kem"]
        + PQC_NIST_ROUND4["kem"]
        + PQC_SIG_ONRAMP["kem"]
    ),
    "sig": (
        PQC_FIPS_FINALIZED["sig"]
        + PQC_NIST_ROUND4["sig"]
        + PQC_SIG_ONRAMP["sig"]
    ),
}

# Default algorithms chosen for digger's bundled commands. ML-DSA-65 gives
# a 128-bit classical / NIST level 3 lattice-based signature with reasonable
# key+sig sizes; ML-KEM-768 pairs to it for hybrid encryption.
DEFAULT_SIG_ALG = "ML-DSA-65"
DEFAULT_KEM_ALG = "ML-KEM-768"


# ---- backend loader ------------------------------------------------------ #


_OQS_IMPORT_ERROR: Optional[BaseException] = None


def _try_import_oqs():
    global _OQS_IMPORT_ERROR
    try:
        import oqs  # type: ignore[import-not-found]
        return oqs
    except Exception as exc:  # ImportError or liboqs-not-found
        _OQS_IMPORT_ERROR = exc
        return None


def available_kems() -> list[str]:
    oqs = _try_import_oqs()
    if oqs is None:
        return []
    try:
        return sorted(oqs.get_enabled_kem_mechanisms())
    except Exception:
        return []


def available_sigs() -> list[str]:
    oqs = _try_import_oqs()
    if oqs is None:
        return []
    try:
        return sorted(oqs.get_enabled_sig_mechanisms())
    except Exception:
        return []


def _require_oqs():
    oqs = _try_import_oqs()
    if oqs is None:
        raise RuntimeError(
            "Post-quantum cryptography support requires the `oqs` Python "
            "package backed by liboqs. Install: `pip install oqs` (after "
            "building liboqs locally — see https://openquantumsafe.org). "
            f"Original import error: {_OQS_IMPORT_ERROR!r}"
        )
    return oqs


# ---- signing ------------------------------------------------------------ #


@dataclass
class SignatureBundle:
    algorithm: str
    public_key_b64: str
    signature_b64: str
    message_sha256: str
    created: float = field(default_factory=time.time)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "public_key_b64": self.public_key_b64,
            "signature_b64": self.signature_b64,
            "message_sha256": self.message_sha256,
            "created": self.created,
            "note": self.note,
            "scheme": "NIST-PQC",
        }


class PQCBackend:
    """Thin wrapper around oqs.Signature / oqs.KeyEncapsulation."""

    def __init__(self, sig_alg: str = DEFAULT_SIG_ALG, kem_alg: str = DEFAULT_KEM_ALG):
        self.sig_alg = sig_alg
        self.kem_alg = kem_alg

    def generate_signing_key(self) -> tuple[bytes, bytes]:
        """Returns (public_key, secret_key) for self.sig_alg."""
        # FIPS gating — refuses non-approved sig algorithms when FIPS mode is on.
        from digger.fips.mode import assert_approved_sig
        assert_approved_sig(self.sig_alg)
        oqs = _require_oqs()
        if self.sig_alg not in oqs.get_enabled_sig_mechanisms():
            raise ValueError(
                f"signature algorithm {self.sig_alg!r} not enabled in this liboqs build; "
                f"available: {', '.join(sorted(oqs.get_enabled_sig_mechanisms()))}"
            )
        with oqs.Signature(self.sig_alg) as signer:
            pk = signer.generate_keypair()
            sk = signer.export_secret_key()
            return pk, sk

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        oqs = _require_oqs()
        with oqs.Signature(self.sig_alg, secret_key) as signer:
            return signer.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        oqs = _require_oqs()
        with oqs.Signature(self.sig_alg) as verifier:
            return bool(verifier.verify(message, signature, public_key))

    def generate_kem_key(self) -> tuple[bytes, bytes]:
        from digger.fips.mode import assert_approved_kem
        assert_approved_kem(self.kem_alg)
        oqs = _require_oqs()
        if self.kem_alg not in oqs.get_enabled_kem_mechanisms():
            raise ValueError(
                f"KEM algorithm {self.kem_alg!r} not enabled in this liboqs build; "
                f"available: {', '.join(sorted(oqs.get_enabled_kem_mechanisms()))}"
            )
        with oqs.KeyEncapsulation(self.kem_alg) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            return pk, sk

    def kem_encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret)."""
        oqs = _require_oqs()
        with oqs.KeyEncapsulation(self.kem_alg) as kem:
            return kem.encap_secret(peer_public_key)

    def kem_decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        oqs = _require_oqs()
        with oqs.KeyEncapsulation(self.kem_alg, secret_key) as kem:
            return kem.decap_secret(ciphertext)


# ---- evidence-chain signing -------------------------------------------- #


def sign_evidence(
    message: bytes,
    out_path: str | Path,
    algorithm: str = DEFAULT_SIG_ALG,
    secret_key_path: Optional[str | Path] = None,
    note: str = "",
) -> SignatureBundle:
    """Sign ``message`` and write a SignatureBundle JSON to ``out_path``.

    If ``secret_key_path`` exists, the existing key is used; otherwise a new
    keypair is generated and the secret key is written alongside (mode 0o600).
    """
    import hashlib

    backend = PQCBackend(sig_alg=algorithm)
    if secret_key_path and Path(secret_key_path).exists():
        sk = Path(secret_key_path).read_bytes()
        # Derive public key by signing a dummy and extracting from a fresh
        # keypair is not possible; we require the user to keep the .pub alongside.
        pk_path = Path(str(secret_key_path) + ".pub")
        if not pk_path.exists():
            raise FileNotFoundError(
                f"public key {pk_path} not found next to secret key; "
                "delete the secret key to regenerate or supply a .pub file"
            )
        pk = pk_path.read_bytes()
    else:
        pk, sk = backend.generate_signing_key()
        if secret_key_path:
            sk_path = Path(secret_key_path)
            sk_path.parent.mkdir(parents=True, exist_ok=True)
            sk_path.write_bytes(sk)
            try:
                os.chmod(sk_path, 0o600)
            except OSError:
                pass
            Path(str(sk_path) + ".pub").write_bytes(pk)

    sig = backend.sign(message, sk)
    bundle = SignatureBundle(
        algorithm=algorithm,
        public_key_b64=base64.b64encode(pk).decode("ascii"),
        signature_b64=base64.b64encode(sig).decode("ascii"),
        message_sha256=hashlib.sha256(message).hexdigest(),
        note=note,
    )
    Path(out_path).write_text(json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")
    return bundle


def verify_evidence(message: bytes, bundle_path: str | Path) -> bool:
    data = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    alg = data["algorithm"]
    pk = base64.b64decode(data["public_key_b64"])
    sig = base64.b64decode(data["signature_b64"])
    return PQCBackend(sig_alg=alg).verify(message, sig, pk)


# ---- hybrid PQC-KEM + AES-256-GCM encryption ---------------------------- #


def _hkdf_sha256(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    import hashlib
    import hmac

    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def hybrid_encrypt(
    plaintext: bytes,
    recipient_public_key: bytes,
    kem_alg: str = DEFAULT_KEM_ALG,
    aad: bytes = b"digger-case-v1",
) -> dict[str, Any]:
    """Encrypt with PQC-KEM(recipient_pk) -> shared secret -> AES-256-GCM.

    Output dict has 'kem_alg', 'kem_ct_b64', 'nonce_b64', 'aad_b64', 'ct_b64'.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError(
            "hybrid_encrypt requires `cryptography` for AES-256-GCM; "
            "install: pip install cryptography"
        ) from exc

    backend = PQCBackend(kem_alg=kem_alg)
    kem_ct, shared = backend.kem_encapsulate(recipient_public_key)
    key = _hkdf_sha256(shared, salt=b"", info=b"digger/aes-256-gcm", length=32)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "kem_alg": kem_alg,
        "kem_ct_b64": base64.b64encode(kem_ct).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "aad_b64": base64.b64encode(aad).decode("ascii"),
        "ct_b64": base64.b64encode(ct).decode("ascii"),
    }


def hybrid_decrypt(blob: dict[str, Any], recipient_secret_key: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("hybrid_decrypt requires `cryptography`") from exc

    backend = PQCBackend(kem_alg=blob["kem_alg"])
    kem_ct = base64.b64decode(blob["kem_ct_b64"])
    shared = backend.kem_decapsulate(kem_ct, recipient_secret_key)
    key = _hkdf_sha256(shared, salt=b"", info=b"digger/aes-256-gcm", length=32)
    nonce = base64.b64decode(blob["nonce_b64"])
    aad = base64.b64decode(blob["aad_b64"])
    ct = base64.b64decode(blob["ct_b64"])
    return AESGCM(key).decrypt(nonce, ct, aad)


# ---- introspection ---------------------------------------------------- #


def report_coverage(mode: str = "all") -> dict[str, Any]:
    """Report which expected NIST PQC algorithms are available locally.

    `mode` is one of "fips", "round4", "onramp", "all".
    """
    sets = {
        "fips": PQC_FIPS_FINALIZED,
        "round4": PQC_NIST_ROUND4,
        "onramp": PQC_SIG_ONRAMP,
        "all": PQC_ALL_KNOWN,
    }
    if mode not in sets:
        raise ValueError(f"unknown mode {mode!r}; choose from {list(sets)}")
    expected = sets[mode]
    have_kems = set(available_kems())
    have_sigs = set(available_sigs())
    return {
        "mode": mode,
        "kem": {
            "expected": expected["kem"],
            "present": sorted(set(expected["kem"]) & have_kems),
            "missing": sorted(set(expected["kem"]) - have_kems),
            "extra_available": sorted(have_kems - set(PQC_ALL_KNOWN["kem"])),
        },
        "sig": {
            "expected": expected["sig"],
            "present": sorted(set(expected["sig"]) & have_sigs),
            "missing": sorted(set(expected["sig"]) - have_sigs),
            "extra_available": sorted(have_sigs - set(PQC_ALL_KNOWN["sig"])),
        },
    }
