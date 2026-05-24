"""Encrypt / decrypt entire case directories.

A case-bundle file looks like:

    +-----------------------------------------------------------------+
    | magic: b"DIGGER01"                                              | 8 B
    | header_len: uint32 BE                                           | 4 B
    | header_json: utf-8 JSON                                         | N B
    |   { "kem_alg":      "ML-KEM-768",                                |
    |     "sig_alg":      "ML-DSA-65",   # optional                    |
    |     "kem_ct_b64":   "...",       # KEM ciphertext (PQC)          |
    |     "nonce_b64":    "...",       # AES-GCM nonce                 |
    |     "aad_b64":      "...",       # AES-GCM associated data       |
    |     "recipient_pk_fingerprint_sha256": "...",                    |
    |     "created":      <unix-ts>,                                   |
    |     "case_id":      "...",                                       |
    |     "chain_tip":    { "artifacts": {...}, "findings": {...} },   |
    |     "sig_b64":      "..." (optional),                            |
    |     "sig_pk_b64":   "..." (optional) }                           |
    | payload_len: uint64 BE                                          | 8 B
    | payload: AES-256-GCM ciphertext of                              | M B
    |          (tar.gz of the case directory)                          |
    +-----------------------------------------------------------------+

The KEM is one of the NIST PQC finalists (default ML-KEM-768, FIPS 203).
The symmetric cipher is AES-256-GCM (FIPS 197 + 800-38D) with a 12-byte
nonce. If a signing key is provided, the entire header+payload is
PQC-signed (ML-DSA-65 by default, FIPS 204) and the signature is stored
in the header so verification is self-contained.

This format is intentionally simple — no chunking, no streaming — to
keep the implementation small and auditable. Practical for case dirs up
to a few GB. Larger cases should be split externally.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import struct
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

MAGIC = b"DIGGER01"


@dataclass
class BundleHeader:
    kem_alg: str
    nonce_b64: str
    aad_b64: str
    kem_ct_b64: str
    recipient_pk_fingerprint_sha256: str
    created: float
    case_id: str
    chain_tip: dict
    sig_alg: Optional[str] = None
    sig_b64: Optional[str] = None
    sig_pk_b64: Optional[str] = None

    def to_json(self) -> bytes:
        d = self.__dict__.copy()
        if d.get("sig_alg") is None: d.pop("sig_alg")
        if d.get("sig_b64") is None: d.pop("sig_b64")
        if d.get("sig_pk_b64") is None: d.pop("sig_pk_b64")
        return json.dumps(d, sort_keys=True).encode("utf-8")


@dataclass
class BundleResult:
    out_path: Path
    bytes_written: int
    case_id: str
    kem_alg: str
    sig_alg: Optional[str]
    chain_tip: dict
    signed: bool


def _fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_recipient_public_key(pubkey_path: str | Path) -> bytes:
    p = Path(pubkey_path).expanduser()
    raw = p.read_bytes()
    # Accept either base64-armored or raw bytes (heuristic: try b64 first).
    s = raw.strip()
    try:
        decoded = base64.b64decode(s, validate=True)
        return decoded
    except Exception:
        return raw


def _maybe_load_signing_key(sk_path: str | Path) -> tuple[bytes, bytes]:
    """Return (secret_key_bytes, public_key_bytes)."""
    sk = Path(sk_path).expanduser().read_bytes()
    pk_path = Path(str(sk_path) + ".pub")
    if not pk_path.exists():
        raise FileNotFoundError(
            f"signing public key {pk_path} not found next to secret key"
        )
    pk = pk_path.read_bytes()
    return sk, pk


def _tar_case_dir(case_dir: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
        tar.add(str(case_dir), arcname=case_dir.name)
    return buf.getvalue()


def _untar_to_dir(blob: bytes, target_parent: Path) -> Path:
    target_parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        # Resolve the top-level dir name from the first member.
        members = tar.getmembers()
        if not members:
            raise ValueError("empty bundle payload")
        top = members[0].name.split("/")[0]
        # Safe extraction — refuse any member that escapes target.
        for m in members:
            full = (target_parent / m.name).resolve()
            if not str(full).startswith(str(target_parent.resolve())):
                raise ValueError(f"unsafe tar member: {m.name}")
        tar.extractall(target_parent)
    return target_parent / top


def encrypt_case(
    case_dir: str | Path,
    out_path: str | Path,
    recipient_public_key: str | Path | bytes,
    kem_alg: str = "ML-KEM-768",
    sign_with_secret_key: Optional[str | Path] = None,
    sig_alg: str = "ML-DSA-65",
    aad: bytes = b"digger-case-bundle-v1",
) -> BundleResult:
    """Compress, hybrid-encrypt, optionally sign a whole case directory.

    Args:
        case_dir: path to the directory holding ``evidence.db`` etc.
        out_path: where to write the ``.digger`` archive.
        recipient_public_key: bytes, OR a path to a file containing the
            recipient's KEM public key (base64-armored or raw).
        kem_alg: NIST PQC KEM algorithm. FIPS-approved default.
        sign_with_secret_key: optional path to a PQC signing secret key.
            The matching ``.pub`` must exist alongside.
        sig_alg: PQC signature algorithm if signing.

    FIPS mode: when on, both ``kem_alg`` and ``sig_alg`` must be
    FIPS-approved. PQC backend enforces this.
    """
    from digger.core.evidence import EvidenceStore
    from digger.crypto.pqc import PQCBackend

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("opsec.bundle.encrypt requires `cryptography`") from exc

    case_dir = Path(case_dir).expanduser().resolve()
    if not (case_dir / "evidence.db").exists():
        raise FileNotFoundError(f"no evidence.db in {case_dir}")

    if isinstance(recipient_public_key, (str, Path)):
        recipient_pk = _read_recipient_public_key(recipient_public_key)
    else:
        recipient_pk = recipient_public_key

    # Snapshot the case chain tip so the bundle header attests to the
    # exact evidence state it carries.
    store = EvidenceStore(case_dir)
    chain_tip = store.chain_tip()
    case_id = str(store.get_meta("case_id", ""))
    store.close()

    # 1. tar.gz the case dir
    payload_plain = _tar_case_dir(case_dir)

    # 2. KEM encapsulate → shared secret
    kem = PQCBackend(kem_alg=kem_alg)
    kem_ct, shared = kem.kem_encapsulate(recipient_pk)

    # 3. Derive AES-256-GCM key with HKDF-SHA256
    from digger.crypto.pqc import _hkdf_sha256
    key = _hkdf_sha256(shared, salt=b"", info=b"digger/opsec-bundle/aes-256-gcm", length=32)

    # 4. AES-GCM seal payload
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload_plain, aad)

    # 5. Build the unsigned header
    header = BundleHeader(
        kem_alg=kem_alg,
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        aad_b64=base64.b64encode(aad).decode("ascii"),
        kem_ct_b64=base64.b64encode(kem_ct).decode("ascii"),
        recipient_pk_fingerprint_sha256=_fingerprint(recipient_pk),
        created=time.time(),
        case_id=case_id,
        chain_tip=chain_tip,
    )

    # 6. Sign header || ciphertext with PQC if requested
    if sign_with_secret_key:
        sk_bytes, pk_bytes = _maybe_load_signing_key(sign_with_secret_key)
        unsigned_header_json = header.to_json()
        to_sign = (
            unsigned_header_json
            + struct.pack(">Q", len(ciphertext))
            + ciphertext
        )
        sig_bytes = PQCBackend(sig_alg=sig_alg).sign(to_sign, sk_bytes)
        header.sig_alg     = sig_alg
        header.sig_b64     = base64.b64encode(sig_bytes).decode("ascii")
        header.sig_pk_b64  = base64.b64encode(pk_bytes).decode("ascii")

    header_bytes = header.to_json()

    # 7. Serialize
    out_path = Path(out_path).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack(">I", len(header_bytes)))
        f.write(header_bytes)
        f.write(struct.pack(">Q", len(ciphertext)))
        f.write(ciphertext)

    return BundleResult(
        out_path=out_path,
        bytes_written=out_path.stat().st_size,
        case_id=case_id,
        kem_alg=kem_alg,
        sig_alg=header.sig_alg,
        chain_tip=chain_tip,
        signed=bool(sign_with_secret_key),
    )


def _read_bundle(in_path: Path) -> tuple[BundleHeader, bytes]:
    """Return (parsed_header, ciphertext_bytes)."""
    with open(in_path, "rb") as f:
        magic = f.read(8)
        if magic != MAGIC:
            raise ValueError(f"not a digger bundle (bad magic {magic!r})")
        header_len = struct.unpack(">I", f.read(4))[0]
        header_bytes = f.read(header_len)
        if len(header_bytes) != header_len:
            raise ValueError("truncated header")
        payload_len = struct.unpack(">Q", f.read(8))[0]
        ciphertext = f.read(payload_len)
        if len(ciphertext) != payload_len:
            raise ValueError("truncated payload")
    header_dict = json.loads(header_bytes.decode("utf-8"))
    header = BundleHeader(**header_dict)
    return header, ciphertext


def decrypt_case(
    in_path: str | Path,
    recipient_secret_key: str | Path | bytes,
    out_dir: str | Path,
    verify_signature: bool = True,
) -> Path:
    """Decrypt a ``.digger`` bundle into ``out_dir``.

    Returns the path of the extracted case directory.

    Verification:
      * KEM decapsulation must succeed and AES-GCM tag must verify.
      * If the bundle carries a PQC signature, it is verified against
        ``sig_pk_b64`` (a self-contained PK). Raises on mismatch.
        Pass ``verify_signature=False`` to skip (not recommended).
    """
    from digger.crypto.pqc import PQCBackend, _hkdf_sha256

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("opsec.bundle.decrypt requires `cryptography`") from exc

    in_path = Path(in_path).expanduser()
    out_dir = Path(out_dir).expanduser()

    header, ciphertext = _read_bundle(in_path)

    # 1. Signature check (if present and requested)
    if header.sig_b64 and verify_signature:
        sig_pk    = base64.b64decode(header.sig_pk_b64)
        sig_bytes = base64.b64decode(header.sig_b64)
        # Reconstruct the signed payload: unsigned-header || u64(payload_len) || payload
        unsigned = BundleHeader(
            kem_alg=header.kem_alg, nonce_b64=header.nonce_b64,
            aad_b64=header.aad_b64, kem_ct_b64=header.kem_ct_b64,
            recipient_pk_fingerprint_sha256=header.recipient_pk_fingerprint_sha256,
            created=header.created, case_id=header.case_id,
            chain_tip=header.chain_tip,
        )
        signed_payload = (
            unsigned.to_json()
            + struct.pack(">Q", len(ciphertext))
            + ciphertext
        )
        ok = PQCBackend(sig_alg=header.sig_alg).verify(signed_payload, sig_bytes, sig_pk)
        if not ok:
            raise ValueError("bundle signature failed verification")

    # 2. KEM decapsulate → shared secret
    if isinstance(recipient_secret_key, (str, Path)):
        sk = Path(recipient_secret_key).expanduser().read_bytes()
    else:
        sk = recipient_secret_key
    kem = PQCBackend(kem_alg=header.kem_alg)
    kem_ct = base64.b64decode(header.kem_ct_b64)
    shared = kem.kem_decapsulate(kem_ct, sk)

    # 3. AES-GCM open
    key = _hkdf_sha256(shared, salt=b"", info=b"digger/opsec-bundle/aes-256-gcm", length=32)
    nonce = base64.b64decode(header.nonce_b64)
    aad   = base64.b64decode(header.aad_b64)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)

    # 4. Untar to out_dir
    return _untar_to_dir(plaintext, out_dir)
