"""Hashing helpers.

digger maintains two parallel hash families:

  SHA-256  (FIPS 180-4)  — preserved for ecosystem interop. Every external
                           consumer of evidence hashes (IOC feeds, VirusTotal,
                           MalwareBazaar, signature-base, code-signing,
                           git/sigstore chains) speaks SHA-256, so we keep
                           emitting and accepting it for those interfaces.

  SHA3-256 (FIPS 202)    — Keccak sponge construction. Structurally
                           independent of SHA-2 — if SHA-2 falls to a
                           future cryptanalytic class, SHA-3 is unlikely
                           to fall to the same attack.

Internally, the evidence-store integrity chain pairs BOTH algorithms.
Every row stores ``data_sha256`` AND ``data_sha3_256``, and two
independent chains (``chain_sha256``, ``chain_sha3_256``) thread through
the table. Forging undetectable tampering would require breaking both
families simultaneously. The PQC signature over the chain tip covers
both digests in one signed payload.

Helpers in this module:

  sha256_* / hash_chain_sha256    — SHA-256 primitives + chain step
  sha3_256_* / hash_chain_sha3    — SHA3-256 primitives + chain step
  paired_hash / paired_chain_step — convenience that returns both at once
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable


# ---- SHA-256 (FIPS 180-4) ---------------------------------------------- #


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def hash_chain_sha256(prev_hex: str, items: Iterable[bytes]) -> str:
    """h_n = SHA-256(h_{n-1} || item_n)."""
    h = hashlib.sha256()
    h.update(bytes.fromhex(prev_hex) if prev_hex else b"")
    for item in items:
        h.update(item)
    return h.hexdigest()


# Backwards-compatible alias for the original API name. Same SHA-256 semantics.
hash_chain = hash_chain_sha256


# ---- SHA3-256 (FIPS 202) ----------------------------------------------- #


def sha3_256_bytes(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def sha3_256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha3_256()
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def hash_chain_sha3(prev_hex: str, items: Iterable[bytes]) -> str:
    """h_n = SHA3-256(h_{n-1} || item_n)."""
    h = hashlib.sha3_256()
    h.update(bytes.fromhex(prev_hex) if prev_hex else b"")
    for item in items:
        h.update(item)
    return h.hexdigest()


# ---- paired (SHA-256 + SHA3-256) --------------------------------------- #


def paired_hash(data: bytes) -> dict[str, str]:
    """Return both SHA-256 and SHA3-256 of the same input.

    Returned dict keys: ``"sha256"`` and ``"sha3_256"``.
    """
    return {
        "sha256":    hashlib.sha256(data).hexdigest(),
        "sha3_256":  hashlib.sha3_256(data).hexdigest(),
    }


def paired_chain_step(
    prev: dict[str, str] | None,
    content: dict[str, str],
) -> dict[str, str]:
    """One chain step in both algorithms simultaneously.

    ``prev``    is the previous row's chain dict (``{"sha256": "...", "sha3_256": "..."}``)
                or None for the first row.
    ``content`` is the current row's content-hash dict in the same shape.

    Returns the new chain-hash dict in the same shape.
    """
    prev = prev or {"sha256": "", "sha3_256": ""}
    return {
        "sha256":   hash_chain_sha256(prev["sha256"],   [bytes.fromhex(content["sha256"])]),
        "sha3_256": hash_chain_sha3  (prev["sha3_256"], [bytes.fromhex(content["sha3_256"])]),
    }
