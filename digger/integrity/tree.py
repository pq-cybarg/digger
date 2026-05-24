"""Shared dual-SHA + PQC tree-signing primitive.

Generic helper used by :mod:`digger.loki.integrity` (signature-base
corpus) and :mod:`digger.intel.integrity` (threat-intel feed cache).
Each of those modules carries its own threat-model docstring; this
file just implements the mechanics.

The primitive:

  1. Walk a directory deterministically (sorted by relative path) and
     hash every file with SHA-256 and SHA3-256 simultaneously.
  2. Roll the per-file digests into two root digests covering the
     entire tree. Filename ordering and the per-file ``relpath || NUL ||
     content`` framing mean renames are detected as content changes.
  3. PQC-sign the canonical message form (JSON of the two root digests
     plus file count and total bytes) with a NIST-finalized signature
     algorithm (default ML-DSA-65, FIPS 204).
  4. Persist the signature bundle to ``<root>/.digger-sig.json``.
  5. Verify by recomputing and checking the on-disk signature.

The signature sidecar is itself excluded from the tree-hash so signing
is idempotent. Re-signing an already-signed (clean) directory yields
the same root digests; only the timestamp + signature bytes change.

Why both SHA-2 and SHA-3: Merkle-Damgård (SHA-2) and Keccak sponge
(SHA-3) are structurally independent. A future cryptanalytic break
against one family is unlikely to break the other; an attacker would
have to forge collisions in both simultaneously to swap content
silently. Same design principle as digger's dual-chain evidence store.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


SIG_FILENAME = ".digger-sig.json"


@dataclass
class TreeHash:
    sha256_root: str
    sha3_256_root: str
    file_count: int
    total_bytes: int
    computed_at: float

    def message_bytes(self) -> bytes:
        """Canonical bytes form — the actual signed payload."""
        return json.dumps({
            "sha256_root":   self.sha256_root,
            "sha3_256_root": self.sha3_256_root,
            "file_count":    self.file_count,
            "total_bytes":   self.total_bytes,
        }, sort_keys=True).encode("utf-8")


@dataclass
class IntegrityResult:
    signed: bool
    verified: Optional[bool] = None
    algorithm: Optional[str] = None
    signed_at: Optional[float] = None
    note: str = ""
    computed: Optional[TreeHash] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.computed:
            d["computed"] = asdict(self.computed)
        return d


_IGNORE_NAMES = {SIG_FILENAME, ".git", ".gitignore"}


def compute_tree_hash(root: Path | str) -> TreeHash:
    """Deterministic dual-algorithm tree hash. Path order is sorted;
    each file contributes ``relpath || NUL || content`` to the rolling
    digest so renames are detected as content changes."""
    root = Path(root).expanduser().resolve()
    h2 = hashlib.sha256()
    h3 = hashlib.sha3_256()
    files = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in _IGNORE_NAMES for part in p.relative_to(root).parts):
            continue
        files.append(p)
    total = 0
    for f in files:
        rel = str(f.relative_to(root)).encode("utf-8")
        h2.update(rel + b"\x00")
        h3.update(rel + b"\x00")
        try:
            with open(f, "rb") as fh:
                while True:
                    chunk = fh.read(1 << 20)
                    if not chunk:
                        break
                    h2.update(chunk)
                    h3.update(chunk)
                    total += len(chunk)
        except OSError:
            continue
    return TreeHash(
        sha256_root=h2.hexdigest(),
        sha3_256_root=h3.hexdigest(),
        file_count=len(files),
        total_bytes=total,
        computed_at=time.time(),
    )


def sign_snapshot(
    root: Path | str,
    secret_key_path: Path | str,
    algorithm: str = "ML-DSA-65",
    note: str = "",
) -> Path:
    """Compute tree hash and PQC-sign it. Returns the signature path.

    The matching public key file (``<secret_key>.pub``) must exist
    alongside the secret key — same convention as ``digger pqc sign``.
    """
    from digger.crypto import sign_evidence

    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"snapshot root {root} is not a directory")
    th = compute_tree_hash(root)
    out = root / SIG_FILENAME
    sign_evidence(
        message=th.message_bytes(),
        out_path=out,
        algorithm=algorithm,
        secret_key_path=secret_key_path,
        note=note or f"digger snapshot signature for {root.name}",
    )
    # Stash the tree-hash content alongside the signature so verifiers
    # can see what was signed without recomputing — but the signature
    # itself covers the canonical message_bytes form above.
    bundle = json.loads(out.read_text(encoding="utf-8"))
    bundle["tree_hash"] = asdict(th)
    out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return out


def verify_snapshot(root: Path | str) -> IntegrityResult:
    """Re-hash the directory and verify the on-disk signature.

    Returns IntegrityResult with .verified True / False / None.
      verified=True   — signature present and matches current content
      verified=False  — signature present but does NOT match
      signed=False    — no signature present (verified=None)
    """
    from digger.crypto import verify_evidence

    root = Path(root).expanduser().resolve()
    sig_path = root / SIG_FILENAME
    if not sig_path.exists():
        return IntegrityResult(signed=False, note=f"no {SIG_FILENAME}")
    try:
        bundle = json.loads(sig_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return IntegrityResult(signed=True, verified=False,
                                note=f"signature file unreadable: {exc}")
    current = compute_tree_hash(root)
    ok = False
    try:
        ok = verify_evidence(current.message_bytes(), sig_path)
    except Exception as exc:
        return IntegrityResult(
            signed=True, verified=False, computed=current,
            algorithm=bundle.get("algorithm"),
            signed_at=bundle.get("created"),
            note=f"verify_evidence failed: {exc}",
        )
    return IntegrityResult(
        signed=True,
        verified=ok,
        algorithm=bundle.get("algorithm"),
        signed_at=bundle.get("created"),
        computed=current,
        note=("verified" if ok else "TAMPERED — current tree-hash does not match signature"),
    )


def quick_status(root: Path | str) -> dict:
    """Cheap status without recomputing the tree-hash — just looks at
    whether a signature file exists and parses its metadata.
    Use ``verify_snapshot`` for the cryptographic check."""
    root = Path(root).expanduser().resolve()
    sig_path = root / SIG_FILENAME
    if not sig_path.exists():
        return {"signed": False, "reason": "no signature file"}
    try:
        bundle = json.loads(sig_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"signed": False, "reason": f"signature unreadable: {exc}"}
    return {
        "signed":    True,
        "algorithm": bundle.get("algorithm"),
        "signed_at": bundle.get("created"),
        "note":      bundle.get("note", ""),
        "tree":      bundle.get("tree_hash"),
    }
