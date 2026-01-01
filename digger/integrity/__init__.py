"""Shared dual-SHA + PQC tree-signing primitive.

Used by:
  * digger.loki.integrity  — signs the LOKI / signature-base corpus
  * digger.intel.integrity — signs the threat-intel feed cache
  * (future) any other on-disk data digger wants tamper-evident

The primitive is:
  1. Walk a directory, deterministically hash every file (sorted by
     relative path) with SHA-256 *and* SHA3-256 simultaneously.
  2. Roll those into root digests.
  3. PQC-sign the canonical message form (JSON of both root digests +
     metadata) with ML-DSA-65 (FIPS 204) by default.
  4. Write the signature bundle to ``<root>/.digger-sig.json``.
  5. Verify by recomputing and checking the signature.

The signature sidecar is itself ignored from the tree hash, so signing
is idempotent.
"""

from digger.integrity.tree import (
    SIG_FILENAME,
    TreeHash,
    IntegrityResult,
    compute_tree_hash,
    sign_snapshot,
    verify_snapshot,
    quick_status,
)

__all__ = [
    "SIG_FILENAME", "TreeHash", "IntegrityResult",
    "compute_tree_hash", "sign_snapshot", "verify_snapshot", "quick_status",
]
