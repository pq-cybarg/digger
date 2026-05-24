"""Post-quantum integrity for the signature-base corpus.

The threat model digger covers here:

  * An attacker who can write to your local signature-base directory
    (``~/.cache/digger/signature-base/``) — supply-chain attack, malicious
    co-tenant, compromised account.
  * An attacker who can MITM the HTTPS pull (compromised CA, state-level
    actor with cert authority access).
  * The classical-TLS "harvest now, decrypt later" risk against the
    confidentiality of the pull — *not* relevant since signature-base
    is public, but the **integrity** half of that risk is relevant: a
    classical signature on the upstream content is harvestable today
    and forgeable in a future cryptanalytically-relevant quantum era.

Mitigation: after a successful ``digger loki update``, compute a dual
SHA-256 + SHA3-256 tree-hash of the local corpus and **PQC-sign that
hash** with the operator's ML-DSA key. The signature lives at
``.digger-sig.json`` inside the corpus root. Every consumer (the
LokiStyleDetector, the YARA loader) optionally verifies the signature
before consuming any rule data. Tampered or unsigned corpora can be
refused (strict mode) or accepted with a logged warning (default).

Note on what this does *not* defend against: the original upstream
content being malicious at the moment of first pull. The signature
proves "this is the same bytes you signed last time" — not "these
bytes are good." For that, pin a known-good upstream commit hash.

Implementation note: the actual tree-hash + PQC-sign logic lives in
:mod:`digger.integrity` so this module and
:mod:`digger.intel.integrity` share it. This file re-exports the same
public names so existing callers (``from digger.loki.integrity import
verify_snapshot``) keep working.
"""

from digger.integrity import (
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
