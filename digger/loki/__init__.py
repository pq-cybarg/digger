"""Loki / signature-base integration.

Florian Roth's `signature-base` repository (https://github.com/Neo23x0/signature-base)
is the IOC + YARA-rule corpus that powers his LOKI scanner family
(LOKI, THOR Lite, Loki-RS). It's the de-facto open-source IOC/YARA
collection for endpoint scanning.

This module pulls signature-base into digger:

  - `signature_base.SignatureBase` discovers and parses a local
    signature-base directory (filename IOCs, hash IOCs, C2 IOCs).
  - `updater.update_signature_base` does the initial `git clone` and
    subsequent `git pull` so updates flow without manual upkeep.
  - `detector.LokiStyleDetector` is a digger Detector that consumes
    SignatureBase + the standard digger artifact set to emit findings.
  - The existing YARA detector (digger.detectors.yara_scan) and IOC
    detector pick up signature-base content automatically when it's
    present, in addition to their normal sources.
"""

from digger.loki.signature_base import (
    SignatureBase,
    signature_base_dir,
    discover_signature_base,
)
from digger.loki.updater import update_signature_base
from digger.loki.detector import LokiStyleDetector
from digger.loki.bridge import run_loki_binary
from digger.loki.integrity import (
    compute_tree_hash, sign_snapshot, verify_snapshot, quick_status,
    TreeHash, IntegrityResult, SIG_FILENAME,
)

__all__ = [
    "SignatureBase",
    "signature_base_dir",
    "discover_signature_base",
    "update_signature_base",
    "LokiStyleDetector",
    "run_loki_binary",
    "compute_tree_hash", "sign_snapshot", "verify_snapshot", "quick_status",
    "TreeHash", "IntegrityResult", "SIG_FILENAME",
]
