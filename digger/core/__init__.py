from digger.core.platform import OS, current_os, is_admin
from digger.core.evidence import EvidenceStore, Artifact, Finding
from digger.core.collector import Collector, CollectorResult
from digger.core.hashing import sha256_file, sha256_bytes

__all__ = [
    "OS",
    "current_os",
    "is_admin",
    "EvidenceStore",
    "Artifact",
    "Finding",
    "Collector",
    "CollectorResult",
    "sha256_file",
    "sha256_bytes",
]
