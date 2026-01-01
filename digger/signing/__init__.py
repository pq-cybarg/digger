"""Code-signature verification of running process executables.

LOKI / signature-base asks: "is this binary known-bad?"
This module asks the inverse: "does this binary have a verifiable
provenance, and if so whose?"

What gets surfaced:

  signed         platform-trusted signature verified
  ad_hoc         macOS ad-hoc signature (no developer identity — many
                 first-run binaries, many malware samples)
  unsigned       no signature at all
  invalid        signature present but verification failed
  package_owned  Linux: a system package manager claims this file
  package_orphan Linux: no package claims this file (could be a
                 hand-installed binary, a build artifact, or a dropper)
  expired        certificate has expired
  revoked        certificate has been revoked

Cross-platform:

  macOS    `codesign --verify --deep --strict -vv` + `spctl --assess`
           Both ship with the OS; no external deps.
  Linux    `dpkg -S` or `rpm -qf` to attribute a file to a package.
           No system-wide signature scheme to verify against.
  Windows  Best-effort via ctypes + WinTrust (not implemented in v1 —
           returns "unsupported" with a clear reason).
"""

from digger.signing.verify import (
    SigInfo, verify_path, SUPPORTED_STATES,
)
from digger.signing.collector import CodeSigningCollector
from digger.signing.detector import UnsignedBinaryDetector

__all__ = [
    "SigInfo", "verify_path", "SUPPORTED_STATES",
    "CodeSigningCollector", "UnsignedBinaryDetector",
]
