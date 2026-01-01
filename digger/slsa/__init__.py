"""SLSA / in-toto build-provenance auditor.

Audits locally-installed packages (npm, PyPI) for SLSA build
attestations. Where present, parses the in-toto statement, extracts
the builder identity + source-repo URI, and reports back so the
``digger.detectors.slsa_audit`` detector can flag:

  - packages with no provenance attestation,
  - packages whose provenance was tampered (subject digest mismatch),
  - packages whose builder is not on the trusted-builder allowlist,
  - packages whose claimed source-repo doesn't match the package
    metadata.

Public API
----------
``audit_local_packages(roots=None) -> list[ProvenanceRecord]``
  walks node_modules + site-packages discovered under ``roots``
  (defaults to common system + user locations on each OS), returns
  a list of one ProvenanceRecord per package.

``ProvenanceRecord`` — single package's audit result
``ProvenanceParseError`` — raised on malformed attestation
``TRUSTED_BUILDERS`` — built-in allowlist
"""

from __future__ import annotations

from digger.slsa.auditor import (
    TRUSTED_BUILDERS,
    ProvenanceParseError,
    ProvenanceRecord,
    audit_local_packages,
    audit_npm_package,
    audit_pypi_package,
    emit_records_to_store,
    parse_attestation,
)

__all__ = [
    "TRUSTED_BUILDERS",
    "ProvenanceParseError",
    "ProvenanceRecord",
    "audit_local_packages",
    "audit_npm_package",
    "audit_pypi_package",
    "emit_records_to_store",
    "parse_attestation",
]
