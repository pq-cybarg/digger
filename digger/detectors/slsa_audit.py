"""SLSA / in-toto provenance audit detector.

Walks locally-installed npm + PyPI packages and emits findings for:

  S1  No provenance attestation:           info
      Most packages still lack a published attestation; we surface
      these as info-level so high-value packages can be reviewed
      individually. Bulk noise on a typical host is large — operator
      can suppress by category if needed.

  S2  Attestation present but unparseable: high
      Either tampering or upstream toolchain bug. Either way the
      operator needs to know.

  S3  Builder not on trusted-builder allowlist: medium
      The package shipped provenance, but the build platform is
      not one of the well-known SLSA-L3 hosted builders. The
      package may still be legitimate (self-hosted runner), but
      the operator can confirm.

  S4  Package metadata vs. provenance source URI mismatch: high
      Manifest says ``repository.url = github.com/foo/bar`` but the
      attestation came from ``github.com/baz/qux``. Classic supply-
      chain hijack signal.

  S5  Predicate type is not a SLSA provenance predicate: medium
      e.g. SPDX or VEX attestations are fine, but if the operator is
      asking for build provenance and only sees a VEX, it's a gap.

The detector is *cluster-agnostic* — it doesn't care about how the
artifacts were collected, only that ``slsa.audit_local_packages``
was run and one Artifact-per-record sits in the store under
collector=``slsa.audit``, category=``packages``.
"""

from __future__ import annotations

from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


_SLSA_PROVENANCE_PREDICATES = (
    "https://slsa.dev/provenance/v1",
    "https://slsa.dev/provenance/v0.2",
    "https://slsa.dev/provenance/v0.1",
)


def _normalize_repo(uri: str | None) -> str:
    """Reduce a repo URI to its github.com/<org>/<name> form for
    comparison."""
    if not uri:
        return ""
    s = uri.strip().lower()
    s = s.removeprefix("git+")
    s = s.removeprefix("git://")
    s = s.removeprefix("https://")
    s = s.removeprefix("http://")
    s = s.removeprefix("ssh://git@")
    s = s.removeprefix("git@")
    if s.startswith("github.com:"):
        s = s.replace(":", "/", 1)
    if s.endswith(".git"):
        s = s[:-4]
    s = s.split("#", 1)[0].split("?", 1)[0]
    return s.rstrip("/")


class SlsaAuditDetector(Detector):
    name = "slsa_audit"
    description = (
        "SLSA / in-toto build-provenance audit findings: missing "
        "attestation, unparseable attestation, untrusted builder, "
        "source-repo mismatch, non-provenance predicate."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "SLSA build-provenance audit failure",
            "id": "digger-slsa-audit-template",
            "description": (
                "Locally-installed npm/PyPI package failed a SLSA / "
                "in-toto provenance audit (missing attestation, "
                "untrusted builder, source URI mismatch, etc)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "supply_chain"},
            "detection": {
                "selection": {
                    "kind": [
                        "no_attestation", "parse_error",
                        "builder_not_trusted", "source_mismatch",
                        "wrong_predicate_type",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1195.002", "attack.t1525",
                "attack.initial_access",
                "attack.supply_chain_compromise",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="slsa.audit",
                                          category="packages"):
            rec = art["data"] or {}
            ecosystem = rec.get("ecosystem", "?")
            name = rec.get("name") or "?"
            version = rec.get("version") or ""
            pkg_label = f"{ecosystem}:{name}@{version}"
            ref = art["artifact_uuid"]

            if rec.get("parse_error"):
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=(
                        f"Provenance attestation present but "
                        f"unparseable: {pkg_label}"
                    ),
                    summary=(
                        f"Package ``{pkg_label}`` shipped a SLSA / "
                        "in-toto attestation file but digger could "
                        f"not parse it: ``{rec.get('parse_error')}``. "
                        "Either the attestation was tampered with "
                        "(intentional supply-chain attack), the "
                        "publishing toolchain emitted a malformed "
                        "bundle, or the schema is newer than "
                        "digger's parser. Inspect the file manually "
                        "and verify the package against the "
                        "registry."
                    ),
                    artifact_refs=[ref],
                    evidence={
                        "kind": "parse_error",
                        "ecosystem": ecosystem,
                        "name": name,
                        "version": version,
                        "attestation_path": rec.get("attestation_path"),
                        "parse_error": rec.get("parse_error"),
                    },
                    mitre="T1195.002",
                )
                continue

            if not rec.get("has_attestation"):
                yield Finding(
                    detector=self.name,
                    severity="info",
                    title=(
                        f"No SLSA provenance for {pkg_label}"
                    ),
                    summary=(
                        f"Package ``{pkg_label}`` installed at "
                        f"``{rec.get('install_path')}`` has no SLSA "
                        "/ in-toto build-provenance attestation "
                        "shipped locally. The bulk of npm + PyPI "
                        "packages still lack provenance — this is "
                        "informational. For high-value deps, "
                        "confirm against the registry; if "
                        "provenance exists upstream, drop the "
                        "bundle next to the install for offline "
                        "verification."
                    ),
                    artifact_refs=[ref],
                    evidence={
                        "kind": "no_attestation",
                        "ecosystem": ecosystem,
                        "name": name,
                        "version": version,
                        "install_path": rec.get("install_path"),
                    },
                    mitre="T1195.002",
                )
                continue

            predicate_type = rec.get("predicate_type") or ""
            if predicate_type and predicate_type not in \
                    _SLSA_PROVENANCE_PREDICATES:
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=(
                        f"Non-provenance predicate "
                        f"({predicate_type}) on {pkg_label}"
                    ),
                    summary=(
                        f"Package ``{pkg_label}`` has an "
                        "attestation, but its predicate type is "
                        f"``{predicate_type}`` — not a SLSA build-"
                        "provenance predicate. SPDX SBOMs, VEX, "
                        "test reports etc. are useful but don't "
                        "tell you *who built* the artifact. If "
                        "you need build provenance, look for a "
                        "second attestation."
                    ),
                    artifact_refs=[ref],
                    evidence={
                        "kind": "wrong_predicate_type",
                        "ecosystem": ecosystem,
                        "name": name,
                        "version": version,
                        "predicate_type": predicate_type,
                    },
                    mitre="T1195.002",
                )

            if rec.get("builder_id") and \
                    rec.get("builder_trusted") is False:
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=(
                        f"Build platform not on trusted-builder "
                        f"allowlist: {pkg_label}"
                    ),
                    summary=(
                        f"Package ``{pkg_label}`` was built by "
                        f"``{rec.get('builder_id')}`` — not one "
                        "of the well-known SLSA-L3 hosted "
                        "builders (GitHub Actions, slsa-github-"
                        "generator, gh-action-pypi-publish, etc). "
                        "The package may still be legitimate (self-"
                        "hosted runner, internal registry), but "
                        "the build platform is a credible attack "
                        "surface — Mini-Shai-Hulud beat SLSA L3 "
                        "exactly here. Verify the builder. Extend "
                        "the allowlist via the "
                        "DIGGER_SLSA_TRUSTED_BUILDERS env var."
                    ),
                    artifact_refs=[ref],
                    evidence={
                        "kind": "builder_not_trusted",
                        "ecosystem": ecosystem,
                        "name": name,
                        "version": version,
                        "builder_id": rec.get("builder_id"),
                        "source_uri": rec.get("source_uri"),
                    },
                    mitre="T1195.002",
                )

            claimed_repo = (rec.get("extras") or {}).get("manifest_repo")
            attested_repo = _normalize_repo(rec.get("source_uri"))
            claimed_repo_norm = _normalize_repo(claimed_repo)
            if claimed_repo_norm and attested_repo and \
                    claimed_repo_norm != attested_repo and \
                    not (claimed_repo_norm in attested_repo
                         or attested_repo in claimed_repo_norm):
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=(
                        f"Package metadata vs. provenance source "
                        f"mismatch: {pkg_label}"
                    ),
                    summary=(
                        f"Package ``{pkg_label}`` manifest claims "
                        f"its source is ``{claimed_repo}``, but its "
                        "SLSA provenance attestation says the "
                        f"artifact was built from ``{rec.get('source_uri')}``. "
                        "A mismatch suggests either typo-squat / "
                        "name-collision, a maintainer migration "
                        "that wasn't reflected in the manifest, or "
                        "an active supply-chain compromise. Verify "
                        "both URLs against the registry's public "
                        "page."
                    ),
                    artifact_refs=[ref],
                    evidence={
                        "kind": "source_mismatch",
                        "ecosystem": ecosystem,
                        "name": name,
                        "version": version,
                        "manifest_repo": claimed_repo,
                        "attested_source_uri": rec.get("source_uri"),
                    },
                    mitre="T1195.002",
                )
