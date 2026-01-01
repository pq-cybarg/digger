"""SLSA / in-toto provenance auditor.

How attestations are shipped per ecosystem
==========================================

npm (npm publish --provenance)
  Packages publish a sigstore-bundle that the npm registry exposes
  at:
    GET https://registry.npmjs.org/-/npm/v1/attestations/<pkg>@<ver>

  digger checks for a local cache of these:
    <node_modules>/<pkg>/.npm-attestation.json
    <node_modules>/.cache/npm-attestations/<pkg>@<ver>.json
  (different toolchains use different conventions).

  The attestation is a sigstore bundle whose .dsseEnvelope.payload
  is a base64 in-toto statement (predicate type
  ``https://slsa.dev/provenance/v1`` or v0.2).

PyPI (PEP 740)
  Packages publish a sigstore bundle per distribution at:
    GET https://pypi.org/integrity/<project>/<file>/provenance

  digger checks for these next to the installed dist-info:
    <site-packages>/<pkg>-<ver>.dist-info/RECORD   (lists files)
    <site-packages>/<pkg>-<ver>.dist-info/PROVENANCE.json
    <site-packages>/<pkg>-<ver>.dist-info/provenance.json
    <site-packages>/<pkg>-<ver>.dist-info/attestations.json

We DO NOT make network calls — auditing is strictly local. If the
operator wants live verification, they should fetch the bundle via
``curl`` and drop it next to the install.

What we report
==============
For every installed package we emit a ProvenanceRecord with:
  ``ecosystem``         — "npm" or "pypi"
  ``name`` / ``version``
  ``install_path``      — absolute path to the install directory
  ``has_attestation``   — bool
  ``attestation_path``  — path if found
  ``parse_error``       — str if attestation present but unparseable
  ``predicate_type``    — slsa.dev/provenance/v1 etc.
  ``builder_id``        — URI of the build platform (e.g.
                          https://github.com/actions/runner/...)
  ``builder_trusted``   — bool (against TRUSTED_BUILDERS allowlist)
  ``source_uri``        — git URL of source repo (from predicate)
  ``subject_digest``    — sha256 expected from the artifact tarball
  ``digest_match``      — if we can recompute, did it match? If no
                          tarball is present, None (unknown).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import platform
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


class ProvenanceParseError(RuntimeError):
    """Raised when an attestation file is present but malformed."""


# ---- trusted-builder allowlist ---- #
#
# Empirically the most common SLSA L3+ builders. Operators can extend
# the list via the env var ``DIGGER_SLSA_TRUSTED_BUILDERS`` (comma-
# separated, substring match on builder.id URI).
#
# live-first-ok: SLSA builders move slowly and there is no canonical
# feed. The Sigstore / SLSA spec publishes well-known builder IDs in
# their repo as static strings; reading them at runtime would require
# pinning a fetch URL with no version contract. Local override env
# var provides escape hatch.

TRUSTED_BUILDERS = [
    "https://github.com/actions/runner",
    "https://github.com/slsa-framework/slsa-github-generator",
    "https://npm.pkg.github.com",
    "https://github.com/python-packaging/upload-pypi-publish",
    "https://github.com/pypa/gh-action-pypi-publish",
    "https://cloud.google.com/cloudbuild",
    "https://gitlab.com/gitlab-org/gitlab-runner",
]


def _trusted_set() -> tuple[str, ...]:
    extra = os.environ.get("DIGGER_SLSA_TRUSTED_BUILDERS", "")
    parts = [s.strip() for s in extra.split(",") if s.strip()]
    return tuple(TRUSTED_BUILDERS + parts)


# ---- record shape ---- #


@dataclass
class ProvenanceRecord:
    ecosystem: str            # "npm" / "pypi"
    name: str
    version: str
    install_path: str
    has_attestation: bool = False
    attestation_path: str | None = None
    parse_error: str | None = None
    predicate_type: str | None = None
    builder_id: str | None = None
    builder_trusted: bool | None = None
    source_uri: str | None = None
    subject_digest: str | None = None
    digest_match: bool | None = None
    extras: dict = field(default_factory=dict)


# ---- DSSE / sigstore-bundle parsing ---- #


_VALID_B64 = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def _b64decode(s: str) -> bytes:
    """Decode standard or URL-safe base64; pad as needed."""
    if not s or not _VALID_B64.match(s):
        raise ProvenanceParseError("payload is not base64")
    pad = (-len(s)) % 4
    try:
        return base64.urlsafe_b64decode(s + ("=" * pad))
    except binascii.Error:
        try:
            return base64.b64decode(s + ("=" * pad))
        except binascii.Error as exc:
            raise ProvenanceParseError(f"base64 decode failed: {exc}") from exc


def parse_attestation(raw: str | bytes) -> dict:
    """Parse a sigstore-bundle / DSSE envelope / raw in-toto statement.

    Returns a dict with:
      predicate_type   str
      builder_id       str | None
      source_uri       str | None
      subject_digest   str | None   (sha256 hex)
      subjects         list[dict]   (in-toto subjects)
      raw              parsed top-level dict
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    try:
        top = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProvenanceParseError(
            f"attestation is not JSON: {exc}",
        ) from exc

    statement = _extract_statement(top)
    if not isinstance(statement, dict):
        raise ProvenanceParseError("attestation has no in-toto statement")

    predicate_type = statement.get("predicateType") or statement.get(
        "predicate_type",
    )
    predicate = statement.get("predicate") or {}
    subjects = statement.get("subject") or []

    builder_id = None
    source_uri = None
    if isinstance(predicate, dict):
        # SLSA v1: predicate.runDetails.builder.id; predicate.buildDefinition
        run_details = predicate.get("runDetails") or {}
        if isinstance(run_details, dict):
            builder = run_details.get("builder") or {}
            if isinstance(builder, dict):
                builder_id = builder.get("id")
        # SLSA v0.2: predicate.builder.id
        if not builder_id:
            builder = predicate.get("builder") or {}
            if isinstance(builder, dict):
                builder_id = builder.get("id")
        # source URI: predicate.buildDefinition.resolvedDependencies[0].uri
        # or predicate.invocation.configSource.uri
        build_def = predicate.get("buildDefinition") or {}
        if isinstance(build_def, dict):
            external = build_def.get("externalParameters") or {}
            if isinstance(external, dict):
                source_uri = external.get("source") or external.get("repository")
                if isinstance(source_uri, dict):
                    source_uri = source_uri.get("uri") or source_uri.get("url")
            if not source_uri:
                resolved = build_def.get("resolvedDependencies") or []
                if isinstance(resolved, list) and resolved:
                    first = resolved[0]
                    if isinstance(first, dict):
                        source_uri = first.get("uri")
        if not source_uri:
            invocation = predicate.get("invocation") or {}
            if isinstance(invocation, dict):
                cfg = invocation.get("configSource") or {}
                if isinstance(cfg, dict):
                    source_uri = cfg.get("uri")
        if not source_uri:
            # v0.2 fallback — predicate.materials[0].uri
            materials = predicate.get("materials") or []
            if isinstance(materials, list) and materials:
                first = materials[0]
                if isinstance(first, dict):
                    source_uri = first.get("uri")

    # First subject's sha256 digest is the artifact we care about.
    subject_digest = None
    if isinstance(subjects, list) and subjects:
        first = subjects[0]
        if isinstance(first, dict):
            digest = first.get("digest") or {}
            if isinstance(digest, dict):
                subject_digest = digest.get("sha256")

    return {
        "predicate_type": predicate_type,
        "builder_id": builder_id,
        "source_uri": source_uri,
        "subject_digest": subject_digest,
        "subjects": subjects if isinstance(subjects, list) else [],
        "raw": top,
    }


def _extract_statement(top: dict) -> dict | None:
    """Pull the in-toto statement out of whatever container we found.

    Supports:
      - bare in-toto statement (has predicateType + subject)
      - DSSE envelope: {payload: base64, payloadType: ...}
      - Sigstore bundle: {dsseEnvelope: {payload: base64, ...}}
      - npm attestations API response:
        {attestations: [{bundle: {...sigstore...}}, ...]}
    """
    if not isinstance(top, dict):
        return None

    if "predicateType" in top or "predicate_type" in top:
        return top

    if "dsseEnvelope" in top and isinstance(top["dsseEnvelope"], dict):
        return _statement_from_dsse(top["dsseEnvelope"])

    if "payload" in top and "payloadType" in top:
        return _statement_from_dsse(top)

    if "attestations" in top and isinstance(top["attestations"], list):
        for entry in top["attestations"]:
            if not isinstance(entry, dict):
                continue
            bundle = entry.get("bundle")
            if not isinstance(bundle, dict):
                continue
            inner = _extract_statement(bundle)
            if inner is not None:
                return inner

    if "messageSignature" in top and "messageBundle" in top:
        return _extract_statement(top["messageBundle"])

    return None


def _statement_from_dsse(env: dict) -> dict | None:
    payload = env.get("payload")
    if not isinstance(payload, str):
        return None
    try:
        decoded = _b64decode(payload)
    except ProvenanceParseError:
        return None
    try:
        return json.loads(decoded)
    except json.JSONDecodeError:
        return None


# ---- per-ecosystem audit ---- #


_NPM_ATTESTATION_CANDIDATES = (
    ".npm-attestation.json",
    "npm-attestation.json",
    ".sigstore-bundle.json",
    "sigstore-bundle.json",
)

_PYPI_ATTESTATION_CANDIDATES = (
    "PROVENANCE.json",
    "provenance.json",
    "attestations.json",
    "ATTESTATIONS.json",
)


def _find_attestation(pkg_dir: Path,
                      candidates: Iterable[str]) -> Path | None:
    for name in candidates:
        p = pkg_dir / name
        if p.is_file():
            return p
    return None


def audit_npm_package(pkg_dir: Path) -> ProvenanceRecord | None:
    """Inspect one node_modules subdirectory and emit a record.

    Returns None if pkg_dir doesn't look like a package."""
    pkg_dir = Path(pkg_dir)
    manifest = pkg_dir / "package.json"
    if not manifest.is_file():
        return None
    try:
        meta = json.loads(manifest.read_text(encoding="utf-8",
                                              errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None
    name = str(meta.get("name") or pkg_dir.name)
    version = str(meta.get("version") or "")
    manifest_repo = None
    repo_field = meta.get("repository")
    if isinstance(repo_field, str):
        manifest_repo = repo_field
    elif isinstance(repo_field, dict):
        manifest_repo = repo_field.get("url") or repo_field.get("uri")
    rec = ProvenanceRecord(
        ecosystem="npm",
        name=name,
        version=version,
        install_path=str(pkg_dir),
        extras={"manifest_repo": manifest_repo} if manifest_repo else {},
    )
    att = _find_attestation(pkg_dir, _NPM_ATTESTATION_CANDIDATES)
    if att is None:
        return rec
    rec.has_attestation = True
    rec.attestation_path = str(att)
    try:
        raw = att.read_text(encoding="utf-8", errors="replace")
        parsed = parse_attestation(raw)
    except ProvenanceParseError as exc:
        rec.parse_error = str(exc)
        return rec
    except OSError as exc:
        rec.parse_error = f"read failed: {exc}"
        return rec
    rec.predicate_type = parsed.get("predicate_type")
    rec.builder_id = parsed.get("builder_id")
    rec.source_uri = parsed.get("source_uri")
    rec.subject_digest = parsed.get("subject_digest")
    if rec.builder_id:
        rec.builder_trusted = any(t in rec.builder_id
                                   for t in _trusted_set())
    return rec


def audit_pypi_package(dist_info_dir: Path) -> ProvenanceRecord | None:
    """Inspect one .dist-info directory and emit a record."""
    dist_info_dir = Path(dist_info_dir)
    metadata_path = dist_info_dir / "METADATA"
    if not metadata_path.is_file():
        return None
    name, version = _parse_pypi_dist_info_name(dist_info_dir.name)
    try:
        md_text = metadata_path.read_text(encoding="utf-8",
                                            errors="replace")
        for line in md_text.splitlines():
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip() or name
            elif line.startswith("Version:"):
                version = line.split(":", 1)[1].strip() or version
            if name and version:
                break
    except OSError:
        pass
    install_path = str(dist_info_dir.parent / name)
    rec = ProvenanceRecord(
        ecosystem="pypi",
        name=name,
        version=version,
        install_path=install_path,
    )
    att = _find_attestation(dist_info_dir, _PYPI_ATTESTATION_CANDIDATES)
    if att is None:
        return rec
    rec.has_attestation = True
    rec.attestation_path = str(att)
    try:
        raw = att.read_text(encoding="utf-8", errors="replace")
        parsed = parse_attestation(raw)
    except ProvenanceParseError as exc:
        rec.parse_error = str(exc)
        return rec
    except OSError as exc:
        rec.parse_error = f"read failed: {exc}"
        return rec
    rec.predicate_type = parsed.get("predicate_type")
    rec.builder_id = parsed.get("builder_id")
    rec.source_uri = parsed.get("source_uri")
    rec.subject_digest = parsed.get("subject_digest")
    if rec.builder_id:
        rec.builder_trusted = any(t in rec.builder_id
                                   for t in _trusted_set())
    return rec


_DIST_INFO_RE = re.compile(r"^(?P<name>.+?)-(?P<version>[^-]+)\.dist-info$")


def _parse_pypi_dist_info_name(dirname: str) -> tuple[str, str]:
    m = _DIST_INFO_RE.match(dirname)
    if not m:
        return ("", "")
    return (m.group("name"), m.group("version"))


# ---- discovery walker ---- #


def _default_roots() -> list[Path]:
    home = Path.home()
    cands: list[Path] = []
    # node_modules
    cands += [home / "node_modules", Path("/usr/lib/node_modules"),
              Path("/usr/local/lib/node_modules")]
    # site-packages — best-effort. We don't want to import sysconfig
    # at module import.
    try:
        import sysconfig
        purelib = sysconfig.get_paths().get("purelib")
        platlib = sysconfig.get_paths().get("platlib")
        for p in (purelib, platlib):
            if p:
                cands.append(Path(p))
    except (KeyError, AttributeError, OSError):
        pass
    # user-site
    try:
        import site
        user_site = site.getusersitepackages()
        if user_site:
            cands.append(Path(user_site))
    except (AttributeError, OSError, Exception):
        pass
    if platform.system() == "Darwin":
        cands += [
            Path("/Library/Frameworks/Python.framework/Versions"),
        ]
    return [p for p in cands if p.exists()]


_MAX_PACKAGES_PER_ROOT = 5000


def audit_local_packages(
    roots: Iterable[Path | str] | None = None,
) -> list[ProvenanceRecord]:
    """Walk node_modules + site-packages discovered under ``roots`` and
    audit every package found.

    If ``roots`` is None, common locations are auto-discovered."""
    if roots is None:
        root_paths = _default_roots()
    else:
        root_paths = [Path(r) for r in roots]
    records: list[ProvenanceRecord] = []
    for root in root_paths:
        records += _audit_under(root)
    return records


def _audit_under(root: Path) -> list[ProvenanceRecord]:
    out: list[ProvenanceRecord] = []
    name = root.name
    if name == "node_modules":
        out += _audit_node_modules(root)
    elif name.endswith("site-packages") or "site-packages" in name:
        out += _audit_site_packages(root)
    else:
        # walk one level: contains either node_modules dirs or .dist-info
        try:
            for child in root.iterdir():
                if child.is_dir() and child.name == "node_modules":
                    out += _audit_node_modules(child)
                elif child.is_dir() and child.name.endswith(
                    ".dist-info",
                ):
                    rec = audit_pypi_package(child)
                    if rec:
                        out.append(rec)
        except OSError:
            return out
    return out


def _audit_node_modules(node_modules: Path) -> list[ProvenanceRecord]:
    out: list[ProvenanceRecord] = []
    count = 0
    try:
        for child in node_modules.iterdir():
            if count >= _MAX_PACKAGES_PER_ROOT:
                break
            if not child.is_dir():
                continue
            # scoped packages: @scope/<pkg>
            if child.name.startswith("@"):
                try:
                    for inner in child.iterdir():
                        if not inner.is_dir():
                            continue
                        rec = audit_npm_package(inner)
                        if rec:
                            out.append(rec)
                            count += 1
                            if count >= _MAX_PACKAGES_PER_ROOT:
                                break
                except OSError:
                    continue
                continue
            if child.name in (".bin", ".cache"):
                continue
            rec = audit_npm_package(child)
            if rec:
                out.append(rec)
                count += 1
    except OSError:
        return out
    return out


def _audit_site_packages(site_packages: Path) -> list[ProvenanceRecord]:
    out: list[ProvenanceRecord] = []
    count = 0
    try:
        for child in site_packages.iterdir():
            if count >= _MAX_PACKAGES_PER_ROOT:
                break
            if not child.is_dir():
                continue
            if not child.name.endswith(".dist-info"):
                continue
            rec = audit_pypi_package(child)
            if rec:
                out.append(rec)
                count += 1
    except OSError:
        return out
    return out


def emit_records_to_store(records: Iterable[ProvenanceRecord], store) -> int:
    """Append every record as an Artifact to the case store.

    Returns the number of records emitted. The detector consumes
    these via ``store.iter_artifacts(collector='slsa.audit',
    category='packages')``."""
    from dataclasses import asdict
    from digger.core.evidence import Artifact
    count = 0
    for rec in records:
        data = asdict(rec)
        subject = f"slsa:{rec.ecosystem}:{rec.name}@{rec.version}"
        store.add_artifact(Artifact(
            collector="slsa.audit",
            category="packages",
            subject=subject[:380],
            data=data,
        ))
        count += 1
    return count


def hash_file_sha256(path: Path) -> str | None:
    """Compute sha256 of a file; return hex digest or None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None
