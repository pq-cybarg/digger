"""SLSA / in-toto provenance auditor + SlsaAuditDetector tests."""

from __future__ import annotations

import base64
import json

import pytest

from digger.core.evidence import EvidenceStore
from digger.detectors.slsa_audit import SlsaAuditDetector, _normalize_repo
from digger.slsa import (
    ProvenanceParseError,
    ProvenanceRecord,
    audit_local_packages,
    audit_npm_package,
    audit_pypi_package,
    emit_records_to_store,
    parse_attestation,
)
from digger.slsa.auditor import (
    TRUSTED_BUILDERS,
    _b64decode,
    _default_roots,
    _parse_pypi_dist_info_name,
    _trusted_set,
)


# ---- normalize_repo ---- #


def test_normalize_repo_strips_git_plus():
    assert _normalize_repo("git+https://github.com/foo/bar.git") == \
        "github.com/foo/bar"


def test_normalize_repo_strips_ssh():
    assert _normalize_repo("git@github.com:foo/bar.git") == \
        "github.com/foo/bar"


def test_normalize_repo_none_or_empty():
    assert _normalize_repo(None) == ""
    assert _normalize_repo("") == ""


def test_normalize_repo_handles_fragment_and_query():
    assert _normalize_repo("https://github.com/foo/bar?ref=main#commit") == \
        "github.com/foo/bar"


# ---- b64decode ---- #


def test_b64decode_standard_and_urlsafe():
    assert _b64decode(base64.b64encode(b"hello").decode()) == b"hello"
    assert _b64decode(
        base64.urlsafe_b64encode(b"hello").decode().rstrip("="),
    ) == b"hello"


def test_b64decode_invalid_raises():
    with pytest.raises(ProvenanceParseError):
        _b64decode("!!!not base64@@@")


def test_b64decode_empty_raises():
    with pytest.raises(ProvenanceParseError):
        _b64decode("")


# ---- attestation parsing ---- #


def _make_statement(builder_id: str = "https://github.com/actions/runner",
                    source_uri: str = "git+https://github.com/foo/bar",
                    subject_sha: str = "a" * 64,
                    predicate_type: str =
                        "https://slsa.dev/provenance/v1") -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": predicate_type,
        "subject": [
            {"name": "bar-1.0.tgz",
             "digest": {"sha256": subject_sha}},
        ],
        "predicate": {
            "buildDefinition": {
                "externalParameters": {
                    "source": {"uri": source_uri},
                },
            },
            "runDetails": {
                "builder": {"id": builder_id},
            },
        },
    }


def test_parse_bare_in_toto_statement():
    stmt = _make_statement()
    parsed = parse_attestation(json.dumps(stmt))
    assert parsed["predicate_type"] == "https://slsa.dev/provenance/v1"
    assert parsed["builder_id"] == "https://github.com/actions/runner"
    assert parsed["source_uri"] == "git+https://github.com/foo/bar"
    assert parsed["subject_digest"] == "a" * 64


def test_parse_dsse_envelope():
    stmt = _make_statement()
    env = {
        "payload": base64.b64encode(json.dumps(stmt).encode()).decode(),
        "payloadType": "application/vnd.in-toto+json",
    }
    parsed = parse_attestation(json.dumps(env))
    assert parsed["builder_id"] == "https://github.com/actions/runner"


def test_parse_sigstore_bundle():
    stmt = _make_statement()
    bundle = {
        "dsseEnvelope": {
            "payload": base64.b64encode(json.dumps(stmt).encode()).decode(),
            "payloadType": "application/vnd.in-toto+json",
        },
    }
    parsed = parse_attestation(json.dumps(bundle))
    assert parsed["builder_id"] == "https://github.com/actions/runner"


def test_parse_npm_attestations_array():
    stmt = _make_statement()
    blob = {
        "attestations": [
            {"bundle": {
                "dsseEnvelope": {
                    "payload": base64.b64encode(
                        json.dumps(stmt).encode(),
                    ).decode(),
                    "payloadType": "application/vnd.in-toto+json",
                },
            }},
        ],
    }
    parsed = parse_attestation(json.dumps(blob))
    assert parsed["builder_id"] == "https://github.com/actions/runner"


def test_parse_attestation_invalid_json_raises():
    with pytest.raises(ProvenanceParseError):
        parse_attestation("not json")


def test_parse_attestation_no_statement_raises():
    with pytest.raises(ProvenanceParseError):
        parse_attestation(json.dumps({"foo": "bar"}))


def test_parse_attestation_slsa_v0_2_shape():
    stmt = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [{"digest": {"sha256": "b" * 64}}],
        "predicate": {
            "builder": {"id": "https://github.com/foo/builder"},
            "materials": [{"uri": "git+https://github.com/foo/bar"}],
        },
    }
    parsed = parse_attestation(json.dumps(stmt))
    assert parsed["predicate_type"] == "https://slsa.dev/provenance/v0.2"
    assert parsed["builder_id"] == "https://github.com/foo/builder"
    assert parsed["source_uri"] == "git+https://github.com/foo/bar"


# ---- trusted-builder allowlist ---- #


def test_trusted_set_default_contains_known_builders():
    s = _trusted_set()
    assert any("github.com/actions/runner" in t for t in s)
    assert any("slsa-github-generator" in t for t in s)


def test_trusted_set_env_override(monkeypatch):
    monkeypatch.setenv(
        "DIGGER_SLSA_TRUSTED_BUILDERS",
        "https://internal.example.com/builder, https://other.example.com",
    )
    s = _trusted_set()
    assert "https://internal.example.com/builder" in s
    assert "https://other.example.com" in s


# ---- _parse_pypi_dist_info_name ---- #


def test_parse_pypi_dist_info_name():
    assert _parse_pypi_dist_info_name("requests-2.31.0.dist-info") == \
        ("requests", "2.31.0")


def test_parse_pypi_dist_info_name_invalid():
    assert _parse_pypi_dist_info_name("no-dist-info-suffix") == ("", "")


# ---- npm package audit ---- #


def _make_npm_pkg(pkg_dir, name, version, *,
                  with_attestation=False,
                  attestation_content=None,
                  repository=None):
    pkg_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"name": name, "version": version}
    if repository is not None:
        manifest["repository"] = repository
    (pkg_dir / "package.json").write_text(json.dumps(manifest))
    if with_attestation:
        att = attestation_content or json.dumps(_make_statement())
        (pkg_dir / ".npm-attestation.json").write_text(att)


def test_audit_npm_package_no_attestation(tmp_path):
    pkg = tmp_path / "node_modules" / "foo"
    _make_npm_pkg(pkg, "foo", "1.2.3")
    rec = audit_npm_package(pkg)
    assert rec is not None
    assert rec.ecosystem == "npm"
    assert rec.name == "foo"
    assert rec.version == "1.2.3"
    assert rec.has_attestation is False
    assert rec.attestation_path is None


def test_audit_npm_package_with_attestation(tmp_path):
    pkg = tmp_path / "node_modules" / "foo"
    _make_npm_pkg(pkg, "foo", "1.2.3", with_attestation=True)
    rec = audit_npm_package(pkg)
    assert rec is not None
    assert rec.has_attestation
    assert rec.builder_id == "https://github.com/actions/runner"
    assert rec.builder_trusted is True
    assert rec.predicate_type == "https://slsa.dev/provenance/v1"


def test_audit_npm_package_untrusted_builder(tmp_path):
    pkg = tmp_path / "node_modules" / "foo"
    stmt = _make_statement(
        builder_id="https://self-hosted.example.com/runner",
    )
    _make_npm_pkg(pkg, "foo", "1.2.3", with_attestation=True,
                   attestation_content=json.dumps(stmt))
    rec = audit_npm_package(pkg)
    assert rec is not None
    assert rec.builder_id == "https://self-hosted.example.com/runner"
    assert rec.builder_trusted is False


def test_audit_npm_package_parse_error(tmp_path):
    pkg = tmp_path / "node_modules" / "foo"
    _make_npm_pkg(pkg, "foo", "1.2.3", with_attestation=True,
                   attestation_content="not json at all")
    rec = audit_npm_package(pkg)
    assert rec is not None
    assert rec.has_attestation
    assert rec.parse_error is not None


def test_audit_npm_package_captures_repository_url(tmp_path):
    pkg = tmp_path / "node_modules" / "foo"
    _make_npm_pkg(pkg, "foo", "1.2.3",
                   repository={"type": "git",
                               "url": "git+https://github.com/foo/bar"})
    rec = audit_npm_package(pkg)
    assert rec is not None
    assert rec.extras["manifest_repo"] == "git+https://github.com/foo/bar"


def test_audit_npm_package_captures_repository_string(tmp_path):
    pkg = tmp_path / "node_modules" / "foo"
    _make_npm_pkg(pkg, "foo", "1.2.3",
                   repository="github:foo/bar")
    rec = audit_npm_package(pkg)
    assert rec is not None
    assert rec.extras["manifest_repo"] == "github:foo/bar"


def test_audit_npm_package_returns_none_without_manifest(tmp_path):
    pkg = tmp_path / "node_modules" / "foo"
    pkg.mkdir(parents=True)
    assert audit_npm_package(pkg) is None


def test_audit_npm_package_handles_unparseable_manifest(tmp_path):
    pkg = tmp_path / "node_modules" / "foo"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text("not json")
    assert audit_npm_package(pkg) is None


# ---- pypi package audit ---- #


def _make_pypi_dist(site_packages, name, version,
                    with_attestation=False,
                    attestation_content=None):
    dist = site_packages / f"{name}-{version}.dist-info"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
    )
    if with_attestation:
        att = attestation_content or json.dumps(_make_statement())
        (dist / "PROVENANCE.json").write_text(att)
    return dist


def test_audit_pypi_package_no_attestation(tmp_path):
    site = tmp_path / "site-packages"
    dist = _make_pypi_dist(site, "requests", "2.31.0")
    rec = audit_pypi_package(dist)
    assert rec is not None
    assert rec.ecosystem == "pypi"
    assert rec.name == "requests"
    assert rec.version == "2.31.0"
    assert rec.has_attestation is False


def test_audit_pypi_package_with_attestation(tmp_path):
    site = tmp_path / "site-packages"
    dist = _make_pypi_dist(site, "requests", "2.31.0",
                            with_attestation=True)
    rec = audit_pypi_package(dist)
    assert rec is not None
    assert rec.has_attestation
    assert rec.builder_trusted is True


def test_audit_pypi_package_returns_none_for_bare_dir(tmp_path):
    bad = tmp_path / "not-a-dist-info"
    bad.mkdir()
    assert audit_pypi_package(bad) is None


# ---- audit_local_packages walker ---- #


def test_audit_local_packages_walks_node_modules(tmp_path):
    root = tmp_path / "myproject"
    nm = root / "node_modules"
    _make_npm_pkg(nm / "foo", "foo", "1.0.0")
    _make_npm_pkg(nm / "bar", "bar", "2.0.0", with_attestation=True)
    records = audit_local_packages(roots=[root])
    assert len(records) == 2
    names = {r.name for r in records}
    assert names == {"foo", "bar"}


def test_audit_local_packages_walks_scoped_packages(tmp_path):
    root = tmp_path / "myproject"
    nm = root / "node_modules"
    _make_npm_pkg(nm / "@scope" / "pkg-a", "@scope/pkg-a", "1.0.0")
    _make_npm_pkg(nm / "@scope" / "pkg-b", "@scope/pkg-b", "1.0.0")
    records = audit_local_packages(roots=[nm])
    assert len(records) == 2
    assert {r.name for r in records} == {"@scope/pkg-a", "@scope/pkg-b"}


def test_audit_local_packages_walks_site_packages(tmp_path):
    site = tmp_path / "lib" / "python3.11" / "site-packages"
    _make_pypi_dist(site, "requests", "2.31.0")
    _make_pypi_dist(site, "urllib3", "2.0.0")
    records = audit_local_packages(roots=[site])
    assert len(records) == 2


def test_audit_local_packages_ignores_dot_bin_and_dot_cache(tmp_path):
    root = tmp_path / "myproject"
    nm = root / "node_modules"
    (nm / ".bin").mkdir(parents=True)
    (nm / ".cache").mkdir(parents=True)
    _make_npm_pkg(nm / "foo", "foo", "1.0.0")
    records = audit_local_packages(roots=[nm])
    assert len(records) == 1
    assert records[0].name == "foo"


def test_default_roots_returns_list():
    # Just check it doesn't crash; what it returns is host-dependent.
    roots = _default_roots()
    assert isinstance(roots, list)
    for r in roots:
        assert r.exists()


# ---- emit_records_to_store ---- #


def test_emit_records_to_store_round_trip(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        recs = [
            ProvenanceRecord(
                ecosystem="npm", name="foo", version="1.0.0",
                install_path="/x/y",
            ),
            ProvenanceRecord(
                ecosystem="pypi", name="bar", version="2.0.0",
                install_path="/p/q", has_attestation=True,
                builder_id="https://github.com/actions/runner",
                builder_trusted=True,
            ),
        ]
        n = emit_records_to_store(recs, store)
        assert n == 2
        arts = list(store.iter_artifacts(collector="slsa.audit",
                                          category="packages"))
        assert len(arts) == 2
        assert arts[0]["data"]["ecosystem"] == "npm"
        assert arts[1]["data"]["builder_trusted"] is True
    finally:
        store.close()


# ---- detector ---- #


def _seed_rec(store, **kwargs):
    rec = ProvenanceRecord(
        ecosystem="npm", name="foo", version="1.0.0",
        install_path="/x/y",
    )
    for k, v in kwargs.items():
        setattr(rec, k, v)
    emit_records_to_store([rec], store)


def test_detector_emits_info_for_no_attestation(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_rec(store, has_attestation=False)
        det = SlsaAuditDetector()
        findings = list(det.detect(store))
        kinds = [f.evidence.get("kind") for f in findings]
        assert "no_attestation" in kinds
        for f in findings:
            if f.evidence.get("kind") == "no_attestation":
                assert f.severity == "info"
    finally:
        store.close()


def test_detector_emits_high_for_parse_error(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_rec(store, has_attestation=True,
                   parse_error="bad base64")
        det = SlsaAuditDetector()
        findings = list(det.detect(store))
        parse_findings = [f for f in findings
                          if f.evidence.get("kind") == "parse_error"]
        assert len(parse_findings) == 1
        assert parse_findings[0].severity == "high"
    finally:
        store.close()


def test_detector_emits_medium_for_untrusted_builder(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_rec(store,
                   has_attestation=True,
                   predicate_type="https://slsa.dev/provenance/v1",
                   builder_id="https://self-hosted.example.com",
                   builder_trusted=False)
        det = SlsaAuditDetector()
        findings = list(det.detect(store))
        ut = [f for f in findings
              if f.evidence.get("kind") == "builder_not_trusted"]
        assert len(ut) == 1
        assert ut[0].severity == "medium"
    finally:
        store.close()


def test_detector_no_finding_for_trusted_builder(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_rec(store,
                   has_attestation=True,
                   predicate_type="https://slsa.dev/provenance/v1",
                   builder_id="https://github.com/actions/runner",
                   builder_trusted=True)
        det = SlsaAuditDetector()
        findings = list(det.detect(store))
        assert not [f for f in findings
                    if f.evidence.get("kind") == "builder_not_trusted"]
    finally:
        store.close()


def test_detector_emits_for_source_mismatch(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_rec(store,
                   has_attestation=True,
                   predicate_type="https://slsa.dev/provenance/v1",
                   builder_id="https://github.com/actions/runner",
                   builder_trusted=True,
                   source_uri="git+https://github.com/evil/qux",
                   extras={"manifest_repo":
                           "git+https://github.com/good/bar"})
        det = SlsaAuditDetector()
        findings = list(det.detect(store))
        mm = [f for f in findings
              if f.evidence.get("kind") == "source_mismatch"]
        assert len(mm) == 1
        assert mm[0].severity == "high"
    finally:
        store.close()


def test_detector_no_source_mismatch_for_matching_repos(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_rec(store,
                   has_attestation=True,
                   predicate_type="https://slsa.dev/provenance/v1",
                   builder_id="https://github.com/actions/runner",
                   builder_trusted=True,
                   source_uri="git+https://github.com/foo/bar.git",
                   extras={"manifest_repo":
                           "git+https://github.com/foo/bar"})
        det = SlsaAuditDetector()
        findings = list(det.detect(store))
        assert not [f for f in findings
                    if f.evidence.get("kind") == "source_mismatch"]
    finally:
        store.close()


def test_detector_emits_for_wrong_predicate_type(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_rec(store,
                   has_attestation=True,
                   predicate_type="https://spdx.dev/Document",
                   builder_id="https://github.com/actions/runner",
                   builder_trusted=True)
        det = SlsaAuditDetector()
        findings = list(det.detect(store))
        wp = [f for f in findings
              if f.evidence.get("kind") == "wrong_predicate_type"]
        assert len(wp) == 1
        assert wp[0].severity == "medium"
    finally:
        store.close()


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        det = SlsaAuditDetector()
        assert list(det.detect(store)) == []
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "slsa_audit" in names


def test_detector_sigma_template_has_supply_chain_tags():
    det = SlsaAuditDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-slsa-audit-template"
    assert "attack.t1195.002" in tpl["tags"]
    assert "attack.supply_chain_compromise" in tpl["tags"]


def test_trusted_builders_includes_expected():
    assert "https://github.com/actions/runner" in TRUSTED_BUILDERS
    assert any("slsa-github-generator" in b for b in TRUSTED_BUILDERS)
