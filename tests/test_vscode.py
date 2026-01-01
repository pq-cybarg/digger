"""VS Code auditor + VsCodeAuditDetector tests."""

from __future__ import annotations

import json

from digger.core.evidence import EvidenceStore
from digger.detectors.vscode_audit import (
    VsCodeAuditDetector,
    _is_suspicious_shell_path,
    _settings_has_any_risky_key,
)
from digger.vscode import (
    VsCodeAudit,
    VsCodeExtension,
    VsCodeSettings,
    audit_vscode,
    emit_records_to_store,
    parse_extension_dir,
    parse_settings_file,
)
from digger.vscode.auditor import (
    KNOWN_GOOD_PUBLISHERS,
    _strip_jsonc_comments,
    _trusted_publishers,
)


# ---- strip_jsonc_comments ---- #


def test_strip_jsonc_removes_line_comments():
    out = _strip_jsonc_comments('{\n  // hi\n  "a": 1\n}')
    assert "//" not in out
    assert '"a": 1' in out


def test_strip_jsonc_removes_block_comments():
    out = _strip_jsonc_comments('{ /* this is\nblock */ "a": 1 }')
    assert "/*" not in out
    assert "*/" not in out


def test_strip_jsonc_preserves_url_in_string():
    """Don't strip // inside a JSON string literal."""
    text = '{ "url": "https://example.com/path" }'
    out = _strip_jsonc_comments(text)
    assert "https://example.com/path" in out


def test_strip_jsonc_strips_trailing_commas():
    out = _strip_jsonc_comments('{ "a": 1, }')
    parsed = json.loads(out)
    assert parsed == {"a": 1}


# ---- _is_suspicious_shell_path ---- #


def test_is_suspicious_shell_path_tmp():
    assert _is_suspicious_shell_path("/tmp/evil") is True
    assert _is_suspicious_shell_path("/Users/Shared/x") is True


def test_is_suspicious_shell_path_safe():
    assert _is_suspicious_shell_path("/opt/homebrew/bin/fish") is False
    assert _is_suspicious_shell_path("/bin/zsh") is False


def test_is_suspicious_shell_path_empty():
    assert _is_suspicious_shell_path("") is False


# ---- _trusted_publishers env override ---- #


def test_trusted_publishers_default_includes_microsoft():
    s = _trusted_publishers()
    assert "ms-python" in s
    assert "github" in s


def test_trusted_publishers_env_override(monkeypatch):
    monkeypatch.setenv("DIGGER_VSCODE_TRUSTED_PUBLISHERS",
                        "internalcorp, mybusiness")
    s = _trusted_publishers()
    assert "internalcorp" in s
    assert "mybusiness" in s


def test_known_good_publishers_includes_anthropic():
    assert "anthropic" in KNOWN_GOOD_PUBLISHERS


# ---- parse_extension_dir ---- #


def _make_ext(parent, publisher, name, version, *,
              with_marketplace=True, body=None):
    d = parent / f"{publisher}.{name}-{version}"
    d.mkdir(parents=True)
    meta = body if body is not None else {
        "publisher": publisher,
        "name": name,
        "version": version,
        "displayName": f"{publisher} {name}",
        "main": "./out/extension.js",
        "activationEvents": ["onStartup"],
        "contributes": {"commands": [
            {"command": "x.run", "title": "Run"},
        ]},
    }
    (d / "package.json").write_text(json.dumps(meta))
    if with_marketplace:
        (d / ".vsixmanifest").write_text(
            "<PackageManifest><Metadata>"
            "<Identity Publisher=\"X\"/>"
            "</Metadata>"
            "<Properties>"
            "<Property Id=\"Microsoft.VisualStudio.Services.Source\""
            " Value=\"ExtensionMarketplace\"/>"
            "</Properties></PackageManifest>"
        )
    return d


def test_parse_extension_dir_basic(tmp_path):
    d = _make_ext(tmp_path / "ext", "ms-python", "python", "2024.1.0")
    rec = parse_extension_dir(d)
    assert rec.publisher == "ms-python"
    assert rec.name == "python"
    assert rec.version == "2024.1.0"
    assert rec.main == "./out/extension.js"
    assert rec.contributes_commands_count == 1
    assert rec.is_marketplace_install is True


def test_parse_extension_dir_sideloaded(tmp_path):
    d = _make_ext(tmp_path / "ext", "evil", "x", "0.0.1",
                  with_marketplace=False)
    rec = parse_extension_dir(d)
    assert rec.is_marketplace_install is None


def test_parse_extension_dir_returns_none_for_non_dir(tmp_path):
    rec = parse_extension_dir(tmp_path / "nope")
    assert rec is None


def test_parse_extension_dir_no_package_json(tmp_path):
    d = tmp_path / "broken"
    d.mkdir()
    rec = parse_extension_dir(d)
    assert "no package.json" in rec.parse_error


def test_parse_extension_dir_malformed_json(tmp_path):
    d = tmp_path / "broken"
    d.mkdir()
    (d / "package.json").write_text("not json")
    rec = parse_extension_dir(d)
    assert rec.parse_error


def test_parse_extension_dir_oversize(tmp_path, monkeypatch):
    d = _make_ext(tmp_path / "ext", "x", "y", "1")
    monkeypatch.setattr(
        "digger.vscode.auditor._MAX_MANIFEST_BYTES", 5,
    )
    rec = parse_extension_dir(d)
    assert "cap" in rec.parse_error


# ---- parse_settings_file ---- #


def _settings_file(tmp_path, body: dict | str) -> str:
    p = tmp_path / "settings.json"
    if isinstance(body, dict):
        p.write_text(json.dumps(body))
    else:
        p.write_text(body)
    return str(p)


def test_parse_settings_basic(tmp_path):
    p = _settings_file(tmp_path, {
        "security.workspace.trust.enabled": True,
        "http.proxyStrictSSL": True,
        "editor.fontSize": 14,
    })
    rec = parse_settings_file(p)
    assert rec.workspace_trust_enabled is True
    assert rec.http_proxy_strict_ssl is True
    assert rec.parse_error == ""


def test_parse_settings_workspace_trust_disabled(tmp_path):
    p = _settings_file(tmp_path, {
        "security.workspace.trust.enabled": False,
    })
    rec = parse_settings_file(p)
    assert rec.workspace_trust_enabled is False


def test_parse_settings_proxy_strict_ssl_false(tmp_path):
    p = _settings_file(tmp_path, {
        "http.proxyStrictSSL": False,
    })
    rec = parse_settings_file(p)
    assert rec.http_proxy_strict_ssl is False


def test_parse_settings_custom_shell(tmp_path):
    p = _settings_file(tmp_path, {
        "terminal.integrated.shell.osx": "/tmp/evil_sh",
    })
    rec = parse_settings_file(p)
    assert rec.custom_default_shell.get(
        "terminal.integrated.shell.osx",
    ) == "/tmp/evil_sh"


def test_parse_settings_automation_profile_dict(tmp_path):
    p = _settings_file(tmp_path, {
        "terminal.integrated.automationProfile.osx": {
            "path": "/Users/Shared/x",
        },
    })
    rec = parse_settings_file(p)
    assert rec.custom_automation_profile.get(
        "terminal.integrated.automationProfile.osx",
    ) == "/Users/Shared/x"


def test_parse_settings_with_jsonc_comments(tmp_path):
    """VS Code settings.json allows comments and trailing commas."""
    p = tmp_path / "settings.json"
    p.write_text('// header\n'
                  '{\n'
                  '  /* block */\n'
                  '  "http.proxyStrictSSL": false,\n'
                  '}\n')
    rec = parse_settings_file(str(p))
    assert rec.http_proxy_strict_ssl is False


def test_parse_settings_missing_file(tmp_path):
    rec = parse_settings_file(tmp_path / "nope.json")
    assert rec.parse_error == "not a file"


def test_parse_settings_invalid_json(tmp_path):
    p = _settings_file(tmp_path, "not json")
    rec = parse_settings_file(p)
    assert "JSON parse" in rec.parse_error


def test_parse_settings_top_level_list(tmp_path):
    p = _settings_file(tmp_path, "[1, 2, 3]")
    rec = parse_settings_file(p)
    assert "not a mapping" in rec.parse_error


# ---- _settings_has_any_risky_key ---- #


def test_settings_has_any_risky_key_workspace_trust():
    assert _settings_has_any_risky_key(
        {"workspace_trust_enabled": False}
    ) is True


def test_settings_has_any_risky_key_ssl():
    assert _settings_has_any_risky_key(
        {"http_proxy_strict_ssl": False}
    ) is True


def test_settings_has_any_risky_key_no_risk():
    assert _settings_has_any_risky_key(
        {"workspace_trust_enabled": True}
    ) is False
    assert _settings_has_any_risky_key({}) is False


# ---- audit_vscode walker ---- #


def test_audit_vscode_explicit_roots(tmp_path):
    ext_root = tmp_path / "extensions"
    _make_ext(ext_root, "ms-python", "python", "1.0.0")
    _make_ext(ext_root, "evilcorp", "x", "0.0.1",
              with_marketplace=False)
    audit = audit_vscode(roots=[ext_root])
    assert len(audit.extensions) == 2


# ---- emit_records_to_store ---- #


def test_emit_records_to_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        audit = VsCodeAudit(
            extensions=[VsCodeExtension(
                extension_dir="/x/.vscode/extensions/p.n-1.0",
                publisher="p", name="n", version="1.0",
            )],
            settings=[VsCodeSettings(
                settings_path="/x/settings.json",
            )],
        )
        n = emit_records_to_store(audit, store)
        assert n == 2
        ext_arts = list(store.iter_artifacts(
            collector="vscode.extension", category="dev_env",
        ))
        s_arts = list(store.iter_artifacts(
            collector="vscode.settings", category="dev_env",
        ))
        assert len(ext_arts) == 1
        assert len(s_arts) == 1
    finally:
        store.close()


# ---- detector ---- #


def _seed_ext(store, **kwargs):
    ext = VsCodeExtension(
        extension_dir="/x/.vscode/extensions/p.n-1.0",
        publisher="ms-python", name="x", version="1.0",
        is_marketplace_install=True,
    )
    for k, v in kwargs.items():
        setattr(ext, k, v)
    audit = VsCodeAudit(extensions=[ext], settings=[])
    emit_records_to_store(audit, store)


def _seed_settings(store, **kwargs):
    s = VsCodeSettings(settings_path="/x/settings.json")
    for k, v in kwargs.items():
        setattr(s, k, v)
    audit = VsCodeAudit(extensions=[], settings=[s])
    emit_records_to_store(audit, store)


def test_detector_v1_sideloaded(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_ext(store, is_marketplace_install=False,
                   publisher="ms-python")
        findings = list(VsCodeAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "sideloaded_extension"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_v2_untrusted_publisher(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_ext(store, publisher="evilcorp",
                   is_marketplace_install=True)
        findings = list(VsCodeAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "untrusted_publisher"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_v2_no_finding_for_trusted_publisher(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_ext(store, publisher="ms-python",
                   is_marketplace_install=True)
        findings = list(VsCodeAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "untrusted_publisher"]
    finally:
        store.close()


def test_detector_v3_workspace_trust_disabled(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_settings(store, workspace_trust_enabled=False)
        findings = list(VsCodeAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "workspace_trust_disabled"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_v4_open_untrusted_files(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_settings(store,
                        workspace_trust_untrusted_files="open")
        findings = list(VsCodeAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "workspace_trust_open_untrusted"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_v5_proxy_strict_ssl_disabled(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_settings(store, http_proxy_strict_ssl=False)
        findings = list(VsCodeAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "proxy_strict_ssl_disabled"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_v6_suspicious_shell_override(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_settings(store,
                        custom_default_shell={
                            "terminal.integrated.shell.osx":
                                "/tmp/evil_sh",
                        })
        findings = list(VsCodeAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "suspicious_shell_override"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_v6_no_finding_for_safe_shell(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_settings(store,
                        custom_default_shell={
                            "terminal.integrated.shell.osx":
                                "/opt/homebrew/bin/fish",
                        })
        findings = list(VsCodeAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "suspicious_shell_override"]
    finally:
        store.close()


def test_detector_v7_project_scoped_risky_settings(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_settings(store, project_scoped=True,
                        workspace_trust_enabled=False)
        findings = list(VsCodeAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "project_settings_risky_keys"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_v7_no_finding_for_user_scoped(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_settings(store, project_scoped=False,
                        workspace_trust_enabled=False)
        findings = list(VsCodeAuditDetector().detect(store))
        # V3 fires, but V7 does not
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "project_settings_risky_keys"]
    finally:
        store.close()


def test_detector_parse_error_extension(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_ext(store, parse_error="bad JSON",
                   is_marketplace_install=None)
        findings = list(VsCodeAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "vscode_parse_error"]
        assert len(f) == 1
        assert f[0].severity == "info"
    finally:
        store.close()


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        assert list(VsCodeAuditDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "vscode_audit" in names


def test_detector_sigma_template_has_tags():
    det = VsCodeAuditDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-vscode-audit-template"
    assert "attack.t1546" in tpl["tags"]
    assert tpl["logsource"]["category"] == "dev_env"
