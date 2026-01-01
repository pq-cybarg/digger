"""MCP config auditor + McpAuditDetector tests."""

from __future__ import annotations

import json

from digger.core.evidence import EvidenceStore
from digger.detectors.mcp_audit import (
    KNOWN_GOOD_NPM_SCOPES,
    McpAuditDetector,
    _looks_like_credential,
    _trusted_scope_set,
)
from digger.mcp import (
    McpServerRecord,
    audit_mcp_configs,
    emit_records_to_store,
    parse_config_file,
)
from digger.mcp.auditor import _classify_package


# ---- _classify_package ---- #


def test_classify_npx_scoped_package():
    eco, ident, scope = _classify_package(
        "npx", ["-y", "@modelcontextprotocol/server-filesystem"],
    )
    assert eco == "npm"
    assert ident == "@modelcontextprotocol/server-filesystem"
    assert scope == "@modelcontextprotocol"


def test_classify_npx_unscoped_package():
    eco, ident, scope = _classify_package(
        "npx", ["-y", "mcp-some-server"],
    )
    assert eco == "npm"
    assert ident == "mcp-some-server"
    assert scope == ""


def test_classify_uvx_python_package():
    eco, ident, _ = _classify_package("uvx", ["mcp-pyserver"])
    assert eco == "pypi"
    assert ident == "mcp-pyserver"


def test_classify_node_raw_script():
    eco, ident, _ = _classify_package("node", ["/usr/local/bin/x.js"])
    assert eco == "raw_node"
    assert ident == "/usr/local/bin/x.js"


def test_classify_python_raw_script():
    eco, _, _ = _classify_package("python3", ["/x/server.py"])
    assert eco == "raw_python"


def test_classify_bash_script():
    eco, _, _ = _classify_package("/usr/local/bin/run.sh", [])
    assert eco == "raw_shell"


def test_classify_url_command():
    eco, ident, _ = _classify_package("https://api.example.com/mcp", [])
    assert eco == "network"
    assert ident == "https://api.example.com/mcp"


def test_classify_plain_binary():
    eco, ident, _ = _classify_package("/usr/local/bin/mcp-server", [])
    assert eco == "binary"
    assert ident == "/usr/local/bin/mcp-server"


# ---- parse_config_file: Claude Desktop shape ---- #


def test_parse_claude_desktop_mcpServers_object(tmp_path):
    p = tmp_path / "claude_desktop_config.json"
    p.write_text(json.dumps({
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem",
                         "/tmp"],
                "env": {"SAFE_FLAG": "1"},
            },
            "evil": {
                "command": "node",
                "args": ["/tmp/exfil.js"],
                "env": {"GITHUB_TOKEN": "ghp_xxx"},
            },
        },
    }))
    recs = parse_config_file(p, config_kind="claude_desktop")
    assert len(recs) == 2
    by_name = {r.name: r for r in recs}
    assert by_name["filesystem"].pkg_ecosystem == "npm"
    assert by_name["filesystem"].pkg_scope == "@modelcontextprotocol"
    assert by_name["evil"].pkg_ecosystem == "raw_node"
    assert by_name["evil"].env == {"GITHUB_TOKEN": "ghp_xxx"}


def test_parse_mcp_dot_servers_shape(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "mcp": {
            "servers": {
                "a": {"command": "npx", "args": ["-y", "x"]},
            },
        },
    }))
    recs = parse_config_file(p)
    assert len(recs) == 1
    assert recs[0].name == "a"


def test_parse_servers_list_shape(tmp_path):
    p = tmp_path / "continue.json"
    p.write_text(json.dumps({
        "servers": [
            {"name": "first", "command": "uvx", "args": ["pkg-a"]},
            {"id": "second", "command": "npx", "args": ["@a/b"]},
        ],
    }))
    recs = parse_config_file(p)
    assert len(recs) == 2
    names = {r.name for r in recs}
    assert names == {"first", "second"}


def test_parse_url_transport(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "mcpServers": {
            "remote": {
                "url": "https://example.com/sse",
                "transport": "sse",
            },
        },
    }))
    recs = parse_config_file(p)
    assert len(recs) == 1
    assert recs[0].transport == "sse"
    assert recs[0].url == "https://example.com/sse"


def test_parse_url_infers_http_transport(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "mcpServers": {
            "remote": {"url": "https://example.com/mcp"},
        },
    }))
    recs = parse_config_file(p)
    assert len(recs) == 1
    assert recs[0].transport == "http"


def test_parse_disabled_server(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "mcpServers": {
            "off": {"command": "npx", "args": ["x"], "disabled": True},
        },
    }))
    recs = parse_config_file(p)
    assert recs[0].disabled is True


def test_parse_autoApprove_list(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "mcpServers": {
            "auto": {
                "command": "npx", "args": ["x"],
                "autoApprove": ["read_file", "write_file"],
            },
        },
    }))
    recs = parse_config_file(p)
    assert recs[0].auto_approve == ["read_file", "write_file"]


def test_parse_returns_empty_for_missing_file(tmp_path):
    recs = parse_config_file(tmp_path / "nonexistent.json")
    assert recs == []


def test_parse_returns_parse_error_for_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json")
    recs = parse_config_file(p)
    assert len(recs) == 1
    assert recs[0].parse_error
    assert recs[0].name == "<unparseable>"


def test_parse_returns_oversize_record_for_huge_file(tmp_path, monkeypatch):
    p = tmp_path / "huge.json"
    p.write_text(json.dumps({"mcpServers": {}}))
    # Monkeypatch cap to a small value
    monkeypatch.setattr(
        "digger.mcp.auditor._MAX_CONFIG_BYTES", 5,
    )
    recs = parse_config_file(p)
    assert len(recs) == 1
    assert "oversize" in recs[0].parse_error or "cap" in recs[0].parse_error


def test_parse_skips_non_dict_blob(tmp_path):
    p = tmp_path / "list.json"
    p.write_text(json.dumps(["not", "a", "dict"]))
    recs = parse_config_file(p)
    assert recs == []


def test_parse_truncates_args(tmp_path):
    """Long arg values are clipped."""
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "mcpServers": {
            "a": {"command": "node", "args": ["x" * 5000]},
        },
    }))
    recs = parse_config_file(p)
    assert len(recs[0].args[0]) <= 513


# ---- audit_mcp_configs walker ---- #


def test_audit_mcp_configs_explicit_roots(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "mcpServers": {
            "a": {"command": "npx", "args": ["-y", "@modelcontextprotocol/pkg"]},
        },
    }))
    recs = audit_mcp_configs(roots=[p])
    assert len(recs) == 1


def test_audit_mcp_configs_skips_nonexistent_roots(tmp_path):
    recs = audit_mcp_configs(roots=[tmp_path / "nope"])
    assert recs == []


def test_audit_mcp_configs_autodiscovers_project_scoped(tmp_path,
                                                          monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "home")
    (tmp_path / "home").mkdir()
    (tmp_path / ".mcp.json").write_text(json.dumps({
        "mcpServers": {
            "p": {"command": "npx", "args": ["-y", "pkg"]},
        },
    }))
    recs = audit_mcp_configs()
    proj = [r for r in recs if r.project_scoped]
    assert len(proj) == 1
    assert proj[0].name == "p"


# ---- credential pattern check ---- #


def test_looks_like_credential_positive_cases():
    assert _looks_like_credential("AWS_ACCESS_KEY_ID", "AKIA...")
    assert _looks_like_credential("GITHUB_TOKEN", "ghp_xxx")
    assert _looks_like_credential("STRIPE_SECRET_KEY", "sk_...")
    assert _looks_like_credential("OPENAI_API_KEY", "sk-...")
    assert _looks_like_credential("MY_SECRET", "x")
    assert _looks_like_credential("DATABASE_URL", "postgres://...")
    assert _looks_like_credential("AUTH_TOKEN", "x")


def test_looks_like_credential_negative_cases():
    assert not _looks_like_credential("PATH", "/usr/bin")
    assert not _looks_like_credential("SAFE_FLAG", "1")
    assert not _looks_like_credential("HOST", "example.com")
    assert not _looks_like_credential("USER", "alice")


# ---- _trusted_scope_set env override ---- #


def test_trusted_scope_set_default():
    s = _trusted_scope_set()
    assert "@modelcontextprotocol" in s


def test_trusted_scope_set_env_override(monkeypatch):
    monkeypatch.setenv("DIGGER_MCP_TRUSTED_SCOPES",
                        "@mycorp, @internal")
    s = _trusted_scope_set()
    assert "@mycorp" in s
    assert "@internal" in s


# ---- emit_records_to_store ---- #


def test_emit_records_to_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        recs = [
            McpServerRecord(
                name="srv1", config_path="/x/y", config_kind="cursor",
            ),
        ]
        n = emit_records_to_store(recs, store)
        assert n == 1
        arts = list(store.iter_artifacts(collector="mcp.audit",
                                          category="ai_tools"))
        assert len(arts) == 1
        assert arts[0]["data"]["name"] == "srv1"
    finally:
        store.close()


# ---- detector ---- #


def _seed(store, **kwargs):
    rec = McpServerRecord(
        name="testsrv", config_path="/test/config.json",
        config_kind="claude_desktop",
    )
    for k, v in kwargs.items():
        setattr(rec, k, v)
    emit_records_to_store([rec], store)


def test_detector_p1_project_scoped(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, project_scoped=True, command="npx",
              args=["-y", "@x/pkg"], pkg_ecosystem="npm",
              pkg_scope="@x")
        det = McpAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "project_scoped_autoinstall"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1195.002"
    finally:
        store.close()


def test_detector_p2_raw_script_exec(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, command="node", args=["/tmp/exfil.js"],
              pkg_ecosystem="raw_node",
              pkg_identifier="/tmp/exfil.js")
        det = McpAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "raw_script_exec"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_p3_credential_env_var(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, command="npx", args=["x"], pkg_ecosystem="npm",
              env={"GITHUB_TOKEN": "ghp_xx",
                   "OPENAI_API_KEY": "sk-xx",
                   "PATH": "/usr/bin"})
        det = McpAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "credential_env_var"]
        assert len(f) == 1
        assert set(f[0].evidence["keys"]) == \
            {"GITHUB_TOKEN", "OPENAI_API_KEY"}
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_p3_no_finding_without_credentials(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, command="npx", args=["x"], pkg_ecosystem="npm",
              env={"PATH": "/usr/bin", "FOO": "bar"})
        det = McpAuditDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "credential_env_var"]
    finally:
        store.close()


def test_detector_p4_network_transport(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, transport="sse", url="https://example.com/sse")
        det = McpAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "network_transport"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_p4_no_finding_for_stdio(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, transport="stdio")
        det = McpAuditDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "network_transport"]
    finally:
        store.close()


def test_detector_p5_untrusted_npm_scope(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, command="npx",
              args=["-y", "@evilcorp/server"],
              pkg_ecosystem="npm",
              pkg_identifier="@evilcorp/server",
              pkg_scope="@evilcorp")
        det = McpAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "untrusted_npm_scope"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_p5_no_finding_for_trusted_scope(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, command="npx",
              args=["-y", "@modelcontextprotocol/server"],
              pkg_ecosystem="npm",
              pkg_identifier="@modelcontextprotocol/server",
              pkg_scope="@modelcontextprotocol")
        det = McpAuditDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "untrusted_npm_scope"]
    finally:
        store.close()


def test_detector_p5_skips_unscoped_npm(tmp_path):
    """Unscoped npm packages can't be classified as 'untrusted-scope';
    those should fall through to other layers."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, command="npx", args=["mcp-server"],
              pkg_ecosystem="npm",
              pkg_identifier="mcp-server", pkg_scope="")
        det = McpAuditDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "untrusted_npm_scope"]
    finally:
        store.close()


def test_detector_skips_disabled_servers(tmp_path):
    """A disabled server emits no findings — operator already turned
    it off."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, disabled=True, project_scoped=True,
              command="node", args=["/tmp/x.js"],
              pkg_ecosystem="raw_node")
        det = McpAuditDetector()
        findings = list(det.detect(store))
        assert findings == []
    finally:
        store.close()


def test_detector_emits_parse_error_finding(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, name="<unparseable>",
              parse_error="JSON parse failed")
        det = McpAuditDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "config_parse_error"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        det = McpAuditDetector()
        assert list(det.detect(store)) == []
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "mcp_audit" in names


def test_detector_sigma_template_has_supply_chain_tags():
    det = McpAuditDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-mcp-audit-template"
    assert "attack.t1195.002" in tpl["tags"]
    assert "attack.t1552.001" in tpl["tags"]
    assert tpl["logsource"]["category"] == "ai_tools"


def test_known_good_scopes_includes_modelcontextprotocol():
    assert "@modelcontextprotocol" in KNOWN_GOOD_NPM_SCOPES
    assert "@anthropic-ai" in KNOWN_GOOD_NPM_SCOPES
